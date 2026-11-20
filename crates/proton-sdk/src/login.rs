//! Signing in to a Proton account, step by step.
//!
//! [`ProtonApiSession::begin_verified`] runs the SRP handshake; a usable
//! session needs more than that. The full sequence is: the password
//! (restarted with a solved CAPTCHA when Proton asks), then a second-factor
//! code, then a mailbox password on accounts that have one, then the key
//! passphrases, derived while the token still has the scope the key salts
//! need. This module is that sequence as a small state machine a frontend
//! drives in its own way: a terminal prompt, a dialog, a phone screen.
//!
//! Storing the result is the caller's business. [`Unlocked::resume_parameters`]
//! is what [`ProtonApiSession::resume`] needs later, and
//! [`Unlocked::key_passphrases`] unlocks the key chain without the mailbox
//! password.
//!
//! ```no_run
//! # async fn demo(config: proton_sdk::config::ProtonClientConfiguration) -> Result<(), proton_sdk::login::LoginError> {
//! use proton_sdk::login::{self, Step};
//!
//! let mut step = login::begin(config, "user@proton.me", "password", None).await?;
//! let unlocked = loop {
//!     step = match step {
//!         Step::SecondFactor(pending) => pending.second_factor("123456").await?,
//!         Step::MailboxPassword(pending) => break pending.mailbox_password("mailbox").await?,
//!         Step::Unlock(pending) => break pending.unlock().await?,
//!     };
//! };
//! let resume = unlocked.resume_parameters().await;
//! // Store `resume` and `unlocked.key_passphrases`, then keep the tokens
//! // current from `unlocked.session.http().set_on_tokens_refreshed`.
//! # Ok(()) }
//! ```

use zeroize::Zeroizing;

use crate::account::{AccountClient, KeyPassphrases, KeySalt};
use crate::api::{HumanVerification, HumanVerificationCredential, ResponseCode};
use crate::config::ProtonClientConfiguration;
use crate::error::{ProtonApiError, ProtonError};
use crate::session::{PasswordMode, ProtonApiSession, ResumeParameters};

/// Why a sign-in step failed, in terms a frontend can act on.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoginError {
    /// Proton wants a CAPTCHA solved first. Show
    /// [`HumanVerification::verification_url`], then call [`begin`] again with
    /// the token (see [`HumanVerification::token_from_message`]). Only CAPTCHA
    /// gates land here; one that wants an e-mail or SMS code is
    /// [`LoginError::Rejected`].
    #[error("Proton asks to confirm this sign-in is made by a person")]
    HumanVerification(Box<HumanVerification>),
    /// The account's only second factor is a security key, which needs
    /// WebAuthn. The half-made session has been ended.
    #[error(
        "This account's only second factor is a security key, which this app cannot use yet. \
         Add an authenticator app in your Proton account settings, then sign in with its code."
    )]
    SecurityKeyOnly,
    /// Proton blocks sign-ins from this client for now. Its own message claims
    /// the app version is unsupported, which is not what is wrong, so the
    /// display text is the SDK's; the response is kept for callers that word
    /// it themselves.
    #[error(
        "Proton has blocked sign-ins from this app for now. Wait a while and try again, \
         or sign in once on proton.me first."
    )]
    Blocked(ProtonApiError),
    /// Proton refused the address and password. Displays Proton's reason,
    /// which is written for people; callers that must not show server text
    /// can use their own.
    #[error("{}", rejected_text(.0))]
    Rejected(ProtonApiError),
    /// The second-factor code was not accepted. Proton does not take a second
    /// try on the same half-made session: start over with [`begin`].
    #[error("That code was not accepted.")]
    WrongCode(ProtonApiError),
    /// The mailbox password did not unlock the account. The pending sign-in
    /// survives; ask again.
    #[error("That mailbox password did not unlock the account.")]
    WrongMailboxPassword,
    /// Anything else: network, server, protocol.
    #[error(transparent)]
    Proton(#[from] ProtonError),
}

/// Where a sign-in stands.
///
/// Every sign-in ends with a call that unlocks the keys by reference,
/// [`Pending::mailbox_password`] or [`Pending::unlock`], so a failed unlock (a
/// dropped connection, a mistyped mailbox password) can be retried on the
/// same session without asking for the password and code again.
pub enum Step {
    /// Ask for a second-factor code and pass it to [`Pending::second_factor`].
    SecondFactor(Pending),
    /// Ask for the mailbox password and pass it to [`Pending::mailbox_password`].
    MailboxPassword(Pending),
    /// The account has one password and it was accepted: call
    /// [`Pending::unlock`].
    Unlock(Pending),
}

/// A sign-in waiting on the user.
pub struct Pending {
    session: ProtonApiSession,
    password: Zeroizing<String>,
}

/// A finished sign-in.
pub struct Unlocked {
    pub session: ProtonApiSession,
    /// Key id to the passphrase that unlocks it. Store these instead of the
    /// mailbox password: they unlock the key chain just the same, but a leaked
    /// store gives away this client's access rather than the password.
    pub key_passphrases: KeyPassphrases,
    /// The account's key salts, for callers that re-derive passphrases later
    /// (such as one that locks and unlocks with the mailbox password). Only a
    /// fresh password sign-in may read them.
    pub key_salts: Vec<KeySalt>,
}

impl Unlocked {
    /// What [`ProtonApiSession::resume`] needs, with the tokens as they are
    /// now.
    pub async fn resume_parameters(&self) -> ResumeParameters {
        self.session.resume_parameters().await
    }
}

/// Start signing in.
///
/// `verification` is the token of a solved CAPTCHA after a first try failed
/// with [`LoginError::HumanVerification`]; the sign-in starts over with it,
/// because the gated attempt's SRP handshake is spent. Surrounding spaces in
/// `username` are ignored.
pub async fn begin(
    config: ProtonClientConfiguration,
    username: &str,
    password: &str,
    verification: Option<&HumanVerificationCredential>,
) -> Result<Step, LoginError> {
    let session = ProtonApiSession::begin_verified(
        config,
        username.trim(),
        password.as_bytes(),
        verification,
    )
    .await
    .map_err(classify_begin_failure)?;
    let pending = Pending {
        session,
        password: Zeroizing::new(password.to_owned()),
    };
    if pending.session.is_waiting_for_second_factor() {
        let methods = pending.session.second_factor_methods();
        if methods.fido2 && !methods.totp {
            // Asking for a code would only fail as a wrong one.
            pending.session.end().await.ok();
            return Err(LoginError::SecurityKeyOnly);
        }
        return Ok(Step::SecondFactor(pending));
    }
    Ok(pending.after_second_factor())
}

impl Pending {
    /// The half-made session, for callers that need its username or want to
    /// end it when the user cancels.
    pub fn session(&self) -> &ProtonApiSession {
        &self.session
    }

    /// Submit a second-factor code. Consumes the sign-in: a wrong code means
    /// starting over (see [`LoginError::WrongCode`]).
    pub async fn second_factor(mut self, code: &str) -> Result<Step, LoginError> {
        self.session
            .apply_second_factor_code(code.trim())
            .await
            .map_err(|error| match error {
                ProtonError::Api(api) if (400..500).contains(&api.http_status) => {
                    LoginError::WrongCode(api)
                }
                other => other.into(),
            })?;
        Ok(self.after_second_factor())
    }

    /// Submit the mailbox password. By reference: a wrong one is detected on
    /// this side, the session survives it, and the user can try again.
    pub async fn mailbox_password(&self, mailbox_password: &str) -> Result<Unlocked, LoginError> {
        unlock(self.session.clone(), mailbox_password).await
    }

    /// Unlock the keys with the login password, on an account that has one
    /// password. By reference, so a failure can be retried.
    pub async fn unlock(&self) -> Result<Unlocked, LoginError> {
        unlock(self.session.clone(), &self.password).await
    }

    fn after_second_factor(self) -> Step {
        match self.session.password_mode() {
            PasswordMode::Dual => Step::MailboxPassword(self),
            PasswordMode::Single => Step::Unlock(self),
        }
    }
}

/// Unlock the key chain with `mailbox_password` and derive the passphrases.
///
/// Unlocking the user keys is what proves the mailbox password: a wrong one
/// unlocks none of them.
async fn unlock(session: ProtonApiSession, mailbox_password: &str) -> Result<Unlocked, LoginError> {
    let account = AccountClient::new(&session, mailbox_password.as_bytes().to_vec());
    // Salts first: they need the scope a password sign-in grants, which the
    // first token refresh drops.
    let key_salts = account.key_salts().await?;
    account.unlock().await.map_err(|error| match error {
        ProtonError::KeysLocked => LoginError::WrongMailboxPassword,
        other => other.into(),
    })?;
    let key_passphrases = account.key_passphrases().await?;
    Ok(Unlocked {
        session,
        key_passphrases,
        key_salts,
    })
}

/// Lift a CAPTCHA gate, a block and a refused password out of the generic
/// API error.
fn classify_begin_failure(error: ProtonError) -> LoginError {
    if let ProtonError::Api(api) = &error
        && let Some(challenge) = api.human_verification()
        && challenge.supports_captcha()
    {
        return LoginError::HumanVerification(Box::new(challenge));
    }
    match error {
        ProtonError::Api(api) if api.code == ResponseCode::Blocked => LoginError::Blocked(api),
        ProtonError::Api(api)
            if api.http_status == 422 && !api.is_human_verification_required() =>
        {
            LoginError::Rejected(api)
        }
        other => other.into(),
    }
}

fn rejected_text(api: &ProtonApiError) -> &str {
    if api.message.is_empty() {
        "Proton did not accept that address and password"
    } else {
        &api.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(code: ResponseCode, message: &str) -> ProtonError {
        ProtonError::Api(ProtonApiError {
            code,
            http_status: 422,
            message: message.to_owned(),
            details: None,
        })
    }

    #[test]
    fn a_blocked_sign_in_keeps_the_response_but_not_its_wording() {
        let error = classify_begin_failure(api(ResponseCode::Blocked, "Please update the app"));
        assert!(matches!(&error, LoginError::Blocked(api) if api.code == ResponseCode::Blocked));
        assert!(!error.to_string().contains("update"), "{error}");
    }

    #[test]
    fn a_refused_password_shows_protons_reason() {
        let error =
            classify_begin_failure(api(ResponseCode::Unknown, "Incorrect login credentials"));
        assert_eq!(error.to_string(), "Incorrect login credentials");
        let silent = classify_begin_failure(api(ResponseCode::Unknown, ""));
        assert!(matches!(silent, LoginError::Rejected(_)));
        assert!(!silent.to_string().is_empty());
    }

    #[test]
    fn other_failures_stay_sdk_errors() {
        let error = classify_begin_failure(ProtonError::KeysLocked);
        assert!(matches!(error, LoginError::Proton(ProtonError::KeysLocked)));
    }
}

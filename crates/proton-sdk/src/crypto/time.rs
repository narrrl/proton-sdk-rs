//! The clock that new keys are stamped with.
//!
//! Proton's servers ignore a key's self-signatures when they are dated after
//! the server's own clock. A device whose clock runs a few seconds fast
//! therefore makes node keys the server considers to have no usable encryption
//! subkey yet, and creating a file fails with 422 "Could not verify the nodeKey
//! was used for encrypting contentKeyPacket". Like the official clients, keys
//! are stamped with the server's time, taken from the `Date` header of its
//! latest response. Mirrors C# `CryptographyTimeProvisionHandler`.

use std::sync::atomic::{AtomicU32, Ordering};

use pgp::types::Timestamp;

/// The latest server time seen, in seconds since the Unix epoch; 0 before the
/// first response.
static SERVER_TIME: AtomicU32 = AtomicU32::new(0);

/// Record the server time from a response's `Date` header. The clock only moves
/// forward, so a response that was delayed in transit cannot set it back.
pub fn note_server_date(date: &str) {
    let Ok(time) = chrono::DateTime::parse_from_rfc2822(date) else {
        return;
    };
    if let Ok(seconds) = u32::try_from(time.timestamp()) {
        SERVER_TIME.fetch_max(seconds, Ordering::Relaxed);
    }
}

/// The time to stamp new keys and their self-signatures with: the latest server
/// time, or the device clock before any response arrived.
pub(crate) fn key_time() -> Timestamp {
    match SERVER_TIME.load(Ordering::Relaxed) {
        0 => Timestamp::now(),
        seconds => Timestamp::from_secs(seconds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_date_only_moves_forward() {
        note_server_date("Tue, 17 Nov 2026 22:23:10 GMT");
        let later = key_time();
        note_server_date("Tue, 17 Nov 2026 22:23:00 GMT");
        note_server_date("not a date");
        assert_eq!(key_time(), later);
        assert!(later.as_secs() >= 1_794_954_190);
    }
}

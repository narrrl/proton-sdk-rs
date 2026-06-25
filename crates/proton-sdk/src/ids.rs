//! Strongly-typed string identifiers used across the SDK.
//!
//! Proton API identifiers are opaque strings. We wrap them in newtypes so the
//! type system prevents mixing e.g. a [`ShareId`] with a [`LinkId`], mirroring
//! the dedicated ID types in the C# SDK.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({:?})"), self.0)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }
    };
}

string_id!(
    /// Identifies an authenticated API session (`x-pm-uid`).
    SessionId
);
string_id!(
    /// Identifies a user account.
    UserId
);
string_id!(
    /// Identifies a user-level encryption key.
    UserKeyId
);
string_id!(
    /// Identifies an email address attached to an account.
    AddressId
);
string_id!(
    /// Identifies an address-level encryption key.
    AddressKeyId
);
string_id!(
    /// Identifies a Drive volume.
    VolumeId
);
string_id!(
    /// Identifies a Drive share.
    ShareId
);
string_id!(
    /// Identifies a Drive link (node) within a volume.
    LinkId
);
string_id!(
    /// Identifies a Drive volume event; doubles as the enumeration cursor.
    DriveEventId
);

/// Globally addresses a Drive node: a [`LinkId`] qualified by its [`VolumeId`].
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct NodeUid {
    pub volume_id: VolumeId,
    pub link_id: LinkId,
}

impl NodeUid {
    pub fn new(volume_id: VolumeId, link_id: LinkId) -> Self {
        Self { volume_id, link_id }
    }
}

impl fmt::Display for NodeUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}~{}", self.volume_id, self.link_id)
    }
}

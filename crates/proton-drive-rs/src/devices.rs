//! Devices: the synced folders a desktop client registers on the main volume.
//!
//! Mirrors C# `Proton.Drive.Sdk.Devices`. A device owns its own share and root
//! folder inside the main volume; the device *name* is the name of that root
//! folder (older devices kept it on the share instead — see
//! [`Device::has_deprecated_name`] handling in `ProtonDriveClient::rename_device`).

use proton_sdk::error::{ProtonError, Result};
use proton_sdk::ids::{DeviceUid, NodeUid, ShareId};

/// The platform a device runs on. Mirrors C# `DeviceType`; the discriminant is
/// the wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum DeviceType {
    Windows = 1,
    MacOs = 2,
    Linux = 3,
}

impl DeviceType {
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    pub(crate) fn from_raw(value: i32) -> Result<Self> {
        match value {
            1 => Ok(Self::Windows),
            2 => Ok(Self::MacOs),
            3 => Ok(Self::Linux),
            other => Err(ProtonError::invalid_operation(format!(
                "unsupported device type {other}"
            ))),
        }
    }
}

/// A registered device. Mirrors C# `Device`.
///
/// `name` is a `Result` because it is decrypted with the device's share key and
/// may fail independently of the rest of the device (C# models it as
/// `Result<string, ProtonDriveError>`): the device is still returned.
#[derive(Debug)]
pub struct Device {
    pub uid: DeviceUid,
    pub device_type: DeviceType,
    /// The decrypted device name, i.e. the name of its root folder.
    pub name: Result<String>,
    /// The device's root folder — the sync root.
    pub root_folder_uid: NodeUid,
    /// Creation time, epoch seconds.
    pub creation_time: i64,
    /// Last time the device synced, epoch seconds; `None` if it never did.
    pub last_sync_time: Option<i64>,
    /// The device's own share. Kept because a device root is not reachable from
    /// the My Files share key (C# `Device.ShareId`, deprecated there pending
    /// volume-based navigation, but still the only way to unlock the root).
    pub share_id: ShareId,
}

/// A device without its (decrypted) name. Mirrors C# `DeviceMetadata`.
#[derive(Debug, Clone)]
pub(crate) struct DeviceMetadata {
    pub uid: DeviceUid,
    pub device_type: DeviceType,
    pub root_folder_uid: NodeUid,
    pub creation_time: i64,
    pub last_sync_time: Option<i64>,
    /// The device name used to live on the share. Old devices still carry it
    /// there, and it must be removed when renaming.
    pub has_deprecated_name: bool,
    pub share_id: ShareId,
}

impl DeviceMetadata {
    pub(crate) fn into_device(self, name: Result<String>) -> Device {
        Device {
            uid: self.uid,
            device_type: self.device_type,
            name,
            root_folder_uid: self.root_folder_uid,
            creation_time: self.creation_time,
            last_sync_time: self.last_sync_time,
            share_id: self.share_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_type_round_trips_through_the_wire_value() {
        for device_type in [DeviceType::Windows, DeviceType::MacOs, DeviceType::Linux] {
            assert_eq!(
                DeviceType::from_raw(device_type.as_i32()).expect("known device type"),
                device_type
            );
        }
        assert!(DeviceType::from_raw(0).is_err());
        assert!(DeviceType::from_raw(4).is_err());
    }
}

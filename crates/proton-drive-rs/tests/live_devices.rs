//! Live integration: device registration and the account quota read surface,
//! against a real Proton account.
//!
//! Skipped by default. Run against the test account with:
//!   cargo test -p proton-drive-rs --test live_devices -- --ignored --nocapture
//!
//! The device test registers a throwaway device and deletes it at the end, so
//! the account stays reusable across runs.

mod common;

use proton_drive_rs::{DeviceType, ProtonDriveClient};
use proton_sdk::ids::DeviceUid;

/// Delete the device; best-effort, logs on failure.
async fn cleanup(client: &ProtonDriveClient, uid: &DeviceUid) {
    if let Err(e) = client.delete_device(uid).await {
        eprintln!("[cleanup] delete_device failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// Device lifecycle
// ---------------------------------------------------------------------------

/// create → enumerate (find + name decrypts) → rename → delete (gone).
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn device_create_enumerate_rename_delete() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let name = format!("dev-{}", common::unique_suffix());

    // create
    let device = client
        .create_device(&name, DeviceType::Linux)
        .await
        .expect("create_device");
    assert_eq!(
        device.device_type,
        DeviceType::Linux,
        "type must round-trip"
    );
    assert_eq!(
        device.name.as_deref().ok(),
        Some(name.as_str()),
        "created device name must match"
    );
    let uid = device.uid.clone();

    // enumerate: the new device must appear, and its name must decrypt to what
    // we set (this exercises the device-share-key name decryption path, which
    // the offline tests can't reach).
    let listed = client.enumerate_devices().await.expect("enumerate_devices");
    let found = listed
        .iter()
        .find(|d| d.uid == uid)
        .expect("the created device must appear in the enumeration");
    assert_eq!(
        found.name.as_deref().ok(),
        Some(name.as_str()),
        "enumerated device name must decrypt to the created name"
    );
    assert_eq!(
        found.device_type,
        DeviceType::Linux,
        "enumerated device type must match"
    );

    // rename
    let renamed = format!("{name}-renamed");
    client
        .rename_device(&uid, &renamed)
        .await
        .expect("rename_device");
    let after = client
        .enumerate_devices()
        .await
        .expect("enumerate_devices (after rename)");
    let found = after
        .iter()
        .find(|d| d.uid == uid)
        .expect("device must still be present after rename");
    assert_eq!(
        found.name.as_deref().ok(),
        Some(renamed.as_str()),
        "rename must take effect and re-decrypt"
    );

    // delete
    cleanup(client, &uid).await;
    let gone = client
        .enumerate_devices()
        .await
        .expect("enumerate_devices (after delete)");
    assert!(
        !gone.iter().any(|d| d.uid == uid),
        "device must be gone after deletion"
    );
}

// ---------------------------------------------------------------------------
// Account quota (read-only)
// ---------------------------------------------------------------------------

/// The account quota must read back with sane values.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn quota_reads() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let quota = client.quota().await.expect("quota");
    eprintln!(
        "[info] quota: used {} / max {} bytes ({:.1}% used)",
        quota.used_space,
        quota.max_space,
        quota.used_fraction() * 100.0
    );

    assert!(quota.max_space > 0, "a real account has non-zero max space");
    assert!(quota.used_space >= 0, "used space cannot be negative");
    assert!(
        quota.used_space <= quota.max_space,
        "used space cannot exceed max space"
    );
    assert!(
        (0.0..=1.0).contains(&quota.used_fraction()),
        "used fraction must be a probability"
    );
}

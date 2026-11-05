//! Live integration: album writes on the photos volume against a real Proton
//! account.
//!
//! Skipped by default, and skipped at run time when the account has no photos
//! volume. Run against the test account with:
//!   cargo test -p proton-drive-rs --test live_albums -- --ignored --nocapture
//!
//! The test deletes the album and the photo it uploads.

mod common;

use proton_drive_rs::{PhotoUploadMetadata, ProtonPhotosClient};

#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn photo_capture_and_modification_times_are_independent() {
    use proton_drive_rs::{ModificationTime, NodeKind};

    let Some(live) = common::live_client().await else {
        return;
    };
    let photos = ProtonPhotosClient::from_drive_client(live.client.clone());
    if photos.get_photos_root().await.unwrap().is_none() {
        return;
    }
    let modified: ModificationTime = "2026-11-05T09:55:00.1234567+08:00".parse().unwrap();
    for last_modification_time in [None, Some(modified)] {
        let suffix = common::unique_suffix();
        let content = format!("timestamp test {suffix}");
        let photo = photos
            .upload_photo(
                &format!("timestamps-{suffix}.jpg"),
                "image/jpeg",
                content.as_bytes(),
                PhotoUploadMetadata {
                    capture_time: Some(1_700_000_000),
                    last_modification_time,
                    ..Default::default()
                },
            )
            .await
            .expect("upload photo");
        let node = photos.get_node(&photo).await;
        // Clean up before asserting so a timestamp mismatch leaves no photo.
        let drive = photos.drive_client();
        let uids = [photo];
        common::log_outcomes("trash", &drive.trash_nodes(&uids).await.unwrap());
        common::log_outcomes("delete", &drive.delete_nodes(&uids).await.unwrap());

        let node = node.expect("read photo").expect("photo exists");
        assert_eq!(node.photo.unwrap().capture_time, 1_700_000_000);
        let NodeKind::File {
            claimed_modification_time,
            ..
        } = node.kind
        else {
            panic!("photo is a file");
        };
        let actual =
            claimed_modification_time.map(|time| time.parse::<ModificationTime>().unwrap());
        assert_eq!(actual, last_modification_time);
        if let Some(actual) = actual {
            assert_eq!(actual.offset(), modified.offset());
        }
    }
}

/// add → add again → cover → remove → add → delete keeping photos, on a photo
/// that is also in the timeline.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn album_add_cover_remove_and_delete_keeping_photos() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let photos = ProtonPhotosClient::from_drive_client(live.client.clone());
    if photos
        .get_photos_root()
        .await
        .expect("photos root")
        .is_none()
    {
        eprintln!("[albums] the account has no photos volume; skipping");
        return;
    }

    let suffix = common::unique_suffix();
    let photo = photos
        .upload_photo(
            &format!("album-ops-{suffix}.jpg"),
            "image/jpeg",
            b"\xff\xd8\xff\xe0 not really a jpeg",
            PhotoUploadMetadata {
                capture_time: Some(1_700_000_000),
                ..Default::default()
            },
        )
        .await
        .expect("upload photo");
    let album = photos
        .create_album(&format!("album-ops-{suffix}"))
        .await
        .expect("create album");

    let added = photos
        .add_photos_to_album(&album, std::slice::from_ref(&photo))
        .await
        .expect("add to album");
    assert_eq!(added.len(), 1);
    assert!(added[0].1.is_ok(), "the photo is added: {:?}", added[0].1);

    let again = photos
        .add_photos_to_album(&album, std::slice::from_ref(&photo))
        .await
        .expect("add to album again");
    eprintln!("[albums] adding twice: {:?}", again[0].1);
    assert!(
        again[0].1.is_err(),
        "a photo already in the album fails its outcome"
    );

    photos
        .set_album_cover(&album, &photo)
        .await
        .expect("set album cover");
    let items = photos.enumerate_album(&album).await.expect("list album");
    assert!(
        items.iter().any(|item| item.uid == photo),
        "the album lists the photo"
    );

    let removed = photos
        .remove_photos_from_album(&album, std::slice::from_ref(&photo))
        .await
        .expect("remove from album");
    assert!(
        removed[0].1.is_ok(),
        "the photo is removed: {:?}",
        removed[0].1
    );

    photos
        .add_photos_to_album(&album, std::slice::from_ref(&photo))
        .await
        .expect("add to album once more");
    photos
        .delete_album_saving_photos(&album)
        .await
        .expect("delete the album, keeping its photos");
    assert!(
        photos.get_node(&photo).await.expect("read photo").is_some(),
        "the photo outlives the album"
    );

    let drive = photos.drive_client();
    let uids = [photo];
    match drive.trash_nodes(&uids).await {
        Ok(outcomes) => common::log_outcomes("trash", &outcomes),
        Err(e) => eprintln!("[cleanup] trash failed: {e}"),
    }
    match drive.delete_nodes(&uids).await {
        Ok(outcomes) => common::log_outcomes("delete", &outcomes),
        Err(e) => eprintln!("[cleanup] delete failed: {e}"),
    }
}

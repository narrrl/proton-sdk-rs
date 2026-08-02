//! Live integration: sharing — public links, standard-share creation, and the
//! read-only shared-with-me / incoming-invitation surfaces, against a real
//! Proton account.
//!
//! Skipped by default. Run against the test account with:
//!   cargo test -p proton-drive-rs --test live_sharing -- --ignored --nocapture
//!
//! Each test creates its own throwaway folder and deletes it at the end
//! (deleting the node tears down any share created on it), so the account stays
//! reusable across runs.
//!
//! What is *not* covered here: inviting a real Proton user (`share_node` with a
//! non-empty invitee list) and accept/reject flows. Those need a *second*
//! account, and inviting a stranger would send them a real email — out of scope
//! for a single-account CI harness. We still exercise share *creation* (the
//! crypto + `POST shares`) by calling `share_node` with an empty invitee list,
//! which provisions the standard share without emailing anyone.

mod common;

use proton_drive_rs::{
    MemberRole, ProtonDriveClient, ProtonDrivePublicLinkClient, ProtonPhotosClient, Thumbnail,
    ThumbnailType,
};
use proton_sdk::ids::NodeUid;

/// Trash then permanently delete the given node; best-effort, logs on failure.
async fn cleanup(client: &ProtonDriveClient, uid: &NodeUid) {
    if let Err(e) = client.trash_nodes(std::slice::from_ref(uid)).await {
        eprintln!("[cleanup] trash failed: {e}");
        return;
    }
    if let Err(e) = client.delete_nodes(std::slice::from_ref(uid)).await {
        eprintln!("[cleanup] delete failed: {e}");
    }
}

/// Create a throwaway folder under My Files, returning its uid.
async fn scratch_folder(client: &ProtonDriveClient, tag: &str) -> NodeUid {
    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let name = format!("{tag}-{}", common::unique_suffix());
    client
        .create_folder(&root.uid, &name, None)
        .await
        .expect("create scratch folder")
}

// ---------------------------------------------------------------------------
// Public links
// ---------------------------------------------------------------------------

/// Full public-link lifecycle on a folder: create → get → remove.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn public_link_create_get_remove() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "publink").await;

    // No public link yet.
    assert!(
        client
            .get_public_link(&folder)
            .await
            .expect("get_public_link (before)")
            .is_none(),
        "a fresh folder must have no public link"
    );

    // Create a viewer link (no custom password, no expiry).
    let link = client
        .create_public_link(&folder, MemberRole::Viewer, None, None)
        .await
        .expect("create_public_link");

    assert_eq!(link.role, MemberRole::Viewer, "role must round-trip");
    assert!(
        !link.has_custom_password,
        "no custom password was requested"
    );
    let url = link.url.as_deref().expect("created link carries its URL");
    assert!(
        url.contains('#'),
        "the URL must carry the secret password fragment: {url}"
    );

    // Now it must be discoverable via get_public_link.
    let fetched = client
        .get_public_link(&folder)
        .await
        .expect("get_public_link (after)")
        .expect("public link must exist after creation");
    assert_eq!(
        fetched.public_link_id, link.public_link_id,
        "get must return the link we just created"
    );
    assert_eq!(fetched.role, MemberRole::Viewer, "fetched role must match");

    // Remove it and confirm it is gone.
    client
        .remove_public_link(&link)
        .await
        .expect("remove_public_link");
    assert!(
        client
            .get_public_link(&folder)
            .await
            .expect("get_public_link (after remove)")
            .is_none(),
        "public link must be gone after removal"
    );

    cleanup(client, &folder).await;
}

/// A public link with a custom password reports `has_custom_password` and still
/// round-trips through get/remove.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn public_link_with_custom_password() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "publink-pw").await;

    let link = client
        .create_public_link(&folder, MemberRole::Editor, Some("s3cr3t!"), None)
        .await
        .expect("create_public_link with custom password");

    assert_eq!(link.role, MemberRole::Editor, "editor role must round-trip");
    assert!(
        link.has_custom_password,
        "a custom password must set has_custom_password"
    );

    let fetched = client
        .get_public_link(&folder)
        .await
        .expect("get_public_link")
        .expect("link must exist");
    assert!(
        fetched.has_custom_password,
        "the listed link must also report the custom password"
    );

    client
        .remove_public_link(&link)
        .await
        .expect("remove_public_link");

    cleanup(client, &folder).await;
}

// ---------------------------------------------------------------------------
// Standard share creation (no real invitees)
// ---------------------------------------------------------------------------

/// `share_node` with an empty invitee list provisions the standard share (the
/// crypto + `POST shares`) without emailing anyone; the members and pending
/// invitations then read back empty.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn share_node_creates_share_and_lists_are_empty() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "share").await;

    // Not shared yet: both listings are empty.
    assert!(
        client
            .list_share_members(&folder)
            .await
            .expect("list_share_members (before)")
            .is_empty(),
        "an unshared folder has no members"
    );
    assert!(
        client
            .list_share_invitations(&folder)
            .await
            .expect("list_share_invitations (before)")
            .is_empty(),
        "an unshared folder has no invitations"
    );

    // Provision the share without inviting anyone.
    let created = client
        .share_node(&folder, &[], None)
        .await
        .expect("share_node with no invitees");
    assert!(
        created.is_empty(),
        "no invitees means no invitations created: {created:?}"
    );

    // The share now exists, but with no members and no pending invitations.
    assert!(
        client
            .list_share_members(&folder)
            .await
            .expect("list_share_members (after)")
            .is_empty(),
        "no one was invited, so there are no members"
    );
    assert!(
        client
            .list_share_invitations(&folder)
            .await
            .expect("list_share_invitations (after)")
            .is_empty(),
        "no one was invited, so there are no pending invitations"
    );

    cleanup(client, &folder).await;
}

// ---------------------------------------------------------------------------
// Read-only shared-with-me / incoming invitations
// ---------------------------------------------------------------------------

/// The shared-with-me and incoming-invitation read surfaces must resolve without
/// error even when there is nothing shared with this account (they typically
/// return empty on the throwaway test account).
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn shared_with_me_and_incoming_invitations_read() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let shared = client
        .enumerate_shared_with_me_node_uids()
        .await
        .expect("enumerate_shared_with_me_node_uids must not error");
    eprintln!("[info] shared-with-me count: {}", shared.len());

    let incoming = client
        .list_incoming_invitations()
        .await
        .expect("list_incoming_invitations must not error");
    eprintln!("[info] incoming invitations count: {}", incoming.len());
}

/// The shared-by-me read surface must resolve on both volumes: the main volume
/// (`ProtonDriveClient`) and the photos volume (`ProtonPhotosClient`, C#
/// `EnumerateSharedNodeUidsAsync`). Empty is a pass — an account with nothing
/// shared, or with no photos volume at all, must not error.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn shared_by_me_read() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let shared = client
        .enumerate_shared_by_me_node_uids()
        .await
        .expect("enumerate_shared_by_me_node_uids must not error");
    eprintln!("[info] shared-by-me count (main volume): {}", shared.len());

    let photos = ProtonPhotosClient::from_drive_client(client.clone());
    let shared_photos = photos
        .enumerate_shared_node_uids()
        .await
        .expect("photos enumerate_shared_node_uids must not error");
    eprintln!(
        "[info] shared-by-me count (photos volume): {}",
        shared_photos.len()
    );
}

// ---------------------------------------------------------------------------
// Public link — consuming a link as an anonymous visitor
// ---------------------------------------------------------------------------

/// Full loop: upload a file, publish a link on its folder, then open that link
/// with [`ProtonDrivePublicLinkClient`] — no session — and read the file back.
///
/// This is the only test that exercises both halves of the public-link feature
/// against each other, so a break in either the mint or the consume side shows
/// up here.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn public_link_round_trips_through_the_visitor_client() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "public-visit").await;

    let contents = b"public link visitor payload".to_vec();
    let name = format!("shared-{}.txt", common::unique_suffix());
    let file = client
        .upload_file(&folder, &name, "text/plain", &contents)
        .await
        .expect("upload_file");

    let link = client
        .create_public_link(&folder, MemberRole::Viewer, None, None)
        .await
        .expect("create_public_link");

    // Pre-auth metadata: a link with no custom password must say so, or a caller
    // would prompt for one that does not exist.
    let url = link.url.clone().expect("a created link must carry its URL");

    let info = ProtonDrivePublicLinkClient::info(common::config(), &url)
        .await
        .expect("public link info");
    assert!(
        !info.is_legacy,
        "a freshly minted link must not read as legacy"
    );
    assert!(
        !info.is_custom_password_protected,
        "no custom password was set"
    );

    // Open it as a visitor — no session, only the URL.
    let visitor = ProtonDrivePublicLinkClient::open(common::config(), &url, None)
        .await
        .expect("open public link");

    assert_eq!(
        visitor.public_role(),
        MemberRole::Viewer,
        "the link was minted read-only"
    );

    let root = visitor.get_root_node().await.expect("visitor root node");
    assert_eq!(root.uid, folder, "the link points at the shared folder");
    assert!(root.is_folder(), "the shared node is a folder");

    // The shared subtree lists and decrypts with the share key alone.
    let child_uids = visitor
        .enumerate_folder_children_node_uids(&folder)
        .await
        .expect("visitor lists children");
    assert!(
        child_uids.contains(&file),
        "the uploaded file must appear in the shared listing"
    );

    let children = visitor
        .enumerate_nodes(&child_uids)
        .await
        .expect("visitor decrypts children");
    let shared_file = children
        .iter()
        .find(|node| node.uid == file)
        .expect("the uploaded file must decrypt for the visitor");
    assert_eq!(
        shared_file.name, name,
        "the name must decrypt to what was uploaded"
    );

    // The payload itself: content key unwrapped from the node key, blocks pulled
    // from storage with the anonymous session.
    let downloaded = visitor
        .download_file(&file)
        .await
        .expect("visitor download");
    assert_eq!(
        downloaded, contents,
        "the visitor must read back exactly what was uploaded"
    );

    // Revoking the link must actually close the door.
    client
        .remove_public_link(&link)
        .await
        .expect("remove_public_link");
    assert!(
        ProtonDrivePublicLinkClient::open(common::config(), &url, None)
            .await
            .is_err(),
        "a revoked link must no longer open"
    );

    cleanup(client, &folder).await;
}

/// A custom-password link must advertise the requirement and refuse to open
/// without it.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn custom_password_link_requires_the_password() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "public-custompw").await;
    let custom = "s3cr3t!";

    let link = client
        .create_public_link(&folder, MemberRole::Viewer, Some(custom), None)
        .await
        .expect("create_public_link with custom password");

    let url = link.url.clone().expect("a created link must carry its URL");

    let info = ProtonDrivePublicLinkClient::info(common::config(), &url)
        .await
        .expect("public link info");
    assert!(
        info.is_custom_password_protected,
        "the link must advertise that a custom password is needed"
    );

    // Without the custom password the SRP handshake itself fails — the server
    // never hands over the encrypted share key.
    assert!(
        ProtonDrivePublicLinkClient::open(common::config(), &url, None)
            .await
            .is_err(),
        "opening without the custom password must fail"
    );

    let visitor = ProtonDrivePublicLinkClient::open(common::config(), &url, Some(custom))
        .await
        .expect("open with the custom password");
    let root = visitor.get_root_node().await.expect("visitor root node");
    assert_eq!(root.uid, folder);

    cleanup(client, &folder).await;
}

// ---------------------------------------------------------------------------
// Public link — seekable reads, the streaming path
// ---------------------------------------------------------------------------

/// A multi-block file, in blocks of `4 MiB`, whose every byte encodes its own
/// offset. A range served from the wrong block is then identifiable rather than
/// merely unequal — which matters here, because a wrong block-size vector
/// returns a full-length read of the wrong bytes with no error at all.
fn positional_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// **The load-bearing test for streaming over a public link.**
///
/// Everything `proton-stream` does rests on one uncertain fact: that the
/// `drive/unauth/` revision endpoint returns a usable `XAttr` to an anonymous
/// visitor. Without it `rank_block_sizes` cannot place block boundaries and
/// refuses to open a multi-block file, and seeking is impossible. The visitor
/// route has form here — `?NoBlockUrls=true` already strips `BareURL`/`Token` —
/// so this is verified, not assumed.
///
/// Then the reads themselves: a range spanning a block boundary, a range wholly
/// inside a later block (the seek case), and the short final block.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn a_visitor_can_seek_within_a_shared_multi_block_file() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "public-seek").await;

    // 9 MiB: two full 4 MiB blocks and a 1 MiB tail, so both the boundary case
    // and the short-tail case are reachable.
    const BLOCK: usize = 4 << 20;
    let contents = positional_payload(9 << 20);
    let name = format!("seekable-{}.bin", common::unique_suffix());
    let file = client
        .upload_file(&folder, &name, "application/octet-stream", &contents)
        .await
        .expect("upload_file");

    let link = client
        .create_public_link(&folder, MemberRole::Viewer, None, None)
        .await
        .expect("create_public_link");
    let url = link.url.clone().expect("a created link must carry its URL");

    let visitor = ProtonDrivePublicLinkClient::open(common::config(), &url, None)
        .await
        .expect("open public link");

    let reader = visitor
        .open_revision(&file)
        .await
        .expect("a visitor must be able to open a revision for reading");

    // If this fails, the unauth revision response carried no usable size and the
    // whole streaming design needs revisiting — so it is asserted before the
    // reads, with a message that says which rung was missing.
    assert_eq!(
        reader.block_sizes(),
        &[BLOCK as u64, BLOCK as u64, 1 << 20],
        "the visitor must resolve true per-block sizes; a padded or empty vector \
         means the unauth revision response omitted its XAttr"
    );
    assert_eq!(
        reader.size(),
        contents.len() as u64,
        "and they must sum to the real file size"
    );

    // A range straddling the block 0 / block 1 boundary.
    let straddle = reader
        .read_at(BLOCK as u64 - 1024, 2048)
        .await
        .expect("read across a block boundary");
    assert_eq!(
        straddle,
        &contents[BLOCK - 1024..BLOCK + 1024],
        "a read spanning two blocks must splice them at the right offset"
    );

    // The seek case: a range wholly inside the *last* full block, touching
    // neither of the ones before it.
    let seeked = reader
        .read_at(6 << 20, 64 << 10)
        .await
        .expect("read from the middle of the file");
    let want = &contents[(6 << 20)..(6 << 20) + (64 << 10)];
    assert_eq!(
        seeked, want,
        "a mid-file read must return the bytes at that offset, not an earlier block's"
    );

    // The short tail, and a read that runs past EOF: clamped, never padded.
    let tail = reader
        .read_at(8 << 20, 4 << 20)
        .await
        .expect("read the short final block");
    assert_eq!(
        tail,
        &contents[8 << 20..],
        "the final block is 1 MiB, and a read past EOF is clamped to it"
    );
    assert!(
        reader
            .read_at(contents.len() as u64, 4096)
            .await
            .expect("a read at EOF is not an error")
            .is_empty(),
        "a read starting at EOF yields nothing"
    );

    // `download_range` is the one-shot form of the same thing.
    let ranged = visitor
        .download_range(&file, 5 << 20, 4096)
        .await
        .expect("download_range");
    assert_eq!(ranged, &contents[(5 << 20)..(5 << 20) + 4096]);

    // And the whole-file path must still agree with all of it — it now drives a
    // paged, concurrent block pipeline rather than one un-paged sequential loop.
    let whole = visitor
        .download_file(&file)
        .await
        .expect("visitor download");
    assert_eq!(
        whole, contents,
        "the whole-file download must match the uploaded bytes"
    );

    cleanup(client, &folder).await;
}

/// A visitor's node listing must carry the uploader's claimed metadata, which it
/// previously left as `None` — a catalog has nothing to show without a size.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn a_visitor_sees_claimed_size_and_digest_on_shared_files() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "public-xattr").await;

    let contents = positional_payload(64 << 10);
    let name = format!("claimed-{}.bin", common::unique_suffix());
    let file = client
        .upload_file(&folder, &name, "application/octet-stream", &contents)
        .await
        .expect("upload_file");

    let link = client
        .create_public_link(&folder, MemberRole::Viewer, None, None)
        .await
        .expect("create_public_link");
    let url = link.url.clone().expect("a created link must carry its URL");

    let visitor = ProtonDrivePublicLinkClient::open(common::config(), &url, None)
        .await
        .expect("open public link");

    let node = visitor
        .get_node(&file)
        .await
        .expect("visitor node lookup")
        .expect("the shared file must exist");

    match &node.kind {
        proton_drive_rs::NodeKind::File {
            claimed_size,
            content_sha1,
            ..
        } => {
            assert_eq!(
                *claimed_size,
                Some(contents.len() as i64),
                "the visitor must read the uploader's claimed size from the link details XAttr"
            );
            assert!(
                content_sha1.is_some(),
                "and the content digest alongside it"
            );
        }
        other => panic!("expected a file, got {other:?}"),
    }

    cleanup(client, &folder).await;
}

/// Renewing the session must not strand a reader that was already handed out —
/// the whole reason the session is swapped in place rather than replaced.
///
/// Simulates the expiry rather than waiting hours for one: an explicit
/// `refresh_session` puts the reader on a session it was not opened with, which
/// is exactly the state a real expiry leaves it in once recovery has run.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn refreshing_the_session_keeps_an_open_reader_working() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "public-renew").await;

    let contents = positional_payload(5 << 20);
    let name = format!("renew-{}.bin", common::unique_suffix());
    let file = client
        .upload_file(&folder, &name, "application/octet-stream", &contents)
        .await
        .expect("upload_file");

    let link = client
        .create_public_link(&folder, MemberRole::Viewer, None, None)
        .await
        .expect("create_public_link");
    let url = link.url.clone().expect("a created link must carry its URL");

    let visitor = ProtonDrivePublicLinkClient::open(common::config(), &url, None)
        .await
        .expect("open public link");

    let reader = visitor.open_revision(&file).await.expect("open_revision");

    let before = reader.read_at(0, 4096).await.expect("read before refresh");
    assert_eq!(before, &contents[..4096]);

    visitor
        .refresh_session()
        .await
        .expect("refresh_session must replay the handshake");

    // Past the first block, so this genuinely fetches under the new session
    // rather than replaying anything cached.
    let after = reader
        .read_at(4 << 20, 4096)
        .await
        .expect("a reader opened before the refresh must keep working");
    assert_eq!(after, &contents[(4 << 20)..(4 << 20) + 4096]);

    cleanup(client, &folder).await;
}

/// Thumbnails on the visitor path: the same block-storage fetch and content-key
/// decrypt as the authenticated one, over `drive/unauth/`.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn a_visitor_can_download_thumbnails_of_shared_files() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "public-thumb").await;

    let contents = positional_payload(32 << 10);
    let thumbnail = b"not a real jpeg, but it round-trips".to_vec();
    let name = format!("thumbed-{}.bin", common::unique_suffix());
    let file = client
        .upload_file_from(
            &folder,
            &name,
            "application/octet-stream",
            std::io::Cursor::new(contents.clone()),
            contents.len() as i64,
            vec![
                Thumbnail::new(ThumbnailType::Thumbnail, thumbnail.clone())
                    .expect("small thumbnail"),
            ],
            None,
            false,
        )
        .await
        .expect("upload_file_from with a thumbnail");

    let link = client
        .create_public_link(&folder, MemberRole::Viewer, None, None)
        .await
        .expect("create_public_link");
    let url = link.url.clone().expect("a created link must carry its URL");

    let visitor = ProtonDrivePublicLinkClient::open(common::config(), &url, None)
        .await
        .expect("open public link");

    let single = visitor
        .download_thumbnail(&file, ThumbnailType::Thumbnail)
        .await
        .expect("visitor thumbnail download");
    assert_eq!(
        single.as_deref(),
        Some(thumbnail.as_slice()),
        "the visitor must decrypt the thumbnail it was shown"
    );

    let batch = visitor
        .enumerate_thumbnails(std::slice::from_ref(&file), ThumbnailType::Thumbnail)
        .await
        .expect("visitor thumbnail batch");
    assert_eq!(batch.len(), 1, "one file in, one result out");
    assert_eq!(
        batch[0]
            .result
            .as_deref()
            .expect("the batch entry succeeded"),
        thumbnail.as_slice()
    );

    cleanup(client, &folder).await;
}

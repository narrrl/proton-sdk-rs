# Changelog

Notable changes to `proton-sdk` and `proton-drive-rs`. The format follows
[Keep a Changelog](https://keepachangelog.com/1.1.0/); versions follow semver,
and both crates are released together under the workspace version. Upstream
commits a change ports are recorded in [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md).

This file starts after 0.9.2; earlier changes are in the git history.

## [Unreleased]

### Added

- **Server-side copy.** `ProtonDriveClient::copy_node(uid, new_parent, name)`
  copies a file, or a folder with everything in it, without downloading and
  uploading it. The copy may get a new name and may land on another volume; the
  returned uid is on the target volume. Ported from the TypeScript SDK
  (`copyNode`).
- **Folder size.** `ProtonDriveClient::get_folder_size(uid)` returns a
  `FolderSize` with the total size and the number of descendants, trashed nodes
  included. Folders count as descendants, and the size is in encrypted bytes.
  Ported from the TypeScript SDK (`getFolderSize`).
- **Changing a public link.** `ProtonDriveClient::update_public_link(uid, role,
  custom_password, expiration_time)` sets the role, the custom password and the
  expiry of the link on a node. The URL does not change. `None` removes a custom
  password or an expiry. A legacy link cannot be updated. Ported from the
  TypeScript SDK (`updateSharedLink`).
- **Walking a public link.** `ProtonDrivePublicLinkClient::enumerate_subtree`
  and `enumerate_subtree_reporting` return every node below a shared folder,
  breadth first, listing several folders of a level at once.
- **Bookmark names.** `list_bookmarks` now decrypts the bookmarked item's name
  into `Bookmark::node_name`, and returns the link's custom password in the new
  `Bookmark::custom_password` field.
- **Album capabilities from the C# SDK** (`a36cc423`):
  - `ProtonPhotosClient::set_album_cover`;
  - `ProtonPhotosClient::delete_album_saving_photos`, which on
    `AlbumContainsPhotosNotInTimeline` (code 200302) saves the photos that are
    only in the album to the timeline and deletes the album again;
  - `add_photos_to_album` adds photos from another volume by copying them in,
    instead of refusing them;
  - a photo group the server reports as incomplete is retried once with the
    missing related photos.
- `ResponseCode::AlbumContainsPhotosNotInTimeline`.
- `ApiHttpClient::post_query`, a POST that only reads and may be sent again.

### Changed

- **A read is sent again when its connection drops.** A GET, a block download or
  a `post_query` that loses its connection mid-request or while reading the body
  is retried under the client's retry policy. A write still is not: it may have
  been applied. Read-only POSTs in `proton-drive-rs` (link details, thumbnails,
  photo duplicates, `checkAvailableHashes`) now use `post_query`.
- `remove_photos_from_album` refuses a photo on another volume per photo, in
  the input order, without sending it.

### Fixed

- A bookmark's URL fragment is now only the generated password, as in the URL
  the web client shows. It used to include the custom password as well.

### Breaking

- `Bookmark` has a new public field, `custom_password`. Code that builds a
  `Bookmark` with a struct literal must set it.
- `ResponseCode` has a new variant. An exhaustive `match` on it needs an arm.

# Changelog

Notable changes to `proton-sdk` and `proton-drive-rs`. The format follows
[Keep a Changelog](https://keepachangelog.com/1.1.0/); versions follow semver,
and both crates are released together under the workspace version. Upstream
commits a change ports are recorded in [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md).

This file starts after 0.9.2; earlier changes are in the git history.

## [0.10.1] — 2026-10-31

### Fixed

- **Address keys whose token is for an inactive account key.** An address key's
  token was decrypted with the active account keys only. A token encrypted to
  an account key since marked inactive never opened, although that key still
  opens with the password, so the address failed with "has no primary key".
  Tokens are now tried with every account key that opens, active ones first.
  Signing still uses active keys only. `AccountClient::key_report` follows the
  same chain.
- **One broken address no longer fails the account.** `AccountClient::addresses`
  failed as a whole when any one address's keys did not open. That address is
  now left out with a warning, and the others work. It fails only when no
  address opens. `address_private_keys` names the reason for a left-out
  address, and `default_address` fails with it when the left-out address is the
  default, instead of handing out the next address.

### Added

- `AccountClient::address(id)`: one address by id, failing with the reason when
  its keys did not open. `proton-drive-rs` uses it to resolve membership
  addresses, which before said "membership address not found" for such an
  address.

## [0.10.0] — 2026-10-26

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
- **A public link's custom password.** `PublicLink::custom_password` holds the
  custom password of a link, recovered from the stored link password, so a
  caller can keep it while `update_public_link` changes the role or the expiry.
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
- `Debug` for `PublicLink` and `Bookmark` no longer prints the URL or the
  custom password; it shows `<redacted>` instead.
- `remove_photos_from_album` refuses a photo on another volume per photo, in
  the input order, without sending it.

### Fixed

- A bookmark's URL fragment is now only the generated password, as in the URL
  the web client shows. It used to include the custom password as well.

### Breaking

- `Bookmark` and `PublicLink` have a new public field, `custom_password`. Code
  that builds either with a struct literal must set it.
- `ResponseCode` has a new variant. An exhaustive `match` on it needs an arm.

# Changelog

Notable changes to `proton-sdk` and `proton-drive-rs`. The format follows
[Keep a Changelog](https://keepachangelog.com/1.1.0/); versions follow semver,
and both crates are released together under the workspace version. Upstream
commits a change ports are recorded in [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md).

This file starts after 0.9.2; earlier changes are in the git history.

## [0.12.6] — 2026-11-22

### Fixed

- **Emptying the trash no longer reports an error when it works.** The server
  answers `DELETE volumes/{vid}/trash` with HTTP 202 and empties the trash in
  the background. `empty_trash` treated that answer as a failure. It now treats
  it as success, as `restore_revision` already does.

## [0.12.5] — 2026-11-22

### Fixed

- **Listing a large trash no longer runs forever.** `enumerate_trash_node_uids`
  sent its paging parameters in lower case, unlike every other paged request,
  and asked for another page as long as pages came back full. On a large trash
  it never finished. It now sends `Page` and `PageSize`, and it stops when a
  page brings no link it has not seen, after at most 10 000 pages.

### Added

- `ProtonDriveClient::enumerate_trashed_nodes_light` returns trashed nodes
  with the time each was trashed (`TrashedNode`), which `Node` does not carry.

## [0.12.4] — 2026-11-21

### Added

- `ProtonPhotosClient::find_missing_thumbnails` lists which photos have no
  thumbnail, from link details read in batches, without downloading any.

## [0.12.3] — 2026-11-21

### Changed

- **Thumbnails need fewer round trips.** `download_thumbnail` used to make
  four requests in a row for each thumbnail: link details, the revision's
  full block list (only to find the thumbnail ids), the thumbnail URL, and
  the blob.
  - The thumbnail ids now come from the link details when the API lists them
    there (`ActiveRevisionDto::thumbnails`). The revision is read only when
    it doesn't.
  - The client remembers each file's content key and thumbnail ids, for up to
    4096 files. A repeat request, a retry, or a fall back from the small
    thumbnail to the preview then needs only the URL and the blob.
  - A node's events drop its entry, and so does a failed fetch from a
    remembered entry, which then looks the file up again.

## [0.12.2] — 2026-11-20

### Added

- **`proton_sdk::login`: the whole sign-in as a small state machine.**
  `login::begin` runs the password step and returns a `Step`:
  `SecondFactor`, `MailboxPassword`, or `Unlock` for a one-password account.
  `Pending::second_factor` takes a code. `Pending::mailbox_password` and
  `Pending::unlock` derive the key passphrases and hand back `Unlocked`
  (session, key passphrases, key salts). Both work by reference, so a mistyped
  mailbox password or a dropped connection can be retried on the same
  session. `LoginError` sorts failures into what a frontend acts on:
  a CAPTCHA gate, an account whose only second factor is a security key, a
  blocked client, a refused password, a wrong code, a wrong mailbox password.
  This sequence previously lived in each app; it moves here from
  `proton-auth-rs`.
- `ProtonApiSession::resume_parameters` and `resume_parameters_with(tokens)`,
  which build the `ResumeParameters` for storing a session, with the current
  tokens or the pair a refresh handed over.
- `PasswordMode::from_wire` is public, with its inverse `PasswordMode::to_wire`,
  for callers that store Proton's number.
- `HumanVerification::token_from_message`, which takes the solved token out of
  a message the verification page posts, and ignores the page's other
  messages.
- `proton_drive_rs::parse_public_link_url` is public, so apps can check a
  pasted share link, or key their records by its token, without opening it.

### Changed

- `parse_public_link_url` ignores surrounding whitespace and a query string
  before the fragment (`…/urls/TOKEN?ref=x#password`).
- `ResumeParameters`' `Debug` output leaves the access and refresh tokens out.

## [0.12.1] — 2026-11-17

### Fixed

- **Uploads from a device whose clock runs ahead of Proton's.** A new node key
  and its self-signatures were dated with the device clock. Proton's servers
  ignore self-signatures dated after their own clock, so a phone only a few
  seconds fast created keys without a usable encryption subkey, and every new
  file or photo failed with 422 "Could not verify the nodeKey was used for
  encrypting contentKeyPacket" (code 200501). New keys and their
  self-signatures are now dated with the server's time, taken from the `Date`
  header of its latest response, as the C# SDK's
  `CryptographyTimeProvisionHandler` does. Before the first response the
  device clock is used.

### Added

- `proton_sdk::crypto::note_server_date`, which records a server `Date`
  header. `ApiHttpClient` calls it for every response; only a client that
  talks to the API through its own HTTP stack needs it.

## [0.12.0] — 2026-11-15

### Fixed

- **Photo duplicate checks no longer fail on drafts.** The duplicates endpoint
  sends `Hash` and `ContentHash` as `null` for a draft left by an interrupted
  upload. Both fields were `String`, so one such draft failed the whole
  `find_duplicates`, `find_duplicates_many` or `name_collisions` call with
  "invalid type: null, expected a string". Drafts, trashed and deleted links
  and candidates without hashes are now skipped, like the TypeScript SDK does.
- **`null` for a defaulted field.** `#[serde(default)]` only covers a missing
  field. The DTO fields with a default (lists, strings, numbers, flags) now
  also read an explicit `null` as that default.
- **Failed uploads remove their draft.** A new file or photo whose block upload
  failed left its draft on the server, and the draft then blocked the next
  attempt at that name. The draft is now deleted, as in the C# and TypeScript
  SDKs. After a failed seal it is only deleted when the server clearly
  rejected the seal, because a seal lost in transit may have been applied.
- A response that cannot be decoded is logged with its API path.

### Added

- `PhotoUploadMetadata::replace_existing_draft`: replace an unsealed draft of
  the same name from any client, not only this session (C#
  `overrideExistingDraftByOtherClient`). A resumed import needs it after a
  fresh login, because the server compares drafts against the session id.
- `PhotoUploadMetadata::location`: write the photo's position to the encrypted
  extended attributes (`Location { Latitude, Longitude }`), as the web client
  does. Build it with `PhotoLocation::from_claimed`.
- `FoundPhotoDuplicateDto::active_name_hash` and `known_content_hash`.

### Breaking

- `PhotoUploadMetadata` has two new fields. Struct literals must set them or
  use `..Default::default()`.
- `FoundPhotoDuplicateDto::name_hash` and `content_hash` are `Option<String>`.
- `ExtendedAttributes` has a new `location` field.

## [0.11.0] — 2026-11-05

### Changed

- **Modification timestamps retain their UTC offset and fractional seconds.**
  Folder creation, streaming file uploads (including draft replacement), and
  revision uploads accept `ModificationTime`, an alias for
  `chrono::DateTime<chrono::FixedOffset>`. Ported from upstream `271f64e4`.
  Downloaded claimed timestamps remain verbatim strings.

### Added

- `PhotoUploadMetadata::last_modification_time`, independent of `capture_time`.
  An unset modification time is omitted; capture time still defaults to the
  upload time.

### Breaking

- Modification-time parameters change from `Option<i64>` to
  `Option<ModificationTime>`. `None` needs no change. For an offset timestamp:

  ```rust
  use proton_drive_rs::ModificationTime;
  let modified: ModificationTime = "2026-11-05T09:55:00.1234567+08:00".parse()?;
  // Pass Some(modified) to create_folder or a streaming upload.
  ```

  For epoch seconds, add `chrono = "0.4"` to the caller's dependencies and use
  `chrono::DateTime::from_timestamp(seconds, 0).map(|time| time.fixed_offset())`.
  This yields a UTC offset and returns `None` for an out-of-range timestamp.
- `PhotoUploadMetadata` struct literals must provide `last_modification_time`
  or use `..Default::default()`. Photo uploads no longer copy capture time into
  modification time; set both fields explicitly when that is intended.

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

/// An uploader-supplied modification time, including its UTC offset and
/// fractional seconds. Downloaded claimed timestamps remain verbatim strings.
///
/// ```
/// use proton_drive_rs::ModificationTime;
///
/// let time: ModificationTime = "2026-11-05T09:55:00.1234567+08:00".parse()?;
/// assert_eq!(time.offset().local_minus_utc(), 8 * 3600);
/// # Ok::<(), chrono::ParseError>(())
/// ```
///
/// To migrate an epoch-second input, use
/// `chrono::DateTime::from_timestamp(seconds, 0).map(|time| time.fixed_offset())`.
///
/// ```
/// use proton_drive_rs::ModificationTime;
///
/// let modified: Option<ModificationTime> =
///     chrono::DateTime::from_timestamp(-1, 0).map(|time| time.fixed_offset());
/// assert_eq!(modified.unwrap().to_rfc3339(), "1969-12-31T23:59:59+00:00");
/// ```
pub type ModificationTime = chrono::DateTime<chrono::FixedOffset>;

pub(crate) fn format_modification_time(time: ModificationTime) -> String {
    time.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::decrypt_extended_attributes_unverified;
    use crate::dtos::{CommonExtendedAttributes, ExtendedAttributes};
    use proton_sdk::crypto::generate_node_key;

    #[test]
    fn modification_timestamps_survive_encrypted_attributes() {
        let node = generate_node_key().unwrap();
        for input in [
            "2026-11-05T09:55:00.1234567+08:00",
            "2026-11-05T09:55:00.123456789-05:30",
            "2026-11-05T09:55:00Z",
            "1970-01-01T00:00:00Z",
            "2024-02-29T12:00:00Z",
            "1969-12-31T23:59:59.001Z",
        ] {
            let time: ModificationTime = input.parse().unwrap();
            let serialized = format_modification_time(time);
            // RFC 3339 may pad fractions, but must preserve their precision
            // and the original offset, not only the instant.
            let reparsed: ModificationTime = serialized.parse().unwrap();
            assert_eq!(reparsed, time);
            assert_eq!(reparsed.offset(), time.offset());
            let attrs = ExtendedAttributes {
                common: CommonExtendedAttributes {
                    size: None,
                    modification_time: Some(serialized.clone()),
                    block_sizes: None,
                    digests: None,
                },
            };
            let json = serde_json::to_vec(&attrs).unwrap();
            let encrypted = node
                .key
                .encrypt_and_sign(&node.key, &json, false, true)
                .unwrap();
            let decoded = decrypt_extended_attributes_unverified(&node.key, &encrypted).unwrap();
            assert_eq!(decoded.common.unwrap().modification_time, Some(serialized));
        }
    }

    #[test]
    fn absent_modification_time_is_omitted() {
        let attrs = ExtendedAttributes {
            common: CommonExtendedAttributes {
                size: None,
                modification_time: None,
                block_sizes: None,
                digests: None,
            },
        };
        assert_eq!(
            serde_json::to_value(attrs).unwrap(),
            serde_json::json!({"Common": {}})
        );
    }
}

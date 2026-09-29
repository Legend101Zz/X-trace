//! Generated XTP transport and XTF storage bindings.
//!
//! The Rust types in [`xtp::agent`] are produced by `prost-build`
//! from the `.proto` files under `schema/proto/xtp-agent/v1/`. They
//! live behind a thin façade so the rest of the crate can add manual
//! helpers (envelope encode/decode, version negotiation, translation
//! into domain DTOs) without polluting the generated code. XTF bindings are
//! kept in a separate module because they describe persisted segment bytes,
//! not messages accepted on the XTP transport.
//!
//! The domain never imports these generated types. Translation modules
//! validate wire input and construct domain values.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "library code must not panic")
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on fallible fixture data"
    )
)]

pub mod envelope;
pub mod handshake;
pub mod translate;

pub use xtp as generated;

/// Re-export of the generated `xtp` module. `prost-build` emits the
/// whole module under the directory passed to `out_dir`, named after
/// the `.proto` `package` declaration. `xtp-agent` becomes the Rust
/// module path `xtp`.
#[allow(clippy::module_inception, reason = "generated module name mirrors the .proto package")]
pub mod xtp {
    #[allow(
        missing_docs,
        reason = "prost-build emits these symbols without rustdoc; the .proto comments stay authoritative"
    )]
    pub mod agent {
        /// Generated bindings grouped by the protobuf package version.
        #[allow(
            missing_docs,
            reason = "prost-build emits these symbols without rustdoc; the .proto comments stay authoritative"
        )]
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/generated/xtp.agent.v1.rs"));
        }

        pub use v1::*;
    }
}

/// Generated XTF v1 storage-schema bindings.
///
/// XTF uses these map-free protobuf messages inside its physical segment
/// framing. This module is intentionally separate from [`xtp`] so callers
/// cannot mistake persisted object bytes for XTP wire messages.
#[allow(
    missing_docs,
    reason = "prost-build emits these symbols without rustdoc; the .proto comments stay authoritative"
)]
pub mod xtf {
    /// Generated bindings grouped by the XTF protobuf package version.
    #[allow(
        missing_docs,
        reason = "prost-build emits these symbols without rustdoc; the .proto comments stay authoritative"
    )]
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/generated/xtf.v1.rs"));
    }

    pub use v1::*;
}

#[cfg(test)]
mod xtf_schema_tests {
    use prost::{Message as _, bytes::Bytes};

    use super::{generated, xtf};

    const TYPE_UINT64: i32 = 4;
    const TYPE_MESSAGE: i32 = 11;
    const TYPE_BYTES: i32 = 12;
    const TYPE_UINT32: i32 = 13;

    #[derive(Clone, PartialEq, prost::Message)]
    struct FileDescriptorSet {
        #[prost(message, repeated, tag = "1")]
        file: Vec<FileDescriptorProto>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct FileDescriptorProto {
        #[prost(string, optional, tag = "1")]
        name: Option<String>,
        #[prost(string, optional, tag = "2")]
        package: Option<String>,
        #[prost(string, repeated, tag = "3")]
        dependency: Vec<String>,
        #[prost(message, repeated, tag = "4")]
        message_type: Vec<DescriptorProto>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct DescriptorProto {
        #[prost(string, optional, tag = "1")]
        name: Option<String>,
        #[prost(message, repeated, tag = "2")]
        field: Vec<FieldDescriptorProto>,
        #[prost(message, repeated, tag = "3")]
        nested_type: Vec<DescriptorProto>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    struct FieldDescriptorProto {
        #[prost(string, optional, tag = "1")]
        name: Option<String>,
        #[prost(int32, optional, tag = "3")]
        number: Option<i32>,
        #[prost(int32, optional, tag = "5")]
        field_type: Option<i32>,
        #[prost(string, optional, tag = "6")]
        type_name: Option<String>,
    }

    #[test]
    fn xtf_descriptor_declares_exact_map_free_storage_contract() {
        let descriptor = FileDescriptorSet::decode(
            &include_bytes!(concat!(env!("OUT_DIR"), "/generated/file_descriptor_set.bin"))[..],
        )
        .expect("decode generated descriptor set");
        let segment = descriptor
            .file
            .iter()
            .find(|file| file.name.as_deref() == Some("xtf/v1/segment.proto"))
            .expect("XTF segment descriptor");

        assert_eq!(segment.package.as_deref(), Some("xtf.v1"));
        assert!(
            segment
                .dependency
                .iter()
                .any(|dependency| dependency == "xtp-agent/v1/recording.proto")
        );
        assert_message_fields(
            segment,
            "XtfHeader",
            &[
                ("format_major", 1, TYPE_UINT32, None),
                ("format_minor", 2, TYPE_UINT32, None),
                ("project_id", 3, TYPE_BYTES, None),
                ("recording_id", 4, TYPE_BYTES, None),
                ("segment_ordinal", 5, TYPE_UINT32, None),
                ("first_recording_seq", 6, TYPE_UINT64, None),
                ("last_recording_seq", 7, TYPE_UINT64, None),
                ("event_count", 8, TYPE_UINT64, None),
            ],
        );
        assert_message_fields(
            segment,
            "XtfEventEnvelope",
            &[
                ("recording_seq", 1, TYPE_UINT64, None),
                ("event", 2, TYPE_MESSAGE, Some(".xtp.agent.v1.RecordingEvent")),
            ],
        );
    }

    #[test]
    fn xtf_generated_messages_encode_and_decode_deterministically() {
        let header = xtf::XtfHeader {
            format_major: 1,
            format_minor: 0,
            project_id: Bytes::from_static(&[0x11; 16]),
            recording_id: Bytes::from_static(&[0x22; 16]),
            segment_ordinal: 0,
            first_recording_seq: 2,
            last_recording_seq: 2,
            event_count: 1,
        };
        let header_bytes = header.encode_to_vec();
        assert_eq!(header_bytes, header.encode_to_vec());
        assert_eq!(
            xtf::XtfHeader::decode(header_bytes.as_slice()).expect("decode XTF header"),
            header
        );

        let envelope = xtf::XtfEventEnvelope {
            recording_seq: 2,
            event: Some(generated::agent::RecordingEvent {
                event_id: "event-2".to_owned(),
                recording_seq: 2,
                ..Default::default()
            }),
        };
        let envelope_bytes = envelope.encode_to_vec();
        assert_eq!(envelope_bytes, envelope.encode_to_vec());
        assert_eq!(
            xtf::XtfEventEnvelope::decode(envelope_bytes.as_slice())
                .expect("decode XTF event envelope"),
            envelope
        );
    }

    #[test]
    fn xtp_reexports_preserve_existing_generated_paths() {
        let original: generated::agent::RecordingEvent = Default::default();
        let versioned: super::xtp::agent::v1::RecordingEvent = original;
        let _preserved: super::xtp::agent::RecordingEvent = versioned;
    }

    fn assert_message_fields(
        file: &FileDescriptorProto,
        expected_name: &str,
        expected_fields: &[(&str, i32, i32, Option<&str>)],
    ) {
        let message = file
            .message_type
            .iter()
            .find(|message| message.name.as_deref() == Some(expected_name))
            .expect("expected XTF message");
        assert!(message.nested_type.is_empty(), "{expected_name} must remain map-free");
        assert_eq!(message.field.len(), expected_fields.len());
        for (name, number, field_type, type_name) in expected_fields {
            let field = message
                .field
                .iter()
                .find(|field| field.name.as_deref() == Some(*name))
                .expect("expected XTF field");
            assert_eq!(field.number, Some(*number));
            assert_eq!(field.field_type, Some(*field_type));
            assert_eq!(field.type_name.as_deref(), *type_name);
        }
    }
}

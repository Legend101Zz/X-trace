//! Stable endpoint identity and versioned fingerprint encoding.

use thiserror::Error;

use crate::{
    ProjectId,
    catalog::{HttpMethod, Transport},
    ids::Id,
};

/// Version of the deterministic CBOR endpoint fingerprint format.
pub const ENDPOINT_FINGERPRINT_FORMAT_VERSION: u32 = 1;

/// Framework-neutral endpoint tuple used for matching and deduplication.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EndpointIdentity {
    /// Project scope included in the canonical identity.
    pub project_id: ProjectId,
    /// Stable caller supplied application component.
    pub application_component: String,
    /// Stable caller supplied transport binding.
    pub binding_key: String,
    /// Transport protocol.
    pub transport: Transport,
    /// Canonical HTTP method.
    pub method: HttpMethod,
    /// Exact route template used for identity.
    pub route_template: String,
}

/// Opaque BLAKE3-256 endpoint matching key. This is not a public entity ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EndpointFingerprint([u8; 32]);

impl EndpointFingerprint {
    /// Returns the fixed-width digest bytes for storage uniqueness checks.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Failure to encode the canonical endpoint fingerprint input.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("endpoint fingerprint encoding failed")]
pub struct EndpointFingerprintEncodingError;

impl EndpointIdentity {
    /// Encodes the versioned eight-element deterministic CBOR identity tuple.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EndpointFingerprintEncodingError> {
        let mut bytes = Vec::with_capacity(256);
        let mut encoder = minicbor::Encoder::new(&mut bytes);
        encoder
            .array(8)
            .map_err(|_| EndpointFingerprintEncodingError)?
            .str("xtrace.endpoint-fingerprint")
            .map_err(|_| EndpointFingerprintEncodingError)?
            .u32(ENDPOINT_FINGERPRINT_FORMAT_VERSION)
            .map_err(|_| EndpointFingerprintEncodingError)?
            .bytes(self.project_id.as_uuid().as_bytes())
            .map_err(|_| EndpointFingerprintEncodingError)?
            .str(&self.application_component)
            .map_err(|_| EndpointFingerprintEncodingError)?
            .str(self.transport.as_str())
            .map_err(|_| EndpointFingerprintEncodingError)?
            .str(&self.binding_key)
            .map_err(|_| EndpointFingerprintEncodingError)?
            .str(self.method.as_str())
            .map_err(|_| EndpointFingerprintEncodingError)?
            .str(&self.route_template)
            .map_err(|_| EndpointFingerprintEncodingError)?;
        Ok(bytes)
    }

    /// Computes the deterministic BLAKE3-256 matching key.
    pub fn fingerprint(&self) -> Result<EndpointFingerprint, EndpointFingerprintEncodingError> {
        let bytes = self.canonical_bytes()?;
        Ok(EndpointFingerprint(*blake3::hash(&bytes).as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn fixture() -> EndpointIdentity {
        EndpointIdentity {
            project_id: ProjectId::from_uuid(
                Uuid::parse_str("018f0000-0000-7000-8000-000000000001").expect("fixed UUID"),
            ),
            application_component: "spring-fixture".to_owned(),
            binding_key: "default".to_owned(),
            transport: Transport::Http,
            method: HttpMethod::Post,
            route_template: "/orders".to_owned(),
        }
    }

    #[test]
    fn canonical_fixture_bytes_and_digest_are_versioned() {
        let identity = fixture();
        let bytes = identity.canonical_bytes().expect("canonical encoding");
        assert_eq!(
            hex::encode(bytes),
            "88781b7874726163652e656e64706f696e742d66696e6765727072696e740150018f00000000700080000000000000016e737072696e672d6669787475726564687474706764656661756c7464504f5354672f6f7264657273"
        );
        assert_eq!(
            hex::encode(identity.fingerprint().expect("digest").as_bytes()),
            "4b28f54d5c1585544de1d5e258e3a173a7dfe61779fae84b2956470ea66db80c"
        );
        assert_eq!(
            identity.fingerprint().expect("digest"),
            identity.fingerprint().expect("repeat")
        );
    }

    #[test]
    fn every_identity_field_changes_the_fingerprint() {
        let original = fixture();
        let baseline = original.fingerprint().expect("baseline");
        let mut changed = original.clone();
        changed.project_id = ProjectId::from_uuid(
            Uuid::parse_str("018f0000-0000-7000-8000-000000000002").expect("fixed UUID"),
        );
        assert_ne!(baseline, changed.fingerprint().expect("project"));
        changed = original.clone();
        changed.application_component.push_str("-other");
        assert_ne!(baseline, changed.fingerprint().expect("component"));
        changed = original.clone();
        changed.binding_key.push_str("-other");
        assert_ne!(baseline, changed.fingerprint().expect("binding"));
        changed = original.clone();
        changed.method = HttpMethod::Get;
        assert_ne!(baseline, changed.fingerprint().expect("method"));
        changed = original;
        changed.route_template.push_str("/other");
        assert_ne!(baseline, changed.fingerprint().expect("route"));
        let vectors = [
            {
                let mut value = fixture();
                value.project_id = ProjectId::from_uuid(
                    Uuid::parse_str("018f0000-0000-7000-8000-000000000002").expect("fixed UUID"),
                );
                value
            },
            {
                let mut value = fixture();
                value.application_component.push_str("-other");
                value
            },
            {
                let mut value = fixture();
                value.binding_key.push_str("-other");
                value
            },
            {
                let mut value = fixture();
                value.method = HttpMethod::Get;
                value
            },
            {
                let mut value = fixture();
                value.route_template.push_str("/other");
                value
            },
        ];
        let expected = [
            (
                "88781b7874726163652e656e64706f696e742d66696e6765727072696e740150018f00000000700080000000000000026e737072696e672d6669787475726564687474706764656661756c7464504f5354672f6f7264657273",
                "07c9b49c49989c8733a5dc5836df30901bd3fd234597169fee07d54ea2134180",
            ),
            (
                "88781b7874726163652e656e64706f696e742d66696e6765727072696e740150018f000000007000800000000000000174737072696e672d666978747572652d6f7468657264687474706764656661756c7464504f5354672f6f7264657273",
                "77f156fce6a188146e8a64c336b622f10ade19baa8ef83913ab3139cf36afefa",
            ),
            (
                "88781b7874726163652e656e64706f696e742d66696e6765727072696e740150018f00000000700080000000000000016e737072696e672d6669787475726564687474706d64656661756c742d6f7468657264504f5354672f6f7264657273",
                "758036cedecc9e4d58595f95cac999cc7a80c32cae5e0414a348d45aa22386e6",
            ),
            (
                "88781b7874726163652e656e64706f696e742d66696e6765727072696e740150018f00000000700080000000000000016e737072696e672d6669787475726564687474706764656661756c7463474554672f6f7264657273",
                "ce6a72eede3e7c4b4c1f5398c069562a40a5ff5bbab766233b130529d20eac1b",
            ),
            (
                "88781b7874726163652e656e64706f696e742d66696e6765727072696e740150018f00000000700080000000000000016e737072696e672d6669787475726564687474706764656661756c7464504f53546d2f6f72646572732f6f74686572",
                "ce6855e8968e9775539b7f91fb6e82f16a17042318b1e986d3187177455d7ded",
            ),
        ];
        for (value, (bytes, digest)) in vectors.into_iter().zip(expected) {
            assert_eq!(hex::encode(value.canonical_bytes().expect("bytes")), bytes);
            assert_eq!(hex::encode(value.fingerprint().expect("hash").as_bytes()), digest);
        }
    }
}

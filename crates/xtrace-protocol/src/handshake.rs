//! AdapterHello/DaemonHello transcript proof.
//!
//! The handshake defined in `docs/plans/x-trace/03b-protocol-and-api.md`
//! §2.4 authenticates an adapter through the following transcript
//! proof:
//!
//! ```text
//! adapter_hmac = HMAC-SHA256(
//!     key   = session_secret,
//!     input = "xtrace-handshake-v1"
//!           || len(tls_exporter)          || tls_exporter
//!           || len(runtime_session_id)    || runtime_session_id
//!           || len(client_nonce)          || client_nonce
//!           || len(server_nonce)          || server_nonce
//!           || len(manifest_digest)       || manifest_digest
//! )
//! ```
//!
//! The TLS exporter is obtained through `rustls`'s
//! `export_keying_material` method on the server-side connection (the
//! `rustls` crate does not expose an `Exporter` trait; the method lives
//! on the connection type). The runtime session identifier, manifest
//! digest, and the negotiated nonces are the only inputs the
//! transcript binds; project identity is represented by the bootstrap
//! `project_id` together with `AdapterHello.repository_fingerprint` and
//! validated separately against the canonical
//! `xtrace_domain::RepositoryFingerprint` negotiated out of band.
//!
//! The transcript is fixed-length encoded per chunk: every variable
//! field is preceded by its byte length as a 32-bit big-endian
//! integer. Two sides that know the same byte sequence compute the
//! same HMAC; flipping any byte yields a different tag.
//!
//! When a peer has not yet established one of the nonces, the missing
//! nonce is fixed to a 32-byte zero placeholder. This only happens on
//! the inbound `AdapterHello`: the adapter does not yet know the
//! daemon's server nonce. The outbound `DaemonHello` uses the actual
//! client nonce recovered from the validated `AdapterHello` and the
//! daemon's own freshly generated server nonce. The placeholder is
//! therefore a documented inbound-only artefact and never appears in
//! the bytes the daemon emits.
//!
//! The module intentionally exposes only the bytes-building and HMAC
//! primitives. The certificate pinning, version negotiation, and
//! session sequencing live in [`crate::envelope`] and
//! [`crate::generated::agent`] so the cryptographic proof stays
//! confined to this single reviewed module.
//!
//! ## HMAC key size
//!
//! HMAC-SHA256 accepts keys of any length; SHA-256's block size is a
//! documented implementation threshold for performance but not a
//! validity constraint. The 256-bit per-runtime-session secret used in
//! production is well within bounds and the API has no key-length error
//! path on success.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Canonical transcript proof for the AdapterHello/DaemonHello HMAC.
///
/// The encoding concatenates the labels in the order documented in
/// `03b-protocol-and-api.md` §2.4 so the verifier and the prover must
/// hash the same byte sequence.
const TRANSCRIPT_LABEL: &[u8] = b"xtrace-handshake-v1";

/// Placeholder nonce used by the inbound `AdapterHello` for the
/// server nonce the adapter has not yet seen. The 32-byte length
/// matches the documented nonce size so the byte layout stays
/// consistent across both directions.
pub const ZERO_NONCE: [u8; 32] = [0u8; 32];

/// Hashes the supplied transcript into a 32-byte HMAC-SHA256 tag.
///
/// The function never refuses the supplied key: HMAC-SHA256 accepts
/// any byte slice and only hashes a pre-padded copy internally. The
/// returned [`Result`] exists so future SHA-3 variants, which may
/// restrict the key length, can be slotted into the same signature
/// without breaking callers; today the `Ok` arm is the only outcome
/// the production caller observes.
pub fn compute_transcript_proof(
    session_secret: &[u8],
    tls_exporter: &[u8],
    runtime_session_id: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
    manifest_digest: &[u8],
) -> Result<[u8; 32], TranscriptProofError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(session_secret).map_err(|_| TranscriptProofError::Mac)?;
    mac.update(TRANSCRIPT_LABEL);
    mac.update(&(tls_exporter.len() as u32).to_be_bytes());
    mac.update(tls_exporter);
    mac.update(&(runtime_session_id.len() as u32).to_be_bytes());
    mac.update(runtime_session_id);
    mac.update(&(client_nonce.len() as u32).to_be_bytes());
    mac.update(client_nonce);
    mac.update(&(server_nonce.len() as u32).to_be_bytes());
    mac.update(server_nonce);
    mac.update(&(manifest_digest.len() as u32).to_be_bytes());
    mac.update(manifest_digest);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Verifies a transcript proof against an expected tag in constant
/// time.
///
/// # Errors
///
/// Returns [`TranscriptProofError::Mismatch`] when the supplied tag
/// does not match the recomputed HMAC. No detail is leaked because the
/// mismatch is the only signal a caller should ever need;
/// the inner algorithm state is internal.
#[allow(
    clippy::too_many_arguments,
    reason = "every field is a wire-shaped transcript input documented in `03b-protocol-and-api.md` §2.4"
)]
pub fn verify_transcript_proof(
    session_secret: &[u8],
    tls_exporter: &[u8],
    runtime_session_id: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
    manifest_digest: &[u8],
    expected: &[u8],
) -> Result<(), TranscriptProofError> {
    let computed = compute_transcript_proof(
        session_secret,
        tls_exporter,
        runtime_session_id,
        client_nonce,
        server_nonce,
        manifest_digest,
    )?;
    if expected.len() != computed.len() {
        return Err(TranscriptProofError::Mismatch);
    }
    // `constant_time_eq` performs a fixed-time comparison so the
    // timing of an HMAC verification cannot be used to recover the
    // session secret.
    if constant_time_eq::constant_time_eq(&computed, expected) {
        Ok(())
    } else {
        Err(TranscriptProofError::Mismatch)
    }
}

/// Errors raised when verifying a transcript proof.
#[derive(Debug, thiserror::Error)]
pub enum TranscriptProofError {
    /// The supplied tag does not match the recomputed HMAC. The error
    /// intentionally carries no detail so an attacker cannot probe
    /// specific verification steps through error variants.
    #[error("transcript proof mismatch")]
    Mismatch,
    /// The HMAC primitive refused the supplied key. HMAC-SHA256
    /// accepts any key length; the variant exists so the public API
    /// stays total when SHA-3 or another future hash is wired in.
    #[error("hmac primitive refused the supplied key")]
    Mac,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(
        secret: &[u8],
        exporter: &[u8],
        session: &[u8],
        client: &[u8],
        server: &[u8],
        manifest: &[u8],
    ) -> [u8; 32] {
        compute_transcript_proof(secret, exporter, session, client, server, manifest)
            .expect("HMAC accepts the test secret")
    }

    #[test]
    fn proof_is_deterministic_and_field_sensitive() {
        let secret = b"a]8=ZxW6Mf7n3Q!2";
        let exporter = b"tls-exporter-bytes";
        let session = b"01900000-0000-0000-0000-000000000000";
        let client = [0xaa_u8; 32];
        let server = [0xbb_u8; 32];
        let manifest = b"b3:0000000000000000000000000000000000000000000000000000000000000000";

        let first = proof(secret, exporter, session, &client, &server, manifest);
        let second = proof(secret, exporter, session, &client, &server, manifest);
        assert_eq!(first, second);

        // Flipping any field must change the proof so a verifier
        // catches every kind of transcript tampering.
        let wrong_secret = proof(b"other-secret", exporter, session, &client, &server, manifest);
        assert_ne!(wrong_secret, first);

        let wrong_exporter = proof(secret, b"different", session, &client, &server, manifest);
        assert_ne!(wrong_exporter, first);

        let wrong_session = proof(
            secret,
            exporter,
            b"01999999-0000-0000-0000-000000000000",
            &client,
            &server,
            manifest,
        );
        assert_ne!(wrong_session, first);

        let wrong_client = proof(secret, exporter, session, &[0xcc; 32], &server, manifest);
        assert_ne!(wrong_client, first);

        let wrong_server = proof(secret, exporter, session, &client, &[0xdd; 32], manifest);
        assert_ne!(wrong_server, first);

        let wrong_manifest = proof(
            secret,
            exporter,
            session,
            &client,
            &server,
            b"b3:1111111111111111111111111111111111111111111111111111111111111111",
        );
        assert_ne!(wrong_manifest, first);
    }

    #[test]
    fn verify_accepts_matching_tag_and_rejects_every_other_field() {
        let secret = b"a]8=ZxW6Mf7n3Q!2";
        let exporter = b"tls-exporter-bytes";
        let session = b"01900000-0000-0000-0000-000000000000";
        let client = [0xaa_u8; 32];
        let server = [0xbb_u8; 32];
        let manifest = b"b3:0000000000000000000000000000000000000000000000000000000000000000";
        let proof_value = proof(secret, exporter, session, &client, &server, manifest);
        verify_transcript_proof(
            secret,
            exporter,
            session,
            &client,
            &server,
            manifest,
            &proof_value,
        )
        .expect("matching proof verifies");

        // Wrong length is rejected without panicking.
        let err = verify_transcript_proof(
            secret,
            exporter,
            session,
            &client,
            &server,
            manifest,
            &proof_value[..31],
        );
        assert!(matches!(err, Err(TranscriptProofError::Mismatch)));

        // Tampered byte is rejected with `Mismatch`.
        let mut tampered = proof_value;
        tampered[0] ^= 0x01;
        let err = verify_transcript_proof(
            secret, exporter, session, &client, &server, manifest, &tampered,
        );
        assert!(matches!(err, Err(TranscriptProofError::Mismatch)));
    }

    #[test]
    fn proof_accepts_keys_longer_than_sha256_block_size() {
        // SHA-256's internal block size is 64 bytes; HMAC pre-hashes
        // longer keys but never refuses them. This guards against a
        // future regression that would start rejecting over-length
        // keys and breaking the transcript.
        let long_key = vec![0x5a; 96];
        let tag = proof(&long_key, b"exporter", b"session", &[0xaa; 32], &[0xbb; 32], b"manifest");
        assert_eq!(tag.len(), 32);
    }
}

//! AdapterHello/DaemonHello transcript proof.
//!
//! The handshake defined in `docs/plans/x-trace/03b-protocol-and-api.md`
//! §2.4 authenticates an adapter through the following transcript
//! proof:
//!
//! ```text
//! adapter_hmac = HMAC-SHA256(
//!     key   = session_secret,
//!     input = tls_exporter
//!           || runtime_session_id
//!           || client_nonce
//!           || server_nonce
//!           || manifest_digest
//! )
//! ```
//!
//! The TLS exporter is obtained through the
//! `rustls::Exporter` trait; the runtime session identifier and
//! manifest digest are negotiated via the bootstrap artifact; the
//! nonces are random per-connection. Both sides compute the same HMAC
//! over the canonical byte layout and prove possession of the session
//! secret without sending it on the wire.
//!
//! The module intentionally exposes only the bytes-building and HMAC
//! primitives. The certificate pinning, version negotiation, and
//! session sequencing live in [`crate::envelope`] and
//! [`crate::generated::agent`] so the cryptographic proof stays
//! confined to this single reviewed module.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Canonical transcript proof for the AdapterHello/DaemonHello HMAC.
///
/// The encoding concatenates the labels in the order documented in
/// `03b-protocol-and-api.md` §2.4 so the verifier and the prover must
/// hash the same byte sequence.
const TRANSCRIPT_LABEL: &[u8] = b"xtrace-handshake-v1";

/// Hashes the supplied transcript into a 32-byte HMAC-SHA256 tag.
///
/// # Errors
///
/// Returns [`TranscriptProofError::Mac`] when the HMAC key is too
/// long for the underlying hash function. SHA-256 accepts any key
/// up to its block size (64 bytes); the daemon's 256-bit session
/// secret is always within bounds so this branch is unreachable
/// in production and exists only to keep the public API total.
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
/// mismatch is the only signal a caller should ever need; the inner
/// algorithm state is internal.
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
    /// The HMAC key was rejected by the underlying primitive. This
    /// branch is unreachable for the documented 256-bit session
    /// secret and exists only to keep the API total.
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
        let client = [0xaa_u8; 16];
        let server = [0xbb_u8; 16];
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

        let wrong_client = proof(secret, exporter, session, &[0xcc; 16], &server, manifest);
        assert_ne!(wrong_client, first);

        let wrong_server = proof(secret, exporter, session, &client, &[0xdd; 16], manifest);
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
        let client = [0xaa_u8; 16];
        let server = [0xbb_u8; 16];
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
}

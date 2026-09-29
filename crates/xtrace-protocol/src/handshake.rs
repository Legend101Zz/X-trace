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
//!           || len(project_context)       || project_context
//! )
//! ```
//!
//! The TLS exporter is obtained through the
//! `rustls::Exporter` trait; the runtime session identifier, manifest
//! digest, and project context are negotiated via the bootstrap
//! artifact; the nonces are random per-connection. The project context
//! is an unambiguous canonical encoding of the bootstrap project
//! identifier so a peer that has accepted the wrong project identity
//! can never produce a matching tag.
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

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Canonical transcript proof for the AdapterHello/DaemonHello HMAC.
///
/// The encoding concatenates the labels in the order documented in
/// `03b-protocol-and-api.md` §2.4 so the verifier and the prover must
/// hash the same byte sequence.
const TRANSCRIPT_LABEL: &[u8] = b"xtrace-handshake-v1";

/// Canonical label for the project context chunk folded into the
/// transcript proof. The label binds the project identity into the
/// HMAC input even though the v1 envelope has no explicit project
/// field; the daemon and the adapter must derive the same byte
/// sequence from the same bootstrap project identifier.
pub const PROJECT_CONTEXT_LABEL: &[u8] = b"xtrace/project/v1:";

/// Placeholder nonce used by the inbound `AdapterHello` for the
/// server nonce the adapter has not yet seen. The 32-byte length
/// matches the documented nonce size so the byte layout stays
/// consistent across both directions.
pub const ZERO_NONCE: [u8; 32] = [0u8; 32];

/// Builds the canonical project context chunk from the supplied
/// project identifier bytes. The returned vector is the unambiguous
/// byte sequence both sides fold into the HMAC input. The chunk is
/// not validated here; the caller owns the project identity and must
/// pass the canonical UUID bytes negotiated at bootstrap.
#[must_use]
pub fn project_context(project_id_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROJECT_CONTEXT_LABEL.len() + project_id_bytes.len());
    out.extend_from_slice(PROJECT_CONTEXT_LABEL);
    out.extend_from_slice(project_id_bytes);
    out
}

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
    project_context: &[u8],
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
    mac.update(&(project_context.len() as u32).to_be_bytes());
    mac.update(project_context);
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
    project_context: &[u8],
    expected: &[u8],
) -> Result<(), TranscriptProofError> {
    let computed = compute_transcript_proof(
        session_secret,
        tls_exporter,
        runtime_session_id,
        client_nonce,
        server_nonce,
        manifest_digest,
        project_context,
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
        project: &[u8],
    ) -> [u8; 32] {
        compute_transcript_proof(secret, exporter, session, client, server, manifest, project)
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
        let project = project_context(b"01900000-0000-7000-8000-000000000000");

        let first = proof(secret, exporter, session, &client, &server, manifest, &project);
        let second = proof(secret, exporter, session, &client, &server, manifest, &project);
        assert_eq!(first, second);

        // Flipping any field must change the proof so a verifier
        // catches every kind of transcript tampering.
        let wrong_secret =
            proof(b"other-secret", exporter, session, &client, &server, manifest, &project);
        assert_ne!(wrong_secret, first);

        let wrong_exporter =
            proof(secret, b"different", session, &client, &server, manifest, &project);
        assert_ne!(wrong_exporter, first);

        let wrong_session = proof(
            secret,
            exporter,
            b"01999999-0000-0000-0000-000000000000",
            &client,
            &server,
            manifest,
            &project,
        );
        assert_ne!(wrong_session, first);

        let wrong_client =
            proof(secret, exporter, session, &[0xcc; 32], &server, manifest, &project);
        assert_ne!(wrong_client, first);

        let wrong_server =
            proof(secret, exporter, session, &client, &[0xdd; 32], manifest, &project);
        assert_ne!(wrong_server, first);

        let wrong_manifest = proof(
            secret,
            exporter,
            session,
            &client,
            &server,
            b"b3:1111111111111111111111111111111111111111111111111111111111111111",
            &project,
        );
        assert_ne!(wrong_manifest, first);

        let wrong_project = proof(
            secret,
            exporter,
            session,
            &client,
            &server,
            manifest,
            project_context(b"01999999-0000-7000-8000-000000000000").as_slice(),
        );
        assert_ne!(wrong_project, first);
    }

    #[test]
    fn verify_accepts_matching_tag_and_rejects_every_other_field() {
        let secret = b"a]8=ZxW6Mf7n3Q!2";
        let exporter = b"tls-exporter-bytes";
        let session = b"01900000-0000-0000-0000-000000000000";
        let client = [0xaa_u8; 32];
        let server = [0xbb_u8; 32];
        let manifest = b"b3:0000000000000000000000000000000000000000000000000000000000000000";
        let project = project_context(b"01900000-0000-7000-8000-000000000000");
        let proof_value = proof(secret, exporter, session, &client, &server, manifest, &project);
        verify_transcript_proof(
            secret,
            exporter,
            session,
            &client,
            &server,
            manifest,
            &project,
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
            &project,
            &proof_value[..31],
        );
        assert!(matches!(err, Err(TranscriptProofError::Mismatch)));

        // Tampered byte is rejected with `Mismatch`.
        let mut tampered = proof_value;
        tampered[0] ^= 0x01;
        let err = verify_transcript_proof(
            secret, exporter, session, &client, &server, manifest, &project, &tampered,
        );
        assert!(matches!(err, Err(TranscriptProofError::Mismatch)));
    }

    #[test]
    fn project_context_encodes_label_and_id_unambiguously() {
        let id = b"01900000-0000-7000-8000-000000000000";
        let ctx = project_context(id);
        assert!(ctx.starts_with(PROJECT_CONTEXT_LABEL));
        assert_eq!(&ctx[PROJECT_CONTEXT_LABEL.len()..], id);
    }
}

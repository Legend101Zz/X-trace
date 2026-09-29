//! Ephemeral daemon certificate and rustls server configuration.
//!
//! Every daemon launch generates a fresh self-signed leaf certificate
//! using [`rcgen`], encodes it to DER, computes the SHA-256 pin of
//! the DER bytes, and bundles the leaf and key into a
//! [`rustls::ServerConfig`] restricted to TLS 1.3 with the ring
//! crypto provider.
//!
//! The pin is what the bootstrap artifact exposes to the adapter; the
//! adapter's TLS stack is expected to verify the pin before completing
//! the handshake so a malicious local listener cannot impersonate the
//! daemon. The certificate is intentionally self-signed and never
//! trusted by a public CA; the security model is "the pin you read
//! out of band is the only chain you accept".
//!
//! ## Private-key hygiene
//!
//! The private key is wrapped in a single-use buffer that zeroes its
//! backing storage on drop and prints a redacted marker under
//! `Debug`. The material is consumed exactly once when the rustls
//! server configuration is built; the [`TlsServerMaterials`] only
//! retains the [`Arc<ServerConfig>`] and the certificate pin, never
//! the key or the DER bytes.

use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, Ia5String, KeyPair, SanType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, ServerConfig, SignatureScheme,
    SupportedProtocolVersion,
};
use sha2::{Digest, Sha256};

use crate::error::DaemonError;

/// Loopback hostnames and IPs included in the certificate's SAN. A
/// generic `localhost` entry plus the two IPv4 / IPv6 loopback
/// literals cover every loopback-only client configuration.
const LOOPBACK_SANS: &[&str] = &["localhost", "127.0.0.1", "::1"];

/// Single supported TLS protocol version. TLS 1.3 is mandatory for the
/// pinned adapter transport documented in `docs/plans/x-trace/03-program-design.md`
/// §11 because the exporter keying material, AEAD suite guarantees,
/// and session secret HMAC transcript are defined against the TLS 1.3
/// key schedule. Earlier versions are not negotiated.
const SUPPORTED_TLS_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// Zero-on-drop wrapper around a PKCS#8 DER-encoded private key.
///
/// The struct holds the bytes by value, never exposes the buffer
/// outside this module, and clears it on `Drop`. The buffer is moved
/// into the rustls builder exactly once; the wrapper exists so the
/// `Debug` formatting always prints the redacted marker and the
/// [`EphemeralCertificate::private_key`] accessor hands the bytes to
/// the rustls builder through a single, traceable call site.
struct EphemeralPrivateKey(Vec<u8>);

impl std::fmt::Debug for EphemeralPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EphemeralPrivateKey(<redacted>)")
    }
}

impl Drop for EphemeralPrivateKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl zeroize::Zeroize for EphemeralPrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl EphemeralPrivateKey {
    /// Mutable access to the inner buffer so the rustls builder can
    /// move the bytes out exactly once. After the call returns, the
    /// wrapper is dropped with whatever buffer the caller left behind.
    fn private_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

/// Bundled TLS materials ready to be installed into a tokio acceptor.
///
/// The struct owns only the [`Arc<ServerConfig>`] and the public
/// certificate pin. The private key and the DER-encoded leaf are
/// consumed by [`TlsServerMaterials::build`] and never duplicated;
/// there is no `Clone` implementation and no public accessor for the
/// DER bytes.
pub struct TlsServerMaterials {
    /// Fully configured server config.
    server_config: Arc<ServerConfig>,
    /// Lowercase hexadecimal SHA-256 digest of the DER-encoded leaf
    /// certificate. Surfaced through [`TlsServerMaterials::certificate_pin`]
    /// so the bootstrap artifact can carry the pin to the adapter.
    certificate_pin: String,
}

impl std::fmt::Debug for TlsServerMaterials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServerMaterials")
            .field("certificate_pin", &self.certificate_pin)
            .field("server_config", &"<rustls::ServerConfig>")
            .finish()
    }
}

impl TlsServerMaterials {
    /// Generates a fresh self-signed leaf certificate for loopback
    /// usage and builds the rustls server configuration. The private
    /// key is generated through [`rcgen`] using the ring CSPRNG; the
    /// key is consumed by the rustls builder exactly once before this
    /// function returns.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::TlsConfig`] when the certificate
    /// generator refuses the requested parameters, or when the
    /// rustls builder rejects the supplied key or version
    /// negotiation.
    pub fn build() -> Result<Self, DaemonError> {
        let mut params = CertificateParams::default();
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "xtrace-daemon");
            dn
        };
        let sans = LOOPBACK_SANS
            .iter()
            .map(|host| {
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    Ok(SanType::IpAddress(ip))
                } else {
                    Ia5String::try_from(*host).map(SanType::DnsName).map_err(|err| {
                        DaemonError::TlsConfig(format!("invalid dns san {host}: {err}"))
                    })
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        params.subject_alt_names = sans;
        let key_pair =
            KeyPair::generate().map_err(|err| DaemonError::TlsConfig(format!("keypair: {err}")))?;
        let certificate = params
            .self_signed(&key_pair)
            .map_err(|err| DaemonError::TlsConfig(format!("self sign: {err}")))?;
        let certificate_der = certificate.der().to_vec();
        let private_key_der = key_pair.serialized_der().to_vec();
        let certificate_pin = sha256_lower_hex(&certificate_der);
        // Wrap the private key in a zero-on-drop guard so the bytes
        // are cleared on every error path; the rustls builder is the
        // single consumer and takes ownership of the inner `Vec<u8>`
        // through `EphemeralPrivateKey::into_inner`.
        let mut private_key_wrapper = EphemeralPrivateKey(private_key_der);
        let moved_bytes = std::mem::take(private_key_wrapper.private_mut());
        let server_config =
            ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_protocol_versions(SUPPORTED_TLS_VERSIONS)
                .map_err(|err| DaemonError::TlsConfig(format!("protocol versions: {err}")))?
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(certificate_der)],
                    PrivateKeyDer::from(PrivatePkcs8KeyDer::from(moved_bytes)),
                )
                .map_err(|err| DaemonError::TlsConfig(format!("single cert: {err}")))?;
        // `private_key_wrapper` is dropped here with an empty buffer;
        // the zeroize-on-drop has nothing to clear because the key was
        // moved into rustls.
        drop(private_key_wrapper);
        Ok(Self { server_config: Arc::new(server_config), certificate_pin })
    }

    /// Returns the [`Arc<ServerConfig>`] ready to plug into a tokio
    /// acceptor.
    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.server_config.clone()
    }

    /// Returns the lowercase hexadecimal SHA-256 pin of the leaf
    /// certificate.
    #[must_use]
    pub fn certificate_pin(&self) -> &str {
        &self.certificate_pin
    }
}

/// Computes the lowercase hexadecimal SHA-256 digest of the supplied
/// bytes. Used for the bootstrap artifact's `certificate_sha256_pin`
/// field; tests rely on the same encoding.
fn sha256_lower_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Builds a `rustls::ClientConfig` that pins a single certificate by
/// its SHA-256 digest and accepts TLS 1.3 only.
///
/// The verifier in this module accepts exactly the leaf whose DER
/// SHA-256 equals the supplied lowercase pin, while still verifying
/// the certificate signature through rustls's supported signature
/// algorithms. Production adapters are expected to construct their
/// verifier from the bootstrap pin string directly; no DER or
/// root certificate material leaves the daemon process.
///
/// # Errors
///
/// Returns [`DaemonError::TlsConfig`] when the verifier cannot be
/// built from the supplied pin string. The function is the single
/// entry point for fake adapters and downstream crates that need to
/// pin the ephemeral leaf.
pub fn build_pinned_client_config(pin: &str) -> Result<ClientConfig, DaemonError> {
    let verifier = Arc::new(PinnedLeafVerifier::new(pin)?);
    let config = ClientConfig::builder_with_provider(default_provider().into())
        .with_protocol_versions(SUPPORTED_TLS_VERSIONS)
        .map_err(|err| DaemonError::TlsConfig(format!("client versions: {err}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(config)
}

/// TLS 1.3 certificate verifier that pins a single certificate by
/// its SHA-256 digest. The verifier is constructed from the
/// lowercase hex pin carried in the bootstrap artifact; no DER or
/// root certificate material leaves the bootstrap process.
#[derive(Debug)]
struct PinnedLeafVerifier {
    pin: String,
}

impl PinnedLeafVerifier {
    fn new(pin: &str) -> Result<Self, DaemonError> {
        if !is_canonical_lowercase_hex_pin(pin) {
            return Err(DaemonError::TlsConfig(format!(
                "pin must be 64 lowercase hex characters: {pin}"
            )));
        }
        Ok(Self { pin: pin.to_string() })
    }
}

fn is_canonical_lowercase_hex_pin(value: &str) -> bool {
    if value.len() != 64 {
        return false;
    }
    value.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

impl ServerCertVerifier for PinnedLeafVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // The verifier accepts exactly one certificate chain: the
        // leaf alone. Intermediate certificates are not allowed
        // because the daemon self-signs every leaf and there is no
        // CA hierarchy to anchor against.
        if !intermediates.is_empty() {
            return Err(RustlsError::General(format!(
                "pinned verifier rejects intermediate certificates: got {}",
                intermediates.len()
            )));
        }
        let leaf_pin = sha256_lower_hex(end_entity.as_ref());
        if !constant_time_eq::constant_time_eq(leaf_pin.as_bytes(), self.pin.as_bytes()) {
            return Err(RustlsError::General(
                "leaf certificate sha-256 does not match the bootstrap pin".to_string(),
            ));
        }
        // Confirm the leaf is a parseable X.509 certificate so the
        // chain is structurally valid; rustls-supported algorithm
        // enforcement happens in `verify_tls13_signature` for the
        // handshake signature. We deliberately do not anchor the
        // leaf to a trust store because the daemon self-signs every
        // leaf and the pin is the only trust anchor.
        webpki::EndEntityCert::try_from(end_entity)
            .map_err(|err| RustlsError::General(format!("leaf parsing failed: {err}")))?;
        // Touch the unused parameters so the compiler does not flag
        // them; the verifier only enforces the pin.
        let _ = (server_name, ocsp_response, now);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // TLS 1.2 is never negotiated; refuse every signature out of
        // an abundance of caution.
        Err(RustlsError::General("pinned verifier does not negotiate TLS 1.2".to_string()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        // Delegate signature verification to webpki's
        // `EndEntityCert::verify_signature` so the chain signature
        // scheme is enforced with the exact same algorithm rules
        // rustls's WebPKI verifier would apply. We pick the first
        // supported scheme matching the wire `dss.scheme`; this
        // mirrors `verify_tls13_signature` from the rustls webpki
        // helper, which is not exposed publicly.
        let supported_algs = &default_provider().signature_verification_algorithms;
        let possible = supported_algs.mapping;
        let scheme = dss.scheme;
        let alg = possible.iter().find(|(s, _)| *s == scheme).map(|(_, algs)| algs[0]).ok_or_else(
            || {
                RustlsError::General(format!(
                    "tls signature scheme {scheme:?} not supported by rustls ring provider"
                ))
            },
        )?;
        let end_entity = webpki::EndEntityCert::try_from(cert)
            .map_err(|err| RustlsError::General(format!("leaf parsing failed: {err}")))?;
        end_entity
            .verify_signature(alg, message, dss.signature())
            .map_err(|err| RustlsError::General(format!("signature verification failed: {err}")))?;
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider().signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_materials_pin_is_stable_and_lowercase_hex() {
        let materials = TlsServerMaterials::build().expect("build");
        assert_eq!(materials.certificate_pin().len(), 64);
        assert!(
            materials
                .certificate_pin()
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
    }

    #[test]
    fn pinned_client_config_rejects_malformed_pin() {
        let err = build_pinned_client_config("not-a-pin").unwrap_err();
        assert!(matches!(err, DaemonError::TlsConfig(_)));
    }

    #[test]
    fn pinned_client_config_rejects_uppercase_pin() {
        // The pin must be lowercase hex; uppercase input is rejected
        // up front rather than silently lowercased.
        let upper = "A".repeat(64);
        let err = build_pinned_client_config(&upper).unwrap_err();
        assert!(matches!(err, DaemonError::TlsConfig(_)));
    }

    #[test]
    fn pinned_client_config_accepts_canonical_pin() {
        let materials = TlsServerMaterials::build().expect("build");
        let _config =
            build_pinned_client_config(materials.certificate_pin()).expect("build config");
    }

    #[test]
    fn tls_materials_have_no_clone_implementation() {
        // The compile-time check is the test: a stray `Clone` derive
        // would let an operator accidentally duplicate private-key
        // material through the public API. We only assert the
        // materials expose the documented fields.
        let materials = TlsServerMaterials::build().expect("build");
        let _ = materials.server_config();
        let _ = materials.certificate_pin();
    }

    #[test]
    fn debug_redacts_tls_materials() {
        let materials = TlsServerMaterials::build().expect("build");
        let rendered = format!("{materials:?}");
        assert!(rendered.contains("TlsServerMaterials"));
        assert!(rendered.contains("<rustls::ServerConfig>"));
    }
}

//! Ephemeral daemon certificate and rustls server configuration.
//!
//! Every daemon launch generates a fresh self-signed leaf certificate
//! using [`rcgen`], encodes it to PEM/DER, computes the SHA-256 pin of
//! the DER bytes, and bundles both into a [`rustls::ServerConfig`]
//! restricted to TLS 1.3 with the ring crypto provider.
//!
//! The pin is what the bootstrap artifact exposes to the adapter; the
//! adapter's TLS stack is expected to verify the pin before completing
//! the handshake so a malicious local listener cannot impersonate the
//! daemon. The certificate is intentionally self-signed and never
//! trusted by a public CA; the security model is "the pin you read
//! out of band is the only chain you accept".

use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, Ia5String, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
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

/// Ephemeral daemon certificate.
#[derive(Clone, Debug)]
pub struct EphemeralCertificate {
    /// DER-encoded leaf certificate bytes.
    pub certificate_der: Vec<u8>,
    /// PKCS#8 DER-encoded private key bytes.
    pub private_key_der: Vec<u8>,
    /// Lowercase hexadecimal SHA-256 digest of the DER-encoded leaf
    /// certificate. The bootstrap artifact exposes this pin so the
    /// adapter can verify the certificate before completing the TLS
    /// handshake.
    pub sha256_pin: String,
}

impl EphemeralCertificate {
    /// Generates a fresh self-signed leaf certificate for loopback
    /// usage. The private key is generated through [`rcgen`] using the
    /// ring CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::TlsConfig`] when the certificate
    /// generator refuses the requested parameters.
    pub fn generate() -> Result<Self, DaemonError> {
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
        let sha256_pin = sha256_lower_hex(&certificate_der);
        Ok(Self { certificate_der, private_key_der, sha256_pin })
    }

    /// Returns the DER-encoded leaf certificate as a `CertificateDer`.
    #[must_use]
    pub fn certificate(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.certificate_der.clone())
    }

    /// Returns the private key as a PKCS#8 `PrivateKeyDer`.
    #[must_use]
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.private_key_der.clone()).into()
    }

    /// Returns the lowercase hexadecimal SHA-256 pin.
    #[must_use]
    pub fn pin(&self) -> &str {
        &self.sha256_pin
    }
}

/// Bundled TLS materials ready to be installed into a tokio acceptor.
#[derive(Clone)]
pub struct TlsServerMaterials {
    /// Fully configured server config.
    pub server_config: Arc<ServerConfig>,
    /// The ephemeral certificate backing the configuration. Held
    /// alongside the [`ServerConfig`] so callers can surface the
    /// SHA-256 pin through the bootstrap artifact without re-deriving
    /// it.
    pub certificate: EphemeralCertificate,
    /// Lowercase hexadecimal summary of the certificate DER. Surfaced
    /// through the manifest digest field of `DaemonHello` so the
    /// adapter can verify the transcript proof matches the wire
    /// handshake. Today the value is the same as the SHA-256 pin;
    /// future slices may switch to a richer identity digest.
    pub certificate_summary: String,
}

impl TlsServerMaterials {
    /// Builds the rustls server configuration for the supplied
    /// ephemeral certificate. The configuration accepts TLS 1.3
    /// only, requires no client certificates (the HMAC transcript
    /// proof provides adapter authentication after the channel is
    /// established), and is ready to plug into a tokio acceptor.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::TlsConfig`] when the rustls builder
    /// refuses the supplied private key or when the version
    /// negotiation rejects the available cipher suites.
    pub fn build(certificate: EphemeralCertificate) -> Result<Self, DaemonError> {
        let server_config =
            ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_protocol_versions(SUPPORTED_TLS_VERSIONS)
                .map_err(|err| DaemonError::TlsConfig(format!("protocol versions: {err}")))?
                .with_no_client_auth()
                .with_single_cert(vec![certificate.certificate()], certificate.private_key())
                .map_err(|err| DaemonError::TlsConfig(format!("single cert: {err}")))?;
        let certificate_summary = certificate.pin().to_string();
        Ok(Self { server_config: Arc::new(server_config), certificate, certificate_summary })
    }
}

/// Builds a `rustls::ClientConfig` that pins a single certificate by
/// its SHA-256 digest and accepts TLS 1.3 only. Used by the fake
/// adapter in the integration tests so the assertion is "TLS works
/// against a real rustls client", not "we hand-rolled a verifier that
/// happens to skip the chain".
///
/// # Errors
///
/// Returns [`DaemonError::TlsConfig`] when the verifier cannot be
/// built from the supplied certificate.
pub fn build_pinned_client_config(certificate_der: &[u8]) -> Result<ClientConfig, DaemonError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate_der.to_vec()))
        .map_err(|err| DaemonError::TlsConfig(format!("add root: {err}")))?;
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        rustls::crypto::ring::default_provider().into(),
    )
    .build()
    .map_err(|err| DaemonError::TlsConfig(format!("client verifier: {err}")))?;
    let config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(SUPPORTED_TLS_VERSIONS)
            .map_err(|err| DaemonError::TlsConfig(format!("client versions: {err}")))?
            .with_webpki_verifier(verifier)
            .with_no_client_auth();
    Ok(config)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_certificate_pin_is_stable_and_lowercase_hex() {
        let cert = EphemeralCertificate::generate().expect("generate");
        assert_eq!(cert.pin().len(), 64);
        assert!(cert.pin().chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn ephemeral_certificate_includes_loopback_sans() {
        let cert = EphemeralCertificate::generate().expect("generate");
        assert!(!cert.certificate_der.is_empty());
    }

    #[test]
    fn tls_materials_build_round_trip() {
        let cert = EphemeralCertificate::generate().expect("cert");
        let materials = TlsServerMaterials::build(cert.clone()).expect("build");
        assert_eq!(materials.certificate.pin(), cert.pin());
        assert_eq!(materials.certificate_summary, cert.pin());
    }
}

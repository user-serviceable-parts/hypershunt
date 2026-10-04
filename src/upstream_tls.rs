// Upstream (client-side) TLS: one place that turns an
// `UpstreamTlsConfig` into a rustls `ClientConfig` plus the server
// name to present.  Shared by the h1/h2 proxy client, the h3 client,
// the active health prober and the L4 stream proxy so that "verify
// against this CA, under this name" means the same thing on every
// transport.

use crate::config::UpstreamTlsConfig;
use anyhow::Context;
use rustls::pki_types::ServerName;
use std::sync::Arc;

/// A built upstream TLS client: the rustls config and, when the
/// operator set `server-name`, the name to send as SNI and verify the
/// certificate against instead of the address the upstream is
/// reached at.
#[derive(Clone, Debug)]
pub struct UpstreamTls {
    pub config: Arc<rustls::ClientConfig>,
    pub server_name: Option<ServerName<'static>>,
}

impl UpstreamTls {
    /// Resolve the name to present, preferring the configured
    /// override and falling back to whatever the transport derived
    /// from the upstream address.
    pub fn server_name_or(
        &self,
        fallback: ServerName<'static>,
    ) -> ServerName<'static> {
        self.server_name.clone().unwrap_or(fallback)
    }
}

/// Build the upstream TLS client for `cfg`.  ALPN is deliberately
/// left unset: hyper-rustls fills it in from `enable_http1()` /
/// `enable_http2()` and panics on a pre-populated list, and the h3
/// client sets `h3` itself.
pub fn build_upstream_tls(
    cfg: &UpstreamTlsConfig,
) -> anyhow::Result<UpstreamTls> {
    let config = if cfg.skip_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                SkipServerVerification,
            ))
            .with_no_client_auth()
    } else {
        let roots = match &cfg.ca_file {
            Some(path) => load_ca_bundle(path)?,
            None => {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                roots
            }
        };
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    let server_name = cfg
        .server_name
        .as_deref()
        .map(|n| {
            ServerName::try_from(n)
                .map(|s| s.to_owned())
                .with_context(|| format!("tls server-name {n:?}"))
        })
        .transpose()?;
    Ok(UpstreamTls {
        config: Arc::new(config),
        server_name,
    })
}

/// Read a PEM bundle into a root store.  A bundle that yields no
/// usable anchors is refused: it would silently make every
/// handshake fail with an unhelpful "unknown issuer".
fn load_ca_bundle(path: &str) -> anyhow::Result<rustls::RootCertStore> {
    let pem = std::fs::read(path)
        .with_context(|| format!("reading tls ca-file {path:?}"))?;
    let certs = rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing tls ca-file {path:?}"))?;
    let mut roots = rustls::RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        anyhow::bail!("tls ca-file {path:?} contains no CA certificates");
    }
    Ok(roots)
}

/// Rustls verifier that accepts any server certificate.  Used by the
/// `tls skip-verify=#true` opt-in for internal upstreams with
/// self-signed certs, and by the test harness for the same reason
/// against in-process listeners.  Operators explicitly opt in via
/// config; this MUST NOT become the default.
#[derive(Debug)]
pub(crate) struct SkipServerVerification;

mod skip_verify_impl {
    use super::SkipServerVerification;
    use rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    impl ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();
    }

    fn tmp_file(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir()
            .join(format!("hypershunt-utls-{}-{name}", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn public_roots_by_default() {
        install_provider();
        let t = build_upstream_tls(&UpstreamTlsConfig::default()).unwrap();
        assert!(t.server_name.is_none());
    }

    #[test]
    fn skip_verify_builds() {
        install_provider();
        let t = build_upstream_tls(&UpstreamTlsConfig {
            skip_verify: true,
            ..Default::default()
        })
        .unwrap();
        assert!(t.server_name.is_none());
    }

    #[test]
    fn server_name_is_parsed_and_preferred() {
        install_provider();
        let t = build_upstream_tls(&UpstreamTlsConfig {
            server_name: Some("api.internal".into()),
            ..Default::default()
        })
        .unwrap();
        let fallback = ServerName::try_from("10.0.0.5").unwrap();
        assert_eq!(
            t.server_name_or(fallback),
            ServerName::try_from("api.internal").unwrap()
        );
    }

    #[test]
    fn missing_ca_file_is_an_error() {
        install_provider();
        let err = build_upstream_tls(&UpstreamTlsConfig {
            ca_file: Some("/nonexistent/ca.pem".into()),
            ..Default::default()
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("ca-file"), "{err}");
    }

    #[test]
    fn ca_file_without_certificates_is_an_error() {
        install_provider();
        let p = tmp_file("empty.pem", "not a certificate\n");
        let err = build_upstream_tls(&UpstreamTlsConfig {
            ca_file: Some(p.to_string_lossy().into_owned()),
            ..Default::default()
        })
        .unwrap_err()
        .to_string();
        let _ = std::fs::remove_file(&p);
        assert!(err.contains("no CA certificates"), "{err}");
    }

    #[test]
    fn ca_file_with_a_ca_loads() {
        install_provider();
        let p = tmp_file("ca.pem", &crate::test::certs::ca_pem_only());
        let t = build_upstream_tls(&UpstreamTlsConfig {
            ca_file: Some(p.to_string_lossy().into_owned()),
            ..Default::default()
        });
        let _ = std::fs::remove_file(&p);
        t.unwrap();
    }
}

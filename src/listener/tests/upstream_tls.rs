// End-to-end tests for upstream TLS trust controls: `tls { ca-file;
// server-name }` on the HTTP proxy pool, on a single upstream, over
// h3, and on the L4 stream proxy.  Each test stands up a backend
// behind a throwaway private CA and checks that verification fails
// without the setting and succeeds with it.

use crate::test::certs;
use crate::test::{TestServer, TestTlsBackend};
use std::sync::Arc;

fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

async fn get(srv: &TestServer, path: &str) -> u16 {
    let (status, _, _) = srv.get("localhost", path).await;
    status.as_u16()
}

// -- h1/h2 ----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_ca_backend_needs_ca_file() {
    install_provider();
    let pki = certs::issue(&["127.0.0.1"]);
    let backend = TestTlsBackend::start(&pki).await;
    let files = pki.write("h1-ca");

    // Public roots do not know the test CA: the handshake fails and
    // the proxy answers 502 on the backend's behalf.
    let srv = TestServer::start(&format!(
        r#"
        listener "tcp://{{addr}}"
        vhost "localhost" {{
            location "/" {{
                proxy {{ upstream "https://{}" }}
            }}
        }}
        "#,
        backend.addr,
    ))
    .await;
    assert_eq!(get(&srv, "/").await, 502);

    let srv = TestServer::start(&format!(
        r#"
        listener "tcp://{{addr}}"
        vhost "localhost" {{
            location "/" {{
                proxy {{
                    tls {{ ca-file "{}" }}
                    upstream "https://{}"
                }}
            }}
        }}
        "#,
        files.ca.display(),
        backend.addr,
    ))
    .await;
    assert_eq!(get(&srv, "/").await, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_name_overrides_sni_and_verified_name() {
    install_provider();
    // The certificate names api.internal; the proxy reaches the
    // backend by loopback IP, which the certificate does not cover.
    let pki = certs::issue(&["api.internal"]);
    let backend = TestTlsBackend::start(&pki).await;
    let files = pki.write("h1-sni");

    let srv = TestServer::start(&format!(
        r#"
        listener "tcp://{{addr}}"
        vhost "localhost" {{
            location "/" {{
                proxy {{
                    tls {{ ca-file "{}" }}
                    upstream "https://{}"
                }}
            }}
        }}
        "#,
        files.ca.display(),
        backend.addr,
    ))
    .await;
    assert_eq!(get(&srv, "/").await, 502, "IP is not in the cert");

    let srv = TestServer::start(&format!(
        r#"
        listener "tcp://{{addr}}"
        vhost "localhost" {{
            location "/" {{
                proxy {{
                    tls {{
                        ca-file "{}"
                        server-name "api.internal"
                    }}
                    upstream "https://{}"
                }}
            }}
        }}
        "#,
        files.ca.display(),
        backend.addr,
    ))
    .await;
    assert_eq!(get(&srv, "/").await, 200);
    // The override is what went on the wire, not the URL host.
    assert_eq!(
        backend.sni_seen().last().cloned().flatten().as_deref(),
        Some("api.internal")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_upstream_tls_overrides_only_that_upstream() {
    install_provider();
    // Two backends under one CA; only the second needs a name
    // override.  Round-robin sends alternate requests to each, so
    // both must verify for every request to succeed.
    let by_ip = certs::issue(&["127.0.0.1"]);
    let by_name = certs::issue_with_ca(&by_ip, &["api.internal"]);
    let b1 = TestTlsBackend::start(&by_ip).await;
    let b2 = TestTlsBackend::start(&by_name).await;
    let files = by_ip.write("h1-per-upstream");

    let srv = TestServer::start(&format!(
        r#"
        listener "tcp://{{addr}}"
        vhost "localhost" {{
            location "/" {{
                proxy {{
                    tls {{ ca-file "{}" }}
                    upstream "https://{}"
                    upstream "https://{}" {{
                        tls {{ server-name "api.internal" }}
                    }}
                }}
            }}
        }}
        "#,
        files.ca.display(),
        b1.addr,
        b2.addr,
    ))
    .await;
    for _ in 0..4 {
        assert_eq!(get(&srv, "/").await, 200);
    }
    assert!(!b1.sni_seen().is_empty() && !b2.sni_seen().is_empty());
    assert!(
        b2.sni_seen()
            .iter()
            .all(|s| s.as_deref() == Some("api.internal")),
        "{:?}",
        b2.sni_seen()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn skip_verify_still_accepts_anything() {
    install_provider();
    let pki = certs::issue(&["somewhere.else"]);
    let backend = TestTlsBackend::start(&pki).await;
    let srv = TestServer::start(&format!(
        r#"
        listener "tcp://{{addr}}"
        vhost "localhost" {{
            location "/" {{
                proxy {{
                    tls skip-verify=#true
                    upstream "https://{}"
                }}
            }}
        }}
        "#,
        backend.addr,
    ))
    .await;
    assert_eq!(get(&srv, "/").await, 200);
}

// -- active health prober ---------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_probe_uses_upstream_trust() {
    use crate::lb::HealthProber as _;

    install_provider();
    let pki = certs::issue(&["127.0.0.1"]);
    let backend = TestTlsBackend::start(&pki).await;
    let files = pki.write("probe");
    let url = format!("https://{}", backend.addr);
    let hc = crate::config::ActiveHealthConfig {
        path: "/h".into(),
        interval_secs: 0,
        timeout_secs: 2,
        expect_status: 200,
        unhealthy_after: 1,
        healthy_after: 1,
    };
    let upstream = |tls| crate::config::UpstreamConfig {
        url: url.clone(),
        weight: 1,
        group: None,
        tls,
    };

    let p = crate::handler::proxy::HttpHealthProber::new(
        &[upstream(None)],
        None,
    )
    .unwrap();
    assert!(!p.probe(&url, &hc).await, "public roots must reject");

    let p = crate::handler::proxy::HttpHealthProber::new(
        &[upstream(Some(crate::config::UpstreamTlsConfig {
            ca_file: Some(files.ca.to_string_lossy().into_owned()),
            ..Default::default()
        }))],
        None,
    )
    .unwrap();
    assert!(p.probe(&url, &hc).await);
}

// -- h3 -----------------------------------------------------------------

/// Start an in-process HTTP/3 listener serving `200` at `/` with the
/// given PEM files.  Returns the bound address; the server lives
/// until the returned sender drops.
async fn start_h3_server(
    files: &certs::PkiFiles,
) -> (std::net::SocketAddr, tokio::sync::watch::Sender<bool>) {
    use crate::auth::AnonymousAuthenticator;
    use crate::cert::tls::CertPair;
    use crate::config::Config;
    use crate::error::ErrorPages;
    use crate::listener::{AppState, BoundSocket};
    use crate::router::Router;
    use arc_swap::ArcSwap;
    use std::collections::HashMap;
    use tokio::sync::watch;

    let tls_cfg = crate::config::TlsListenerConfig {
        cert: crate::config::TlsConfig::Files {
            cert: files.cert.to_string_lossy().into_owned(),
            key: files.key.to_string_lossy().into_owned(),
        },
        options: crate::config::TlsOptions::default(),
        mtls: None,
        ocsp: Default::default(),
    };
    let opts = crate::config::TlsOptions::default();
    let (_acc, pair) = crate::cert::tls::build_acceptor_with_pair_alpn(
        &tls_cfg, &opts, None,
    )
    .unwrap();
    let (cert_tx, cert_rx) = watch::channel(Arc::new(CertPair {
        chain: pair.chain.clone(),
        key: crate::cert::tls::clone_key(&pair.key),
        alpn_store: None,
        ocsp: Vec::new(),
    }));

    let config = Config::parse(
        r#"
        listener "udp://127.0.0.1:0" { tls "self-signed" }
        vhost "localhost" {
            location "/" { respond status=200 body="ok" }
        }
        "#,
    )
    .unwrap();
    let metrics = Arc::new(crate::metrics::Metrics::new());
    let summary = Arc::new(
        crate::handler::status::ServerSummary::from_config(&config),
    );
    let router = Router::new(&config, &metrics, &summary, None).unwrap();
    let state = Arc::new(AppState {
        router: Arc::new(router),
        acme_challenges: Default::default(),
        authenticator: Arc::new(AnonymousAuthenticator),
        metrics,
        geoip: None,
        health: Arc::new(crate::handler::health::HealthState::disabled()),
        error_pages: Arc::new(ErrorPages::new(HashMap::new())),
        jwt_manager: None,
        oidc: None,
        access_log: Arc::new(
            crate::access_log::AccessLogger::tracing_default(),
        ),
        cache: None,
    });
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_nonblocking(true).unwrap();
    let addr = sock.local_addr().unwrap();
    let mut cfg = config.listeners.into_iter().next().unwrap();
    cfg.bind =
        crate::config::BoundAddr::parse(&format!("udp://{addr}")).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        // Keep the cert and stop-accept senders alive with the task.
        let _keep = (cert_tx, stop_tx);
        let _ = crate::listener::run_quic(
            cfg,
            BoundSocket::Udp(sock),
            Arc::new(ArcSwap::from(state)),
            cert_rx,
            opts,
            None,
            None,
            shutdown_rx,
            stop_rx,
        )
        .await;
    });
    (addr, shutdown_tx)
}

/// One h3 GET through `tls`; `Ok(status)` or the connect/handshake
/// error.  Retries briefly because the server's accept loop may not
/// be live on the first attempt.
async fn h3_get(
    addr: std::net::SocketAddr,
    tls: &crate::config::UpstreamTlsConfig,
) -> anyhow::Result<u16> {
    use crate::handler::proxy::H3Client;
    use http_body_util::BodyExt;

    let upstream: hyper::Uri =
        format!("https://127.0.0.1:{}/", addr.port()).parse()?;
    let tls = crate::upstream_tls::build_upstream_tls(tls)?;
    let h3 = H3Client::new(&upstream, &tls, None)?;
    let mut last = anyhow::anyhow!("no attempt");
    for _ in 0..20 {
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "localhost")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )?;
        match h3.request(req).await {
            Ok(resp) => return Ok(resp.status().as_u16()),
            Err(e) => {
                last = e;
                tokio::time::sleep(std::time::Duration::from_millis(50))
                    .await;
            }
        }
    }
    Err(last)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_private_ca_needs_ca_file_and_server_name() {
    install_provider();
    let pki = certs::issue(&["api.internal"]);
    let files = pki.write("h3");
    let (addr, _shutdown) = start_h3_server(&files).await;

    let ca = files.ca.to_string_lossy().into_owned();
    // Public roots: rejected.
    assert!(h3_get(addr, &Default::default()).await.is_err());
    // Right CA, but the IP is not in the certificate: rejected.
    assert!(
        h3_get(
            addr,
            &crate::config::UpstreamTlsConfig {
                ca_file: Some(ca.clone()),
                ..Default::default()
            },
        )
        .await
        .is_err()
    );
    // CA plus the certificate's name: accepted.
    let status = h3_get(
        addr,
        &crate::config::UpstreamTlsConfig {
            ca_file: Some(ca),
            server_name: Some("api.internal".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
}

// -- L4 stream proxy ------------------------------------------------------

/// Start a plain TCP stream listener that re-originates TLS to
/// `backend` with the given `tls` block body, then send one raw HTTP
/// request through it and return the first response line (empty when
/// the proxy closed the connection without answering, i.e. the
/// upstream handshake failed).
async fn stream_roundtrip(
    backend: std::net::SocketAddr,
    tls_block: &str,
) -> String {
    use crate::listener::{BoundSocket, run_stream_proxy};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::watch;

    let proxy_l =
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_l.local_addr().unwrap();
    let config = crate::config::Config::parse(&format!(
        r#"listener "tcp://{proxy_addr}" {{
               proxy "tcp://{backend}" {{ {tls_block} }}
           }}"#,
    ))
    .unwrap();
    let cfg = config.listeners.into_iter().next().unwrap();
    let utls = crate::bootstrap::build_upstream_tls(
        cfg.proxy.as_ref().unwrap(),
    )
    .unwrap();
    let (_tx, rx) = watch::channel(false);
    let (_stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(run_stream_proxy(
        cfg,
        BoundSocket::Tcp(proxy_l),
        None,
        utls,
        rx,
        stop_rx,
        None,
        None,
        Arc::new(crate::metrics::Metrics::new()),
    ));

    let mut client =
        tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut buf),
    )
    .await;
    String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_proxy_verifies_hostname_cert_with_server_name() {
    install_provider();
    let pki = certs::issue(&["db.internal"]);
    let backend = TestTlsBackend::start(&pki).await;
    let files = pki.write("stream");
    let ca = files.ca.display().to_string();

    // Without the override the stream proxy verifies against the IP,
    // which this certificate does not name.
    let line =
        stream_roundtrip(backend.addr, &format!(r#"tls {{ ca-file "{ca}" }}"#))
            .await;
    assert!(line.is_empty(), "expected handshake failure, got {line:?}");

    let line = stream_roundtrip(
        backend.addr,
        &format!(r#"tls {{ ca-file "{ca}"; server-name "db.internal" }}"#),
    )
    .await;
    assert!(line.starts_with("HTTP/1.1 200"), "got {line:?}");
    assert_eq!(
        backend.sni_seen().last().cloned().flatten().as_deref(),
        Some("db.internal")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_proxy_ip_cert_verifies_without_server_name() {
    install_provider();
    // The pre-existing behaviour: an IP-SAN certificate verifies under
    // the default IP server name once the CA is trusted.
    let pki = certs::issue(&["127.0.0.1"]);
    let backend = TestTlsBackend::start(&pki).await;
    let files = pki.write("stream-ip");
    let line = stream_roundtrip(
        backend.addr,
        &format!(r#"tls {{ ca-file "{}" }}"#, files.ca.display()),
    )
    .await;
    assert!(line.starts_with("HTTP/1.1 200"), "got {line:?}");
}

// Shared in-process test infrastructure for component tests.
//
// Provides TestServer (an hypershunt HTTP server with auto-shutdown) and
// TestBackend (a minimal raw-TCP backend for proxy tests), plus the
// http_get / http_get_with_headers request helpers.
//
// The entire file is compiled only under #[cfg(test)].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::watch;

use crate::auth::AnonymousAuthenticator;
use crate::config::{BoundAddr, ListenerConfig, Timeouts};
use crate::error::ErrorPages;
use arc_swap::ArcSwap;

use crate::listener::{AppState, BoundSocket, run_plain};
use crate::metrics::Metrics;
use crate::router::Router;

// ── TestServer ───────────────────────────────────────────────────────

/// In-process hypershunt HTTP server for component tests.
/// Sends a graceful shutdown signal when dropped.
pub(crate) struct TestServer {
    pub addr: SocketAddr,
    // Shared with the running server so tests can read live gauges.
    pub metrics: Arc<Metrics>,
    // Dropping the sender broadcasts shutdown to the server task.
    _tx: watch::Sender<bool>,
}

impl TestServer {
    /// Start a server from a KDL template.
    ///
    /// `{addr}` is replaced with the actual bound port before parsing.
    /// Other placeholders (e.g. `{backend}`) must be substituted by
    /// the caller before passing the template in.
    ///
    /// Timeouts and other settings in the template are respected; the
    /// `ListenerConfig` comes directly from the parsed config.
    pub async fn start(template: &str) -> Self {
        // Pre-bind a TCP port so {addr} substitution gets a real address.
        // For unix-socket templates the placeholder is unused; the port
        // is bound but discarded once we detect the unix bind below.
        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let kdl = template.replace("{addr}", &tcp_addr.to_string());
        let config = crate::config::Config::parse(&kdl).unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router = Router::new(&config, &metrics, &summary, None).unwrap();
        let health = Arc::new(
            crate::handler::health::HealthState::from_config(
                &config.server.health,
                &config.listeners,
            ),
        );
        // Take the parsed ListenerConfig so timeouts etc. are honoured.
        let cfg = config.listeners.into_iter().next().unwrap();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health,
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
            access_log: Arc::new(
                crate::access_log::AccessLogger::tracing_default(),
            ),
            cache: None,
        });
        let metrics = state.metrics.clone();
        let (tx, rx) = watch::channel(false);
        // Per-listener stop-accept channel; tests never trigger it,
        // so the receiver waits indefinitely.  Tx is retained inside
        // the spawned task via `move` so the channel stays open.
        let (_stop_tx, stop_rx) = watch::channel(false);

        // Choose socket type based on the parsed bind kind.
        let addr = if let Some(path) = cfg.bind.as_unix_path() {
            #[cfg(unix)]
            {
                drop(tcp_listener); // TCP port not needed
                let unix_listener =
                    tokio::net::UnixListener::bind(path).unwrap();
                tokio::spawn(run_plain(
                    cfg,
                    BoundSocket::Unix(unix_listener),
                    Arc::new(ArcSwap::from(state)),
                    rx,
                    stop_rx,
                ));
                // Return the loopback addr as a placeholder; callers
                // that test unix sockets connect via the socket path.
                "127.0.0.1:0".parse().unwrap()
            }
            #[cfg(not(unix))]
            panic!("unix sockets not supported on this platform");
        } else {
            tcp_listener.set_nonblocking(true).unwrap();
            let tokio_listener =
                TokioTcpListener::from_std(tcp_listener).unwrap();
            tokio::spawn(run_plain(
                cfg,
                BoundSocket::Tcp(tokio_listener),
                Arc::new(ArcSwap::from(state)),
                rx,
                stop_rx,
            ));
            tcp_addr
        };

        Self { addr, metrics, _tx: tx }
    }

    /// Start with a pre-built AppState (uses default timeouts).
    /// Use this when you need to inject a custom authenticator, JWT
    /// manager, or error pages that cannot be expressed in KDL alone.
    pub async fn start_with_state(state: Arc<AppState>) -> Self {
        Self::start_with_state_and_alt_svc(state, None).await
    }

    /// Like `start_with_state` but lets a test pre-set the listener's
    /// `auto_alt_svc` field so the Alt-Svc injection path can be
    /// exercised end-to-end.
    pub async fn start_with_state_and_alt_svc(
        state: Arc<AppState>,
        auto_alt_svc: Option<String>,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let tokio_listener = TokioTcpListener::from_std(listener).unwrap();
        let metrics = state.metrics.clone();
        let (tx, rx) = watch::channel(false);
        // Per-listener stop-accept channel; tests never trigger it,
        // so the receiver waits indefinitely.  Tx is retained inside
        // the spawned task via `move` so the channel stays open.
        let (_stop_tx, stop_rx) = watch::channel(false);
        let cfg = ListenerConfig {
            bind: BoundAddr::parse(&format!("tcp://{addr}")).unwrap(),
            tls: None,
            proxy: None,
            accept_proxy_protocol: None,
            trusted_proxies: Vec::new(),
            vhosts: Vec::new(),
            reject_unknown_host: false,
            health: None,
            timeouts: Timeouts::default(),
            http2: Default::default(),
            max_connections: None,
            max_request_body: None,
            auto_alt_svc,
            alpn: None,
            quic_transport: None,
            line: 0,
        };
        tokio::spawn(run_plain(
            cfg,
            BoundSocket::Tcp(tokio_listener),
            Arc::new(ArcSwap::from(state)),
            rx,
            stop_rx,
        ));
        Self { addr, metrics, _tx: tx }
    }

    pub async fn get(
        &self,
        host: &str,
        path: &str,
    ) -> (hyper::StatusCode, hyper::HeaderMap, Bytes) {
        http_get(self.addr, host, path).await
    }

    pub async fn get_h(
        &self,
        host: &str,
        path: &str,
        extra: &[(&str, &str)],
    ) -> (hyper::StatusCode, hyper::HeaderMap, Bytes) {
        http_get_with_headers(self.addr, host, path, extra).await
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self._tx.send(true);
    }
}

// ── HTTP helpers ─────────────────────────────────────────────────────

pub(crate) async fn http_get(
    addr: SocketAddr,
    host: &str,
    path_and_query: &str,
) -> (hyper::StatusCode, hyper::HeaderMap, Bytes) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri(path_and_query)
        .header("host", host)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    (status, headers, body)
}

pub(crate) async fn http_get_with_headers(
    addr: SocketAddr,
    host: &str,
    path_and_query: &str,
    extra: &[(&str, &str)],
) -> (hyper::StatusCode, hyper::HeaderMap, Bytes) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let mut builder =
        Request::builder().uri(path_and_query).header("host", host);
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let req = builder.body(Empty::<Bytes>::new()).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    (status, headers, body)
}

// ── TestBackend ──────────────────────────────────────────────────────

/// Minimal in-process TCP server for proxy tests.
/// Handles HTTP at the raw byte level to avoid hyper server overhead.
pub(crate) struct TestBackend {
    pub addr: SocketAddr,
    // Held to keep the background task alive; dropped by the owning test.
    _handle: tokio::task::JoinHandle<()>,
}

impl TestBackend {
    /// Start a backend that replies to every request with `status` and
    /// `body`, then closes the connection.
    pub async fn start_responding(status: u16, body: &'static [u8]) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // Drain until end-of-headers so the proxy client
                    // does not see a connection reset mid-response.
                    let mut buf = vec![0u8; 4096];
                    let mut n = 0;
                    loop {
                        match conn.read(&mut buf[n..]).await {
                            Ok(0) | Err(_) => break,
                            Ok(r) => {
                                n += r;
                                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n")
                                {
                                    break;
                                }
                                if n >= buf.len() {
                                    break;
                                }
                            }
                        }
                    }
                    let head = format!(
                        "HTTP/1.1 {status} OK\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n",
                        body.len(),
                    );
                    let _ = conn.write_all(head.as_bytes()).await;
                    let _ = conn.write_all(body).await;
                });
            }
        });

        Self {
            addr,
            _handle: handle,
        }
    }

    /// Start a backend that accepts connections but never sends any
    /// response bytes.  Useful for triggering handler timeouts.
    pub async fn start_hanging() -> Self {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            // Accumulate accepted sockets to keep them open.
            let mut sockets = Vec::new();
            while let Ok((conn, _)) = listener.accept().await {
                sockets.push(conn);
            }
        });

        Self {
            addr,
            _handle: handle,
        }
    }
}

// -- Test PKI ---------------------------------------------------------

/// Throwaway certificates for upstream-TLS tests: a CA and one leaf
/// it issued.  Everything is in memory; `write()` drops the three
/// PEM files into a temp dir for configs that need paths.
pub(crate) mod certs {
    use rcgen::{
        CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        SanType,
    };
    use std::path::PathBuf;
    use std::sync::Arc;

    pub(crate) struct TestPki {
        pub ca_pem: String,
        pub leaf_cert_pem: String,
        pub leaf_key_pem: String,
        // Kept so further leaves can be issued under the same CA.
        ca_params: CertificateParams,
        ca_key_pem: String,
    }

    pub(crate) struct PkiFiles {
        pub ca: PathBuf,
        pub cert: PathBuf,
        pub key: PathBuf,
    }

    impl Drop for PkiFiles {
        fn drop(&mut self) {
            for p in [&self.ca, &self.cert, &self.key] {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    /// Issue a leaf for `sans` (DNS names or IP literals) signed by a
    /// fresh CA.
    pub(crate) fn issue(sans: &[&str]) -> TestPki {
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(DnType::CommonName, "hypershunt test CA");
        ca.key_usages.push(KeyUsagePurpose::KeyCertSign);
        let ca_key = KeyPair::generate().unwrap();
        let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
        let ca_key_pem = ca_key.serialize_pem();
        issue_leaf(ca_pem, ca, ca_key_pem, sans)
    }

    /// Issue another leaf under `ca`'s CA, for pools where several
    /// backends share one private PKI.
    pub(crate) fn issue_with_ca(ca: &TestPki, sans: &[&str]) -> TestPki {
        issue_leaf(
            ca.ca_pem.clone(),
            ca.ca_params.clone(),
            ca.ca_key_pem.clone(),
            sans,
        )
    }

    fn issue_leaf(
        ca_pem: String,
        ca_params: CertificateParams,
        ca_key_pem: String,
        sans: &[&str],
    ) -> TestPki {
        let ca_key = KeyPair::from_pem(&ca_key_pem).unwrap();
        let issuer = Issuer::new(ca_params.clone(), ca_key);
        let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf.distinguished_name
            .push(DnType::CommonName, "hypershunt test leaf");
        for s in sans {
            let san = match s.parse::<std::net::IpAddr>() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName((*s).try_into().unwrap()),
            };
            leaf.subject_alt_names.push(san);
        }
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert_pem = leaf.signed_by(&leaf_key, &issuer).unwrap().pem();
        TestPki {
            ca_pem,
            leaf_cert_pem,
            leaf_key_pem: leaf_key.serialize_pem(),
            ca_params,
            ca_key_pem,
        }
    }

    /// Just a CA, for tests that only need a bundle to load.
    pub(crate) fn ca_pem_only() -> String {
        issue(&["unused.test"]).ca_pem
    }

    impl TestPki {
        pub(crate) fn write(&self, tag: &str) -> PkiFiles {
            let dir = std::env::temp_dir();
            let stem = format!("hypershunt-pki-{}-{tag}", std::process::id());
            let f = PkiFiles {
                ca: dir.join(format!("{stem}-ca.pem")),
                cert: dir.join(format!("{stem}-cert.pem")),
                key: dir.join(format!("{stem}-key.pem")),
            };
            std::fs::write(&f.ca, &self.ca_pem).unwrap();
            std::fs::write(&f.cert, &self.leaf_cert_pem).unwrap();
            std::fs::write(&f.key, &self.leaf_key_pem).unwrap();
            f
        }

        /// rustls server config presenting the leaf.
        pub(crate) fn server_config(&self) -> Arc<rustls::ServerConfig> {
            let certs = rustls_pemfile::certs(
                &mut self.leaf_cert_pem.as_bytes(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let key = rustls_pemfile::private_key(
                &mut self.leaf_key_pem.as_bytes(),
            )
            .unwrap()
            .unwrap();
            Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .unwrap(),
            )
        }
    }
}

// -- TestTlsBackend ---------------------------------------------------

/// HTTPS backend for upstream-TLS tests.  Serves `200 ok` over
/// HTTP/1.1 behind the given leaf and records the SNI each
/// connection presented, so a test can assert what name the proxy
/// actually sent.
pub(crate) struct TestTlsBackend {
    pub addr: SocketAddr,
    sni_seen: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    _handle: tokio::task::JoinHandle<()>,
}

impl TestTlsBackend {
    pub async fn start(pki: &certs::TestPki) -> Self {
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use tokio_rustls::LazyConfigAcceptor;

        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_cfg = pki.server_config();
        let sni_seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = sni_seen.clone();

        let handle = tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let cfg = server_cfg.clone();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let acceptor = LazyConfigAcceptor::new(
                        rustls::server::Acceptor::default(),
                        conn,
                    );
                    let Ok(start) = acceptor.await else { return };
                    seen.lock().unwrap().push(
                        start.client_hello().server_name().map(String::from),
                    );
                    let Ok(tls) = start.into_stream(cfg).await else {
                        return;
                    };
                    let svc = service_fn(|_req| async {
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::new(
                                http_body_util::Full::new(Bytes::from_static(
                                    b"ok",
                                )),
                            ),
                        )
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        Self {
            addr,
            sni_seen,
            _handle: handle,
        }
    }

    /// SNI values presented so far, in connection order.  `None` is a
    /// ClientHello without the extension (rustls sends none for IP
    /// server names).
    pub fn sni_seen(&self) -> Vec<Option<String>> {
        self.sni_seen.lock().unwrap().clone()
    }
}

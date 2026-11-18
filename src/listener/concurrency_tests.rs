// End-to-end tests for per-location concurrency limits: a real
// listener in front of a backend whose responses the test can hold
// open, so a slot stays occupied for as long as the test wants.

use crate::metrics::Metrics;
use crate::test::{TestServer, http_get_with_headers};
use hyper::StatusCode;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Backend that answers every request with the head and the first
/// half of a ten-byte body, then holds the rest until `release()`.
/// A request through it therefore sits mid-body, the state in which a
/// slot must still be counted.
struct GatedBackend {
    addr: SocketAddr,
    gate: watch::Sender<bool>,
}

impl GatedBackend {
    async fn start() -> Self {
        // The proxy handler builds a TLS-capable client even for a
        // plain-HTTP upstream, which needs a process-wide provider.
        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (gate, open) = watch::channel(false);
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let mut open = open.clone();
                tokio::spawn(async move {
                    read_until(&mut conn, b"\r\n\r\n").await;
                    let _ = conn
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\
                              Connection: close\r\n\r\nhello",
                        )
                        .await;
                    let _ = open.wait_for(|o| *o).await;
                    let _ = conn.write_all(b"world").await;
                });
            }
        });
        Self { addr, gate }
    }

    /// Let every held (and future) response finish.
    fn release(&self) {
        let _ = self.gate.send(true);
    }
}

/// Read from `conn` until `needle` has been seen (or EOF); returns
/// everything read.
async fn read_until(conn: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    while !got.windows(needle.len()).any(|w| w == needle) {
        match conn.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    got
}

/// Start a request to `path` and return once the first half of the
/// body has arrived, leaving the response mid-stream.
async fn start_streaming(srv: &TestServer, path: &str) -> TcpStream {
    let mut sock = TcpStream::connect(srv.addr).await.unwrap();
    sock.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let got = read_until(&mut sock, b"hello").await;
    assert!(got.starts_with(b"HTTP/1.1 200"), "{got:?}");
    sock
}

async fn reaches(gauge: &AtomicI64, want: i64) -> bool {
    for _ in 0..300 {
        if gauge.load(Ordering::Relaxed) == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

async fn in_flight_reaches(m: &Metrics, want: i64) -> bool {
    reaches(&m.concurrency_in_flight, want).await
}

/// Server with one vhost `h`; `{b}` in `body` is the backend address.
async fn serve(backend: &GatedBackend, server: &str, body: &str) -> TestServer {
    let body = body.replace("{b}", &backend.addr.to_string());
    TestServer::start(&format!(
        r#"
        server {{ {server} }}
        listener "tcp://{{addr}}"
        vhost "h" {{ {body} }}
        "#
    ))
    .await
}

const ONE_SLOT: &str = r#"
    location "/" {
        concurrency-limit max=1
        proxy { upstream "http://{b}" }
    }
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_pool_rejects_with_503_while_a_body_is_streaming() {
    let backend = GatedBackend::start().await;
    let srv = serve(&backend, "", ONE_SLOT).await;

    // The first response's head has been delivered, yet its body is
    // unfinished, so its slot must still be taken.
    let mut first = start_streaming(&srv, "/").await;
    assert_eq!(srv.metrics.concurrency_in_flight.load(Ordering::Relaxed), 1);
    let (status, headers, _) = srv.get("h", "/").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers.get("retry-after").unwrap(), "1");
    assert_eq!(srv.metrics.concurrency_rejected.load(Ordering::Relaxed), 1);

    // Finishing the body frees the slot for the next request.
    backend.release();
    let rest = read_until(&mut first, b"world").await;
    assert!(rest.ends_with(b"world"), "{rest:?}");
    assert!(in_flight_reaches(&srv.metrics, 0).await, "slot leaked");
    assert_eq!(srv.get("h", "/").await.0, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_disconnect_mid_body_frees_the_slot() {
    let backend = GatedBackend::start().await;
    let srv = serve(&backend, "", ONE_SLOT).await;
    let first = start_streaming(&srv, "/").await;
    assert!(in_flight_reaches(&srv.metrics, 1).await);
    drop(first);
    assert!(in_flight_reaches(&srv.metrics, 0).await, "slot leaked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_request_is_served_once_a_slot_frees() {
    let backend = GatedBackend::start().await;
    let srv = serve(
        &backend,
        "",
        r#"
        location "/" {
            concurrency-limit max=1 queue=1 queue-timeout=30
            proxy { upstream "http://{b}" }
        }
        "#,
    )
    .await;
    let mut first = start_streaming(&srv, "/").await;

    let addr = srv.addr;
    let second = tokio::spawn(async move {
        http_get_with_headers(addr, "h", "/", &[]).await
    });
    assert!(
        reaches(&srv.metrics.concurrency_waiting, 1).await,
        "second request never queued"
    );
    // The queue holds one; a third request finds it full.
    assert_eq!(srv.get("h", "/").await.0, StatusCode::SERVICE_UNAVAILABLE);

    backend.release();
    read_until(&mut first, b"world").await;
    let (status, _, body) = second.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"helloworld");
    assert_eq!(srv.metrics.concurrency_queued.load(Ordering::Relaxed), 1);
    assert_eq!(srv.metrics.concurrency_waiting.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queue_wait_that_expires_is_rejected() {
    let backend = GatedBackend::start().await;
    let srv = serve(
        &backend,
        "",
        r#"
        location "/" {
            concurrency-limit max=1 queue=1 queue-timeout=1
            proxy { upstream "http://{b}" }
        }
        "#,
    )
    .await;
    let _first = start_streaming(&srv, "/").await;
    let (status, headers, _) = srv.get("h", "/").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(headers.contains_key("retry-after"));
    assert_eq!(srv.metrics.concurrency_queued.load(Ordering::Relaxed), 1);
    assert_eq!(srv.metrics.concurrency_rejected.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn named_pool_is_exhausted_across_locations_with_its_status() {
    let backend = GatedBackend::start().await;
    let srv = serve(
        &backend,
        r#"concurrency-limit "shared" max=1 status=429"#,
        r#"
        location "/a/" {
            concurrency-limit "shared"
            proxy { upstream "http://{b}" }
        }
        location "/b/" {
            concurrency-limit "shared"
            proxy { upstream "http://{b}" }
        }
        location "/free/" {
            proxy { upstream "http://{b}" }
        }
        "#,
    )
    .await;
    let _first = start_streaming(&srv, "/a/x").await;
    // The other location draws on the same single slot.
    let (status, headers, _) = srv.get("h", "/b/x").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.contains_key("retry-after"));
    // A location outside the pool is unaffected.
    backend.release();
    assert_eq!(srv.get("h", "/free/x").await.0, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keyed_pool_limits_each_key_separately() {
    let backend = GatedBackend::start().await;
    let srv = serve(
        &backend,
        "",
        r#"
        location "/" {
            concurrency-limit max=1 { key "header" "X-Tenant" }
            proxy { upstream "http://{b}" }
        }
        "#,
    )
    .await;
    let mut sock = TcpStream::connect(srv.addr).await.unwrap();
    sock.write_all(b"GET / HTTP/1.1\r\nHost: h\r\nX-Tenant: a\r\n\r\n")
        .await
        .unwrap();
    read_until(&mut sock, b"hello").await;

    let same = srv.get_h("h", "/", &[("x-tenant", "a")]).await.0;
    assert_eq!(same, StatusCode::SERVICE_UNAVAILABLE);
    backend.release();
    let other = srv.get_h("h", "/", &[("x-tenant", "b")]).await.0;
    assert_eq!(other, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dry_run_serves_over_limit_requests_and_counts_them() {
    let backend = GatedBackend::start().await;
    let srv = serve(
        &backend,
        "",
        r#"
        location "/" {
            concurrency-limit max=1 dry-run=#true
            proxy { upstream "http://{b}" }
        }
        "#,
    )
    .await;
    let _first = start_streaming(&srv, "/").await;
    // The first request still holds the only slot, so this one is
    // over the limit; `start_streaming` asserts it gets a 200.
    let _second = start_streaming(&srv, "/").await;
    assert_eq!(srv.metrics.concurrency_dry_run.load(Ordering::Relaxed), 1);
    // An admitted over-limit request is not counted against the pool.
    assert_eq!(srv.metrics.concurrency_in_flight.load(Ordering::Relaxed), 1);
    assert_eq!(srv.metrics.concurrency_rejected.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limited_request_does_not_take_a_slot() {
    let backend = GatedBackend::start().await;
    let srv = serve(
        &backend,
        "",
        r#"
        location "/" {
            rate-limit rate=1 per="hour" burst=1 { key "client-ip" }
            concurrency-limit max=1
            proxy { upstream "http://{b}" }
        }
        "#,
    )
    .await;
    let _first = start_streaming(&srv, "/").await;
    // Both gates would refuse this one; the rate limit answers first.
    assert_eq!(srv.get("h", "/").await.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(srv.metrics.concurrency_rejected.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_rejection_maps_to_unavailable() {
    let backend = GatedBackend::start().await;
    let srv = serve(&backend, "", ONE_SLOT).await;
    let _first = start_streaming(&srv, "/").await;
    let ct = ("content-type", "application/grpc");
    let (status, headers, _) = srv.get_h("h", "/pkg.Svc/M", &[ct]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("grpc-status").unwrap(), "14");
    assert!(headers.contains_key("retry-after"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_websocket_tunnel_holds_its_slot_until_closed() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{
        accept_async, connect_async, tungstenite::protocol::Message,
    };

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = echo.accept().await {
            tokio::spawn(async move {
                let Ok(mut ws) = accept_async(sock).await else {
                    return;
                };
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_close() {
                        break;
                    }
                    if ws.send(msg).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let srv = TestServer::start(&format!(
        r#"
        listener "tcp://{{addr}}" {{ }}
        vhost "h" {{
            location "/" {{
                concurrency-limit max=1
                proxy {{ upstream "http://{echo_addr}" }}
            }}
        }}
        "#
    ))
    .await;

    let url = format!("ws://{}/echo", srv.addr);
    let (mut ws, response) = connect_async(&url).await.expect("ws connect");
    assert_eq!(response.status(), 101);
    ws.send(Message::text("ping")).await.unwrap();
    let reply = ws.next().await.expect("reply").unwrap();
    assert_eq!(reply.into_text().unwrap().as_str(), "ping");

    // The 101 response is long finished; only the tunnel is left,
    // and it must still be holding the slot.
    assert_eq!(srv.metrics.concurrency_in_flight.load(Ordering::Relaxed), 1);
    assert_eq!(srv.get("h", "/").await.0, StatusCode::SERVICE_UNAVAILABLE);

    ws.close(None).await.unwrap();
    drop(ws);
    assert!(in_flight_reaches(&srv.metrics, 0).await, "tunnel slot leaked");
}

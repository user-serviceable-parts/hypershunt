// `concurrency-limit` config-parse tests: inline pools on a location,
// named pools in `server`, references between them, and validation.

use crate::config::*;

/// Parse a config whose only location carries `body`, with `server`
/// as the contents of the `server` block.
fn parse_with(server: &str, body: &str) -> anyhow::Result<Config> {
    Config::parse(&format!(
        r#"
        server {{ {server} }}
        listener "tcp://[::]:80"
        vhost h {{
            location "/api/" {{
                {body}
                static root="."
            }}
        }}
        "#
    ))
}

fn limits(body: &str) -> Vec<ConcurrencyLimitRef> {
    parse_with("", body).unwrap().vhosts[0].locations[0]
        .concurrency_limits
        .clone()
}

fn inline(r: &ConcurrencyLimitRef) -> &ConcurrencyLimitConfig {
    match r {
        ConcurrencyLimitRef::Inline(c) => c,
        other => panic!("expected an inline pool, got {other:?}"),
    }
}

fn err(server: &str, body: &str) -> String {
    parse_with(server, body).unwrap_err().to_string()
}

#[test]
fn concurrency_limit_defaults() {
    let l = limits("concurrency-limit max=8");
    assert_eq!(
        *inline(&l[0]),
        ConcurrencyLimitConfig {
            name: "api-cl-0".into(),
            max: 8,
            queue: 0,
            queue_timeout_secs: None,
            status: 503,
            dry_run: false,
            key: None,
        }
    );
}

#[test]
fn concurrency_limit_all_properties_parse() {
    let l = limits(
        r#"concurrency-limit max=2 queue=16 queue-timeout=5 status=429 \
               dry-run=#true name="per-client" {
               key "header" "X-Api-Key"
           }"#,
    );
    assert_eq!(
        *inline(&l[0]),
        ConcurrencyLimitConfig {
            name: "per-client".into(),
            max: 2,
            queue: 16,
            queue_timeout_secs: Some(5),
            status: 429,
            dry_run: true,
            key: Some(RateLimitKeyConfig::Header("x-api-key".into())),
        }
    );
}

#[test]
fn concurrency_limit_queue_timeout_accepts_duration_string() {
    let l = limits(r#"concurrency-limit max=1 queue=1 queue-timeout="2m""#);
    assert_eq!(inline(&l[0]).queue_timeout_secs, Some(120));
}

#[test]
fn concurrency_limit_blocks_preserve_order() {
    let l = limits(
        r#"concurrency-limit max=2 { key "client-ip" }
           concurrency-limit max=8"#,
    );
    assert_eq!(l.len(), 2);
    assert_eq!(inline(&l[0]).key, Some(RateLimitKeyConfig::ClientIp));
    assert_eq!(inline(&l[1]).name, "api-cl-1");
    assert_eq!(inline(&l[1]).key, None);
}

#[test]
fn named_pool_and_reference_parse() {
    let cfg = parse_with(
        r#"concurrency-limit "reports" max=8 queue=4 queue-timeout=3"#,
        r#"concurrency-limit "reports""#,
    )
    .unwrap();
    let pool = &cfg.server.concurrency_limits["reports"];
    assert_eq!(pool.name, "reports");
    assert_eq!((pool.max, pool.queue), (8, 4));
    assert!(matches!(
        &cfg.vhosts[0].locations[0].concurrency_limits[0],
        ConcurrencyLimitRef::Named { name, .. } if name == "reports"
    ));
}

#[test]
fn named_pool_may_be_declared_after_its_reference() {
    Config::parse(
        r#"
        listener "tcp://[::]:80"
        vhost h {
            location "/" {
                concurrency-limit "late"
                static root="."
            }
        }
        server { concurrency-limit "late" max=1 }
        "#,
    )
    .unwrap();
}

#[test]
fn concurrency_limit_requires_max() {
    let e = err("", "concurrency-limit queue=1 queue-timeout=1");
    assert!(e.contains("requires max=<integer>"), "{e}");
}

#[test]
fn concurrency_limit_rejects_zero_max() {
    let e = err("", "concurrency-limit max=0");
    assert!(e.contains("`max` must be"), "{e}");
}

#[test]
fn concurrency_limit_queue_requires_timeout() {
    let e = err("", "concurrency-limit max=1 queue=4");
    assert!(e.contains("`queue` requires `queue-timeout`"), "{e}");
}

#[test]
fn concurrency_limit_timeout_requires_queue() {
    let e = err("", "concurrency-limit max=1 queue-timeout=5");
    assert!(e.contains("`queue-timeout` requires `queue` > 0"), "{e}");
}

#[test]
fn concurrency_limit_rejects_zero_queue_timeout() {
    let e = err("", "concurrency-limit max=1 queue=1 queue-timeout=0");
    assert!(e.contains("'queue-timeout' must be positive"), "{e}");
}

#[test]
fn concurrency_limit_rejects_non_error_status() {
    let e = err("", "concurrency-limit max=1 status=200");
    assert!(e.contains("`status` must be 400..=599"), "{e}");
}

#[test]
fn concurrency_limit_rejects_unknown_property() {
    let e = err("", "concurrency-limit max=1 queu=2");
    assert!(e.contains("unknown property 'queu'"), "{e}");
    assert!(e.contains("did you mean 'queue'"), "{e}");
}

#[test]
fn concurrency_limit_rejects_unknown_child() {
    let e = err("", r#"concurrency-limit max=1 { kee "client-ip" }"#);
    assert!(e.contains("unknown node 'kee' in concurrency-limit"), "{e}");
    assert!(e.contains("did you mean 'key'"), "{e}");
}

#[test]
fn concurrency_limit_rejects_unknown_key_form() {
    let e = err("", r#"concurrency-limit max=1 { key "cookie" }"#);
    assert!(e.contains("concurrency-limit unknown key form"), "{e}");
}

#[test]
fn reference_to_unknown_pool_is_rejected_with_suggestion() {
    let e = err(
        r#"concurrency-limit "reports" max=8"#,
        r#"concurrency-limit "report""#,
    );
    assert!(e.contains("unknown concurrency-limit pool 'report'"), "{e}");
    assert!(e.contains("did you mean 'reports'"), "{e}");
}

#[test]
fn reference_takes_no_properties_or_children() {
    let server = r#"concurrency-limit "reports" max=8"#;
    for body in [
        r#"concurrency-limit "reports" max=2"#,
        r#"concurrency-limit "reports" { key "client-ip" }"#,
    ] {
        let e = err(server, body);
        assert!(e.contains("takes no properties or children"), "{e}");
    }
}

#[test]
fn duplicate_pool_name_is_rejected() {
    let e = err(
        r#"concurrency-limit "p" max=1
           concurrency-limit "p" max=2"#,
        "",
    );
    assert!(e.contains("duplicate concurrency-limit name 'p'"), "{e}");
}

#[test]
fn server_pool_requires_a_name() {
    let e = err("concurrency-limit max=1", "");
    assert!(e.contains("requires a name argument"), "{e}");
}

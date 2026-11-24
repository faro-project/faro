//! The real listener: `server::run` over TCP, uptime bookkeeping and
//! graceful shutdown.

mod common;

use common::*;
use sqlx::Row;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

#[tokio::test]
async fn serves_over_tcp_and_records_uptime() {
    let t = TestApp::new().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(faro_server::server::run(t.state.clone(), listener, async {
        let _ = stop_rx.await;
    }));

    let resp = http_get(addr, "/.well-known/faro").await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains(t.state.instance_id().as_str()));
    // hyper adds a Date header, which devices use to detect clock skew (§3.6).
    assert!(resp.to_ascii_lowercase().contains("\r\ndate: "));

    // While running, the uptime row is open.
    let open = count(
        &t.state,
        "SELECT COUNT(*) FROM instance_uptime WHERE stopped_at IS NULL",
    )
    .await;
    assert_eq!(open, 1);

    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();

    // `run` closed the pool on the way out; reopen to inspect.
    let db = faro_server::db::Db::connect(&t.state.config().database_url())
        .await
        .unwrap();
    let row = sqlx::query("SELECT started_at, stopped_at FROM instance_uptime")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let started: i64 = row.try_get("started_at").unwrap();
    let stopped: Option<i64> = row.try_get("stopped_at").unwrap();
    assert!(stopped.is_some_and(|s| s >= started), "clean stop recorded");
}

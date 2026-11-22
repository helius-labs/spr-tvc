use std::{io, sync::Arc};

use axum::{
    body::Bytes,
    http::StatusCode,
    routing::{get, post},
};
use tokio::{
    io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::{mpsc, oneshot, Notify},
    time::Instant,
};

use super::*;

const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: enclave\r\n\r\n";

struct TestListener(mpsc::Receiver<DuplexStream>);

impl Listener for TestListener {
    type Io = DuplexStream;
    type Addr = ();

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        (self.0.recv().await.unwrap(), ())
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn caps_connections_and_drains_the_completed_provisioning_reply() {
    let (connect, incoming) = mpsc::channel(2);
    let (stop, stopped) = oneshot::channel();
    let started = Arc::new(Notify::new());
    let done = Arc::new(Notify::new());
    let handler_started = started.clone();
    let handler_done = done.clone();
    let router = Router::new().route(
        "/",
        get(move || async move {
            handler_started.notify_one();
            handler_done.notified().await;
            StatusCode::NO_CONTENT
        }),
    );
    let server = tokio::spawn(serve(TestListener(incoming), router, 1, async {
        stopped.await.unwrap();
    }));

    let (mut idle, server_idle) = duplex(1024);
    let (mut second, server_second) = duplex(1024);
    connect.send(server_idle).await.unwrap();
    connect.send(server_second).await.unwrap();
    second.write_all(REQUEST).await.unwrap();
    assert!(timeout(HEADER_DEADLINE / 2, started.notified())
        .await
        .is_err());
    started.notified().await;
    assert_eq!(idle.read(&mut [0]).await.unwrap(), 0);

    stop.send(()).unwrap();
    done.notify_one();
    let mut reply = Vec::new();
    second.read_to_end(&mut reply).await.unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 204 No Content\r\n"));
    server.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn closes_incomplete_headers_at_the_header_deadline() {
    let (mut client, server) = duplex(1024);
    let router = Router::new().route("/", get(|| async { StatusCode::OK }));
    let start = Instant::now();
    let task = tokio::spawn(connection(server, router));
    client
        .write_all(&REQUEST[..REQUEST.len() - 2])
        .await
        .unwrap();
    task.await.unwrap();
    assert_eq!(Instant::now() - start, HEADER_DEADLINE);
    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn bounds_header_bytes_and_still_streams_a_larger_body() {
    let app = Router::new().route(
        "/",
        post(|body: Bytes| async move { body.len().to_string() }),
    );
    let (mut client, server) = duplex(HEADER_BYTES * 2);
    let task = tokio::spawn(connection(server, app.clone()));
    let header = format!(
        "POST / HTTP/1.1\r\nHost: enclave\r\nX-Padding: {}\r\n\r\n",
        "a".repeat(HEADER_BYTES)
    );
    client.write_all(header.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 431 "));
    task.await.unwrap();

    let (mut client, server) = duplex(1024);
    let task = tokio::spawn(connection(server, app));
    let body_bytes = HEADER_BYTES * 2;
    let header =
        format!("POST / HTTP/1.1\r\nHost: enclave\r\nContent-Length: {body_bytes}\r\n\r\n");
    client.write_all(header.as_bytes()).await.unwrap();
    client.write_all(&vec![b'a'; body_bytes]).await.unwrap();
    response.clear();
    client.read_to_end(&mut response).await.unwrap();
    let reply = String::from_utf8(response).unwrap();
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(reply.contains("\r\nconnection: close\r\n"));
    assert!(reply.ends_with(&body_bytes.to_string()));
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn stalled_response_cannot_hold_a_socket_past_the_connection_deadline() {
    let (mut client, server) = duplex(1024);
    let app = Router::new().route("/", get(|| async { vec![0_u8; 16 * 1024] }));
    let start = Instant::now();
    let task = tokio::spawn(connection(server, app));
    client.write_all(REQUEST).await.unwrap();
    task.await.unwrap();
    assert_eq!(Instant::now() - start, CONNECTION_DEADLINE);
}

//! Bounded HTTP/1 connections from the Nitro parent.

use std::{future::Future, time::Duration};

use axum::{serve::Listener, Router};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinSet,
    time::timeout,
};

const HEADER_BYTES: usize = 16 * 1024;
const HEADER_DEADLINE: Duration = Duration::from_secs(3);
const CONNECTION_DEADLINE: Duration = Duration::from_secs(10);
const DRAIN_DEADLINE: Duration = Duration::from_secs(5);

pub(crate) async fn serve(
    mut listener: impl Listener,
    router: Router,
    limit: usize,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            _ = connections.join_next(), if !connections.is_empty() => {},
            (stream, _) = listener.accept(), if connections.len() < limit => {
                connections.spawn(connection(stream, router.clone()));
            }
        }
    }

    // Let the provisioning response flush. Dropping the set then closes any stalled sockets.
    let _ = timeout(DRAIN_DEADLINE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
}

async fn connection(stream: impl AsyncRead + AsyncWrite + Unpin, router: Router) {
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(HEADER_DEADLINE)
        .max_buf_size(HEADER_BYTES)
        .keep_alive(false);
    let _ = timeout(
        CONNECTION_DEADLINE,
        http.serve_connection(TokioIo::new(stream), TowerToHyperService::new(router)),
    )
    .await;
}

#[cfg(test)]
#[path = "../tests/unit/nitro_connections.rs"]
mod tests;

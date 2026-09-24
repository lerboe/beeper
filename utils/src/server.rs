//! The servers the integration tests send their requests to: an HTTP echo
//! server and Redis.

use std::net::SocketAddr;

use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use tracing::debug;

/// Answers a request with its own headers and body.
///
/// Responds with `400 Bad Request` if the body is not valid UTF-8.
async fn echo(headers: HeaderMap, body: Bytes) -> Result<impl IntoResponse, StatusCode> {
    if let Ok(body) = String::from_utf8(body.to_vec()) {
        debug!(
            target: "echo",
            "received request with headers: {:?} and body: {}", headers, body
        );
        Ok((headers, body))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

/// Launches an echo server on localhost and returns the address it is bound to.
pub async fn launch() -> Result<SocketAddr> {
    let echo = get(move |hdrs: HeaderMap, body: Bytes| echo(hdrs, body));
    let app = Router::new()
        .route("/", echo.clone())
        .route("/{*path}", echo.clone());

    let addr: SocketAddr = "127.0.0.1:0".parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Ok(local_addr)
}

/// A Redis server the RESP2 tests send their commands to. It is killed when
/// this value is dropped.
pub struct Redis {
    /// The address the server listens on.
    pub addr: SocketAddr,
    _child: tokio::process::Child,
}

/// Launches `redis-server` on localhost, without persistence, and waits until
/// it accepts connections.
///
/// # Errors
///
/// Returns an error if `redis-server` cannot be run, or if it does not accept
/// connections within five seconds.
pub async fn launch_redis() -> Result<Redis> {
    // the port is picked by the kernel and released again for the server to take
    let addr = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let child = tokio::process::Command::new("redis-server")
        .args(["--bind", "127.0.0.1", "--port", &addr.port().to_string()])
        .args(["--save", "", "--appendonly", "no"])
        .stdout(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;

    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            debug!("redis-server listening on {addr}");
            return Ok(Redis {
                addr,
                _child: child,
            });
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    anyhow::bail!("redis-server did not come up on {addr}")
}

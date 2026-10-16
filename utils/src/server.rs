//! The echo servers the integration tests send their requests to.

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

/// Launches a TCP server on localhost that echoes whatever it receives, and
/// returns the address it is bound to.
pub async fn launch_tcp_echo() -> Result<SocketAddr> {
    let addr: SocketAddr = "127.0.0.1:0".parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut rx, mut tx) = stream.split();
                _ = tokio::io::copy(&mut rx, &mut tx).await;
            });
        }
    });

    Ok(local_addr)
}

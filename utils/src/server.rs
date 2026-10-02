//! An HTTP echo server the integration tests send their requests to.

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
    launch_on("127.0.0.1:0".parse()?).await
}

/// Launches an echo server on `addr` and returns the address it is bound to,
/// which differs from `addr` only if its port is 0.
pub async fn launch_on(addr: SocketAddr) -> Result<SocketAddr> {
    let echo = get(move |hdrs: HeaderMap, body: Bytes| echo(hdrs, body));
    let app = Router::new()
        .route("/", echo.clone())
        .route("/{*path}", echo.clone());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Ok(local_addr)
}

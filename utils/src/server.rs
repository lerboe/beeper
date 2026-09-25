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
/// The port is picked by the kernel and released again for the server to
/// take, so a test running alongside may pick the same one. The server that
/// loses it exits, and is launched again on another port.
///
/// # Errors
///
/// Returns an error if `redis-server` cannot be run, or if it does not accept
/// connections on any of the ports it is launched on.
pub async fn launch_redis() -> Result<Redis> {
    for _ in 0..5 {
        let addr = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
        let mut child = tokio::process::Command::new("redis-server")
            .args(["--bind", "127.0.0.1", "--port", &addr.port().to_string()])
            .args(["--save", "", "--appendonly", "no"])
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;

        for _ in 0..50 {
            if child.try_wait()?.is_some() {
                debug!("redis-server exited, {addr} is taken");
                break;
            }

            if serves(addr, child.id()).await {
                debug!("redis-server listening on {addr}");
                return Ok(Redis {
                    addr,
                    _child: child,
                });
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    anyhow::bail!("redis-server did not come up")
}

/// Returns whether the Redis listening on `addr` is the process `pid`, rather
/// than one another test launched on the same port.
async fn serves(addr: SocketAddr, pid: Option<u32>) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (Some(pid), Ok(mut stream)) = (pid, tokio::net::TcpStream::connect(addr).await) else {
        return false;
    };

    // the server closes the connection behind the reply to QUIT
    let req = b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n*1\r\n$4\r\nQUIT\r\n";
    let mut info = Vec::new();
    if stream.write_all(req).await.is_err() || stream.read_to_end(&mut info).await.is_err() {
        return false;
    }

    String::from_utf8_lossy(&info).contains(&format!("process_id:{pid}\r\n"))
}

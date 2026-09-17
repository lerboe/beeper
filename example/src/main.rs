//! A minimal server whose traffic is monitored from eBPF.

use axum::{Router, http::HeaderMap, http::header::ACCEPT_LANGUAGE, routing::get};
use monitor::Monitor;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use xbpf::OpenObject;

mod monitor;

/// Greets the client in the language its `Accept-Language` header asks for,
/// German or French, and in English otherwise.
async fn greet(headers: HeaderMap) -> &'static str {
    let lang = headers
        .get(ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .unwrap_or("")
        .trim();

    if lang.starts_with("de") {
        "Hallo Welt"
    } else if lang.starts_with("fr") {
        "Bonjour le monde"
    } else {
        "Hello World"
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,bpf=trace", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // the monitor has to outlive the server, and nothing of it is loaded
    // unless it is attached
    let mut open_obj = OpenObject::new();
    let _monitor = Monitor::attach(addr, &mut open_obj).expect("attach monitor");

    let app = Router::new().fallback(get(greet));

    let listener = TcpListener::bind(addr).await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

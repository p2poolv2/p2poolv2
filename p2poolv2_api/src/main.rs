use axum::{Router, routing::get};
use p2poolv2_lib::config::Config;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    println!("p2poolv2_api crate booting...");

    let app = Router::new().route("/health", get(|| async { "OK" }));

    let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
    println!("Running API server on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

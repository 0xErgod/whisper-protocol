//! `prover-server` binary: build the keys registry, build the
//! router, bind a TCP listener, serve.
//!
//! ## Environment
//!
//! - `PROVER_BIND_ADDR` — TCP socket to bind. Default `127.0.0.1:3001`.
//! - `PROVER_KEYS_DIR` — directory for PK/VK artifacts. Default
//!   `./keys/`. The directory is created on boot if missing; the
//!   server runs Groth16 setup for any circuit whose `.pk` /
//!   `.vk` files are absent and writes them.
//!
//! ## Logs
//!
//! Plain `println!`. No `tracing_subscriber` (see
//! `specs/zk/stack.md` for the 400x regression that justifies
//! this).

use std::sync::Arc;

use prover_server::keys::{build as build_registry, default_keys_dir};
use prover_server::routes::{build_router, AppState};
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let bind_addr = std::env::var("PROVER_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3001".to_string());
    let keys_dir = std::env::var("PROVER_KEYS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| default_keys_dir());

    println!("[main] keys_dir = {}", keys_dir.display());
    println!("[main] bind_addr = {bind_addr}");

    // Boot-time setup: load or generate every circuit's PK/VK.
    // This runs the heavy Groth16 setup paths on first boot; on
    // subsequent boots it's a pair of file reads per circuit.
    let registry = Arc::new(build_registry(&keys_dir)?);
    println!("[main] keys registry built");

    let state = AppState { registry };
    let app = build_router(state).layer(
        // Permissive CORS for development. Production deployments
        // should tighten this to the dApp's known origin.
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any),
    );

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    println!("[main] listening on http://{bind_addr}");
    axum::serve(listener, app).await?;

    Ok(())
}

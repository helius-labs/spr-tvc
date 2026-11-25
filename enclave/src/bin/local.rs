//! Explicitly unattested local development server.

use std::io;
use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use spr_tvc_decryption_service::{local_unattested_service, serve, DEFAULT_BIND_PORT};

#[derive(Debug, Parser)]
#[command(name = "spr-tvc-decryption-service-local")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,

    #[arg(long, default_value_t = DEFAULT_BIND_PORT)]
    port: u16,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(cli.host, cli.port)).await?;
    let address = listener.local_addr()?;
    eprintln!(
        "LOCAL DEVELOPMENT ONLY: unattested decryption service on {address}; do not use funds"
    );
    println!("{address}");
    serve(listener, local_unattested_service()).await
}

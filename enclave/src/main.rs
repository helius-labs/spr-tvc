use std::io;
use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use spr_tvc_decryption_service::{serve, Release, Service, DEFAULT_BIND_PORT};

#[derive(Debug, Parser)]
#[command(name = "spr-tvc-decryption-service")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,

    #[arg(long, default_value_t = DEFAULT_BIND_PORT)]
    port: u16,

    #[command(flatten)]
    release: Release,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let service = Service::load(cli.release)?;
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(cli.host, cli.port)).await?;
    serve(listener, service).await
}

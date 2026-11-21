#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    use clap::Parser;
    use spr_tvc_decryption_service::nitro::{run, Config};
    run(Config::parse()).await
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::other("native Nitro requires Linux"))
}

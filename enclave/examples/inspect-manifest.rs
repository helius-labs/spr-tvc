//! Read the approved QOS manifest using the same schema and hash as the enclave.

use std::io::{self, Read};

use qos_core::protocol::services::boot::manifest::VersionedManifest;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let manifest = VersionedManifest::V2(serde_json::from_slice(&input)?);
    println!(
        "{}",
        serde_json::json!({
            "manifestDigest": hex::encode(manifest.manifest_hash()),
            "executableDigest": hex::encode(manifest.pivot_hash()),
            "quorumPublicKey": hex::encode(&manifest.namespace().quorum_key),
        })
    );
    Ok(())
}

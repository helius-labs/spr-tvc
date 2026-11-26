//! A spend that has not opened notes fetches the nullifier secret once.

use spr_tvc_rust_example::{local_client, owner};

fn main() {
    let client = local_client();
    let owner = owner();
    let mut keys = client.keys(&owner).expect("keys");
    let secret = keys.nullifier_secret().expect("nullifier secret");
    println!("ok nullifier_secret_len={}", secret.len());
}

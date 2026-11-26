//! The address a sender pays before the owner registers a shielded wallet.

use spr_tvc_rust_example::{local_client, owner};
use spr_tvc_wire::encoding::encode_lower_hex;

fn main() {
    let client = local_client();
    let owner = owner();
    let address = client.address(&owner.pubkey()).expect("address");
    println!(
        "ok viewing_public_key={}",
        encode_lower_hex(address.viewing_pubkey.as_bytes())
    );
}

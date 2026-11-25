//! The owner opens one note encrypted to the service address.

use spr_tvc_rust_example::{local_client, note_for, owner};

fn main() {
    let client = local_client();
    let owner = owner();
    let mut keys = client.keys(&owner).expect("keys");
    let plaintext = b"ten usdc".to_vec();
    let note = note_for(&keys.address(), &plaintext, 0);
    let opened = keys.decrypt(std::slice::from_ref(&note)).expect("decrypt");
    assert_eq!(opened, vec![plaintext]);
    println!(
        "ok plaintext={}",
        std::str::from_utf8(&opened[0]).expect("utf-8")
    );
}

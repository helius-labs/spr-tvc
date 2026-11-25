//! The owner opens two notes in one decrypt. The plaintexts stay in order.

use spr_tvc_rust_example::{local_client, note_for, owner};

fn main() {
    let client = local_client();
    let owner = owner();
    let mut keys = client.keys(&owner).expect("keys");
    let first = b"ten usdc".to_vec();
    let second = b"two sol".to_vec();
    let notes = [
        note_for(&keys.address(), &first, 0),
        note_for(&keys.address(), &second, 1),
    ];
    let opened = keys.decrypt(&notes).expect("decrypt");
    assert_eq!(opened, vec![first, second]);
    println!(
        "ok plaintexts={},{}",
        std::str::from_utf8(&opened[0]).expect("utf-8"),
        std::str::from_utf8(&opened[1]).expect("utf-8")
    );
}

#[path = "common/mod.rs"]
mod support;

use support::{one_note, replay, Key, Tape};

use spr_tvc_client::{DecryptionClient, ReqwestTransport};

#[test]
fn opens_one_note_for_its_owner() {
    let Ok(endpoint) = std::env::var("DECRYPTION_SERVICE_LOCAL_ENDPOINT") else {
        return;
    };
    let tape = Tape::new(ReqwestTransport::new().expect("client"));
    let client = DecryptionClient::connect_local(endpoint.as_str(), &tape).expect("loopback");
    let owner = Key::from_seed(7);
    let other = Key::from_seed(8);
    let mut keys = client.keys(&owner).expect("keys");
    let (note, plaintext) = one_note(&keys.address());
    let opened = keys.decrypt(std::slice::from_ref(&note)).expect("decrypt");
    assert_eq!(opened, vec![plaintext.clone()]);

    let decrypt = tape
        .posts()
        .into_iter()
        .rfind(|post| post.url.ends_with("/v1/operations"))
        .expect("decrypt request");
    replay(&tape, &decrypt, None);

    let mut other_keys = client.keys(&other).expect("other keys");
    let wrong = other_keys
        .decrypt(std::slice::from_ref(&note))
        .expect("other owner");
    assert_ne!(wrong, vec![plaintext]);
}

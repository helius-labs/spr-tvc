use super::*;

#[test]
fn a_client_key_id_is_the_prefix_and_a_truncated_digest() {
    assert_eq!(
        client_key_id(&[4; 65]),
        "spr-client-p256-9bda95bda1ef8f1b61f6d47223f4a119"
    );
}

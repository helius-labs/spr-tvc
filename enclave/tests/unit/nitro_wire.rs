use qos_p256::{encrypt::P256EncryptPublic, P256Pair};

use super::*;

#[test]
fn interoperates_with_spr_wire_and_requires_authenticated_canonical_frames() {
    let native = NativePair::generate().unwrap();
    let qos = P256Pair::generate().unwrap();
    let message = b"native Nitro transport interoperability";
    let incoming = P256EncryptPublic::from_bytes(&native.public[..POINT])
        .unwrap()
        .encrypt(message)
        .unwrap();
    assert_eq!(native.decrypt(&incoming).unwrap().as_slice(), message);

    let native_response = NativePeer::parse(&qos.public_key().to_bytes()[..POINT])
        .unwrap()
        .encrypt(message)
        .unwrap();
    assert_eq!(qos.decrypt(&native_response).unwrap().as_slice(), message);
    qos_p256::P256Public::from_bytes(&native.public)
        .unwrap()
        .verify(message, &native.sign(message).unwrap())
        .unwrap();

    assert!(NativePair::generate().unwrap().decrypt(&incoming).is_none());
    let mut corrupt = incoming.clone();
    corrupt[0] ^= 1;
    assert!(native.decrypt(&corrupt).is_none());
    let mut corrupt = incoming.clone();
    corrupt[NONCE] = 2;
    assert!(native.decrypt(&corrupt).is_none());
    let mut corrupt = incoming.clone();
    corrupt[NONCE + POINT] ^= 1;
    assert!(native.decrypt(&corrupt).is_none());
    assert!(native.decrypt(&incoming[..incoming.len() - 1]).is_none());
    let mut corrupt = incoming;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(native.decrypt(&corrupt).is_none());
}

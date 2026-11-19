use zeroize::Zeroizing;

use super::*;

#[test]
fn qos_signatures_are_normalized_to_low_s_for_the_wire() {
    let message = b"spr tvc low-s interop";
    for seed_byte in 0u8..=u8::MAX {
        let pair = P256Pair::from_master_seed(&Zeroizing::new([seed_byte; 32])).unwrap();
        let raw = pair.sign(message).unwrap();
        let raw = Signature::from_slice(&raw).unwrap();
        if raw.normalize_s().is_some() {
            let normalized = sign_ephemeral_low_s(&pair, message).unwrap();
            let normalized = Signature::from_slice(&normalized).unwrap();
            assert!(normalized.normalize_s().is_none());
            pair.public_key()
                .verify(message, &normalized.to_bytes())
                .unwrap();
            return;
        }
    }
    panic!("fixed QOS seed corpus did not produce a high-S signature");
}

use strum::VariantArray;

use super::ErrorCode;

#[test]
fn every_code_is_its_variant_name() {
    let names: Vec<&str> = ErrorCode::VARIANTS
        .iter()
        .map(|code| code.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "UnsupportedVersion",
            "RequestTooLarge",
            "ReleaseBindingMismatch",
            "QuorumKeyEpochMismatch",
            "ExpiredRequest",
            "TurnkeyEvidenceInvalid",
            "InvalidCanonicalJson",
            "DuplicateJsonField",
            "UnknownJsonField",
            "InvalidHex",
            "InvalidDecimal",
            "InvalidPublicKey",
            "InvalidSignature",
            "HighSSignature",
            "DerSignatureRejected",
            "CompressedKeyRejected",
            "DoubleHashRejected",
            "BootProofUnverified",
            "DiscoveryUntrusted",
            "NetworkMismatch",
            "ReleasePolicyInvalid",
        ]
    );
    for code in ErrorCode::VARIANTS {
        assert_eq!(code.to_string(), code.as_str());
        assert_eq!(crate::TvcError::new(*code).to_string(), code.as_str());
    }
}

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;

pub const DOMAIN: &str = "beta-devnet.helius-rpc.com";
pub const NOW: u64 = 1_800_000_000_000;

pub fn enrollment(domains: &[&str]) -> Enrollment {
    let domains: Vec<String> = domains.iter().map(|&domain| domain.to_owned()).collect();
    Enrollment::new(Network::Devnet, &domains)
}

pub fn owner() -> SigningKey {
    SigningKey::from_bytes(&[3; 32])
}

pub fn client_public_hex() -> String {
    let secret = p256::SecretKey::from_slice(&[5; 32]).expect("test client key is invalid");
    hex::encode(secret.public_key().to_encoded_point(false).as_bytes())
}

/// An enrollment signed by [`owner`] at `issued_at_ms`.
pub fn signed_request(issued_at_ms: u64) -> EnrollmentRequest {
    let mut request = EnrollmentRequest {
        organization_id: "1f0e6b1e-2a4c-4f7e-8d2b-3c4d5e6f7a8b".to_owned(),
        turnkey_wallet_id: "2a1b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d".to_owned(),
        solana_address: bs58::encode(owner().verifying_key().to_bytes()).into_string(),
        client_public_key: client_public_hex(),
        issued_at_ms,
        owner_signature: String::new(),
    };
    request.owner_signature = sign(&owner(), DOMAIN, &request);
    request
}

fn sign(signer: &SigningKey, domain: &str, request: &EnrollmentRequest) -> String {
    sign_for(signer, domain, Network::Devnet, request)
}

fn sign_for(
    signer: &SigningKey,
    domain: &str,
    network: Network,
    request: &EnrollmentRequest,
) -> String {
    let message = message(domain, network, request).expect("the test request formats");
    hex::encode(signer.sign(message.as_bytes()).to_bytes())
}

pub fn input() -> EnrollmentInput {
    enrollment(&[DOMAIN])
        .verify(&signed_request(NOW), NOW)
        .expect("test request is invalid")
}

#[test]
fn a_recent_owner_signature_enrolls() {
    let enrollment = enrollment(&[DOMAIN]);
    for now in [NOW, NOW + MAX_ENROLLMENT_AGE_MS, NOW - MAX_CLOCK_SKEW_MS] {
        assert!(
            enrollment.verify(&signed_request(NOW), now).is_ok(),
            "{now}"
        );
    }
}

#[test]
fn an_old_or_future_enrollment_is_refused() {
    let enrollment = enrollment(&[DOMAIN]);
    for now in [NOW + MAX_ENROLLMENT_AGE_MS + 1, NOW - MAX_CLOCK_SKEW_MS - 1] {
        assert_eq!(
            enrollment.verify(&signed_request(NOW), now).err(),
            Some(ApiError::StaleEnrollment)
        );
    }
}

#[test]
fn a_signature_by_another_key_or_over_other_fields_is_refused() {
    let enrollment = enrollment(&[DOMAIN]);
    let invalid = Some(ApiError::InvalidOwnerEnrollmentSignature);
    let mut intruder = signed_request(NOW);
    intruder.owner_signature = sign(&SigningKey::from_bytes(&[4; 32]), DOMAIN, &intruder);
    assert_eq!(enrollment.verify(&intruder, NOW).err(), invalid);
    let mut other_key = signed_request(NOW);
    let secret = p256::SecretKey::from_slice(&[6; 32]).expect("test client key is invalid");
    other_key.client_public_key =
        hex::encode(secret.public_key().to_encoded_point(false).as_bytes());
    assert_eq!(enrollment.verify(&other_key, NOW).err(), invalid);
    let mut other_time = signed_request(NOW);
    other_time.issued_at_ms += 1;
    assert_eq!(enrollment.verify(&other_time, NOW).err(), invalid);
}

#[test]
fn a_signature_for_any_of_the_gateways_domains_enrolls() {
    let enrollment = enrollment(&["devnet.helius-rpc.com", DOMAIN]);
    for domain in ["devnet.helius-rpc.com", DOMAIN] {
        let mut request = signed_request(NOW);
        request.owner_signature = sign(&owner(), domain, &request);
        assert!(enrollment.verify(&request, NOW).is_ok(), "{domain}");
    }
}

#[test]
fn a_signature_for_another_network_is_refused() {
    let mut mainnet = signed_request(NOW);
    mainnet.owner_signature = sign_for(&owner(), DOMAIN, Network::Mainnet, &mainnet);
    assert_eq!(
        enrollment(&[DOMAIN]).verify(&mainnet, NOW).err(),
        Some(ApiError::InvalidOwnerEnrollmentSignature)
    );
    let message = message(DOMAIN, Network::Mainnet, &mainnet).expect("formats");
    assert!(message.contains("\nChain ID: mainnet\n"), "{message}");
}

#[test]
fn a_signature_for_another_domain_is_refused() {
    let mut elsewhere = signed_request(NOW);
    elsewhere.owner_signature = sign(&owner(), "wallet.example", &elsewhere);
    assert_eq!(
        enrollment(&[DOMAIN]).verify(&elsewhere, NOW).err(),
        Some(ApiError::InvalidOwnerEnrollmentSignature)
    );
}

#[test]
fn malformed_requests_are_refused() {
    let enrollment = enrollment(&[DOMAIN]);
    let mut uppercase = signed_request(NOW);
    uppercase.client_public_key = uppercase.client_public_key.to_uppercase();
    assert!(enrollment.verify(&uppercase, NOW).is_err());
    let mut compressed = signed_request(NOW);
    compressed.client_public_key.truncate(66);
    assert!(enrollment.verify(&compressed, NOW).is_err());
    let mut multiline = signed_request(NOW);
    multiline.organization_id.push('\n');
    assert_eq!(
        enrollment.verify(&multiline, NOW).err(),
        Some(ApiError::InvalidEnrollmentRequest)
    );
}

#[test]
fn the_message_matches_the_shared_test_vector() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/wallet-enrollment.json"))
            .expect("the test vector parses");
    let mut enrollment = fixture["enrollment"].clone();
    let domain = enrollment["domain"].take();
    let network: Network =
        serde_json::from_value(enrollment["network"].take()).expect("the network parses");
    let object = enrollment
        .as_object_mut()
        .expect("the enrollment is an object");
    object.remove("domain");
    object.remove("network");
    object.insert("ownerSignature".to_owned(), "".into());
    let request: EnrollmentRequest =
        serde_json::from_value(enrollment).expect("the test vector is an enrollment");
    assert_eq!(
        message(
            domain.as_str().expect("the domain is a string"),
            network,
            &request
        ),
        fixture["message"].as_str().map(str::to_owned)
    );
}

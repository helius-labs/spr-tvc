use super::*;

#[test]
fn proving_key_names_the_key_file_of_the_circuit_shape() {
    use serde_json::json;

    let transfer = |circuit: &str, inputs: usize, outputs: usize| {
        json!({
            "circuitType": circuit,
            "inputs": vec![json!({}); inputs],
            "outputs": vec![json!({}); outputs],
        })
    };
    let merge = |circuit: &str, inputs: usize| json!({ "circuitType": circuit, "inputs": vec![json!({}); inputs] });
    for (body, key) in [
        (
            transfer("transfer-confidential", 2, 2),
            "transfer_confidential_2_2",
        ),
        (
            transfer("transfer-confidential", 12, 16),
            "transfer_confidential_12_16",
        ),
        (transfer("transfer-ring", 1, 2), "transfer_ring_1_2"),
        (merge("merge", 8), "merge_8_1"),
        (merge("merge", 52), "merge_52_1"),
        (merge("merge-ring", 52), "merge_ring_52_1"),
    ] {
        assert_eq!(prove::proving_key(&body).expect("key"), key);
    }
    for body in [
        // A circuit the wallet never proves.
        transfer("transfer-ring-authority", 1, 2),
        json!({ "circuitType": "custom-ring-policy" }),
        // Slot counts outside the installed keys.
        transfer("transfer-confidential", 0, 2),
        transfer("transfer-confidential", 2, 0),
        merge("merge", MAX_PROVE_INPUTS + 1),
        json!({ "circuitType": "transfer-confidential", "inputs": [{}], "outputs": "0x2" }),
        json!("not an object"),
    ] {
        assert_eq!(
            failure(prove::proving_key(&body)),
            Failure::Invalid,
            "{body}"
        );
    }
}

#[test]
fn prove_fills_only_the_open_secret_slots() {
    use serde_json::json;

    let secret = [0x0a; 31];
    // The prover's field encoding: no leading zero digits.
    let filled = "0x".to_owned() + "0a".repeat(31).trim_start_matches('0');
    let transfer = json!({
        "circuitType": "transfer-confidential",
        "nInputs": 2,
        "inputs": [
            { "isDummy": "0x0", "nullifierSecret": null, "nullifier": "0x1" },
            { "isDummy": "0x1", "nullifierSecret": "0x0", "nullifier": "0x2" },
        ],
        "outputs": [],
    });
    let complete = prove::complete(&transfer, &secret).expect("complete");
    assert_eq!(complete["inputs"][0]["nullifierSecret"], filled);
    assert_eq!(complete["inputs"][1]["nullifierSecret"], "0x0");
    // Nothing else moves.
    let mut expected = transfer.clone();
    expected["inputs"][0]["nullifierSecret"] = json!(filled);
    assert_eq!(complete, expected);

    let merge = json!({
        "circuitType": "merge",
        "inputs": [{ "nullifier": "0x1" }],
        "userNullifierPk": "0x3",
        "userNullifierSecret": null,
    });
    let complete = prove::complete(&merge, &secret).expect("complete");
    assert_eq!(complete["userNullifierSecret"], filled);

    // A leading zero byte in the secret is not written: fields are integers.
    let mut short = [0u8; 31];
    short[30] = 0x0f;
    assert_eq!(
        prove::complete(&merge, &short).expect("complete")["userNullifierSecret"],
        "0xf"
    );

    for body in [
        // Nothing to fill.
        json!({ "circuitType": "merge", "inputs": [{}], "userNullifierSecret": "0x1" }),
        // Unknown circuit.
        json!({ "circuitType": "custom-ring", "inputs": [{}] }),
        // The secret asked for in a padding slot.
        json!({ "circuitType": "transfer-ring", "inputs": [{ "isDummy": "0x1", "nullifierSecret": null }] }),
        // A slot of the wrong shape.
        json!({ "circuitType": "transfer-ring", "inputs": [{ "isDummy": "0x0", "nullifierSecret": 7 }] }),
        // No inputs, too many inputs.
        json!({ "circuitType": "transfer-confidential", "inputs": [] }),
        json!({ "circuitType": "merge", "inputs": vec![json!({}); MAX_PROVE_INPUTS + 1], "userNullifierSecret": null }),
        json!("not an object"),
    ] {
        assert_eq!(
            failure(prove::complete(&body, &secret)),
            Failure::Invalid,
            "{body}"
        );
    }
}

/// The image trusts the policy signers of the network it was built for.
#[test]
fn the_image_trusts_its_networks_policy_signers() {
    let expected =
        PolicySigners::new(NETWORK, NET.policy_signers.to_vec(), NET.policy_threshold).unwrap();
    assert_eq!(ProverTrust::image().signers, expected);
}

#[test]
fn prove_seals_the_completed_request_to_the_attested_prover() {
    let case = prover_case("/prove/merge_1_1");
    let sealed = seal_case(&case).expect("sealed");
    assert_eq!(sealed.target, "/prove/merge_1_1");

    let opened = case
        .prover
        .open("POST", &sealed.target, &sealed.enc, &sealed.ciphertext)
        .expect("opens on its route");
    case.prover
        .open(
            "POST",
            "/v1/spr/prove/merge_1_1",
            &sealed.enc,
            &sealed.ciphertext,
        )
        .expect("opens on its route under the gateway prefix");
    let witness: serde_json::Value = serde_json::from_slice(&opened.plaintext).expect("json");
    assert_eq!(
        witness["userNullifierSecret"],
        format!("0x{}", "0a".repeat(32).trim_start_matches('0'))
    );
    assert_eq!(opened.response_key, sealed.response_key);
    assert!(case
        .prover
        .open("POST", "/prove/merge_8_1", &sealed.enc, &sealed.ciphertext)
        .is_err());
}

#[test]
fn prove_refuses_a_prover_outside_the_signed_policy() {
    type Edit = fn(&mut ProverCase);
    let cases: &[(&str, Edit)] = &[
        ("policy signed by another key", |case| {
            let other = ed25519_dalek::SigningKey::from_bytes(&[0x98; 32]);
            let policy = approved_policy(case);
            case.sealing.policy = signed_policy(&other, NETWORK, policy, ATTESTED_AT_SECS + 60);
        }),
        ("policy of another network", |case| {
            let policy = approved_policy(case);
            case.sealing.policy =
                signed_policy(&policy_signer(), "localnet", policy, ATTESTED_AT_SECS + 60);
        }),
        ("expired policy", |case| {
            let policy = approved_policy(case);
            case.sealing.policy =
                signed_policy(&policy_signer(), NETWORK, policy, ATTESTED_AT_SECS);
        }),
        ("edited release payload", |case| {
            let release = &mut case.sealing.policy["release"];
            let payload = release["payload"].as_str().unwrap().to_owned();
            release["payload"] = serde_json::json!(payload.replacen("7b", "7b20", 1));
        }),
        ("the image's own signers", |case| {
            case.trust.signers = ProverTrust::image().signers
        }),
        ("attestation for another nonce", |case| {
            case.sealing.nonce = [0x12; 32]
        }),
        ("measurement the policy does not pin", |case| {
            let mut tee = serde_json::to_value(approved_policy(case)).unwrap();
            tee["measurements"][0]["pcr0"] = serde_json::json!("04".repeat(48));
            let policy = serde_json::from_value(tee).unwrap();
            case.sealing.policy =
                signed_policy(&policy_signer(), NETWORK, policy, ATTESTED_AT_SECS + 60);
        }),
        ("evidence under a root the enclave does not trust", |case| {
            case.trust.anchors = Anchors::PRODUCTION
        }),
        ("an attestation without evidence", |case| {
            case.sealing.attestation = serde_json::json!({ "platform": "aws-nitro" })
        }),
    ];
    for (name, edit) in cases {
        let mut case = prover_case("/prove/merge_1_1");
        edit(&mut case);
        assert_eq!(
            failure(seal_case(&case)),
            Failure::Stage(FailureStage::Prover),
            "{name}"
        );
    }
}

#[test]
fn prove_binds_only_the_route_of_the_requests_proving_key() {
    seal_case(&prover_case("/prove/merge_1_1")).expect("the route");
    for target in [
        "/v1/spr/prove/merge_1_1",
        "/v1/zolana/prove/merge_1_1",
        "/prove/merge_8_1",
        "/prove/merge_1_1?jobId=1",
        "/prove/merge_1_1/",
        "/prove/merge_1_1/status",
        "//prove/merge_1_1",
        "prove/merge_1_1",
        "",
    ] {
        assert_eq!(
            failure(seal_case(&prover_case(target))),
            Failure::Invalid,
            "{target}"
        );
    }
}

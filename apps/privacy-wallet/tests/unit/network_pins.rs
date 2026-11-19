use super::*;

/// The keys each network's gateway signs with, and the policy signers
/// zolana pins for each network at the revision this crate builds
/// against.
#[test]
fn each_network_trusts_its_own_keys() {
    let signer = "1fe5d29c79064ea17a16308452040b799df8aeaaae588d44a527a8da9ffa924a";
    for (net, network, provisioning, grant) in [
        (
            &DEVNET,
            "devnet",
            "046e852f2eb1bc79e2ed3cdb57fa7e2f75720fe53032f6aedcfbdfceb67f635691540564e208ca675f4d8b33291aa1388a0067dadc4f1d04519aab320bbd2cce64",
            "04d92dfa9ba9aafd471ff9ffbf454b9a11b14858a8c2edb4f79a4ea4b4dba8ca5cac9ec06d9bb5576db72d07e087ac6aadf72e4eb31323aafaf9dbd133d26f4dc7",
        ),
        (
            &MAINNET,
            "mainnet",
            "04f87ca34fcd2b78f57321c662a66395e400744a1951655ed77fbd1482a84e7590359b5f9b157a84489db68b02984c90b641a05deec3cdfd67dd990aecc89a58e0",
            "048929b53b1b9d0b22be43a306583cdb9233e48da9e260cde61c6f93ceb1e5ea43973c01057c98779d47c03e5a5ed8e2ed1e0bc3d9685bc6deea2474d44fd57d5d",
        ),
    ] {
        assert_eq!(hex::encode(net.provisioning), provisioning, "{network}");
        assert_eq!(hex::encode(net.grant), grant, "{network}");
        assert_eq!(
            net.policy_signers.iter().map(hex::encode).collect::<Vec<_>>(),
            [signer],
            "{network}"
        );
        assert_eq!(net.policy_threshold, 1);
    }
}

#[test]
fn an_image_built_without_spr_network_is_devnet() {
    if option_env!("SPR_NETWORK").is_none() {
        assert_eq!(spr_tvc_enclave::NETWORK, Network::Devnet);
    }
}

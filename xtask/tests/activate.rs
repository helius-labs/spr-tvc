use super::*;
use serde_json::json;

#[test]
fn activation_requires_the_same_two_distinct_operators_for_approval_and_recovery() {
    let mut value = json!({
        "manifestSet": { "threshold": 2, "operators": [{"id": "one"}, {"id": "two"}] },
        "shareSet": { "threshold": 2, "operators": [{"id": "two"}, {"id": "one"}] },
        "manifestApprovals": [],
    });
    let sets: OperatorSets = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(sets.operators().unwrap(), ["one", "two"]);
    value["shareSet"]["operators"][0]["id"] = json!("other");
    let sets: OperatorSets = serde_json::from_value(value).unwrap();
    assert!(sets.operators().is_err());
}

#[test]
fn interactive_review_and_attestation_cannot_be_skipped_by_environment() {
    let command = activation_command("approve", "candidate");
    for var in [
        "TVC_DANGEROUS_SKIP_INTERACTIVE",
        "TVC_DANGEROUS_SKIP_VERIFICATION",
        "TVC_NON_INTERACTIVE",
    ] {
        assert!(command
            .get_envs()
            .any(|(key, val)| key == var && val.is_none()));
    }
}

#[test]
fn runtime_selection_alone_does_not_make_the_deployment_ready() {
    let record: Deployment =
        serde_json::from_value(json!({"deployId": "candidate", "replicas": 2})).unwrap();
    let mut value = json!({
        "reason": "deployment_runtime_status", "deploymentId": "candidate",
        "appId": "app", "isTargeted": true, "replicas": {"ready": 1, "desired": 2},
    });
    let state: RuntimeStatus = serde_json::from_value(value.clone()).unwrap();
    assert!(!state.ready(true, &record, "app").unwrap());
    assert!(state.ready(true, &record, "other-app").is_err());
    value["replicas"]["ready"] = json!(2);
    let state: RuntimeStatus = serde_json::from_value(value.clone()).unwrap();
    assert!(state.ready(true, &record, "app").unwrap());
    value["isTargeted"] = json!(false);
    let state: RuntimeStatus = serde_json::from_value(value).unwrap();
    assert!(!state.ready(true, &record, "app").unwrap());

    for (code, pending) in [("not_found", true), ("unauthorized", false)] {
        let state: RuntimeStatus = serde_json::from_value(json!({
            "reason": "command_error", "code": code, "message": "example error",
        }))
        .unwrap();
        assert_eq!(
            state.ready(false, &record, "app").ok(),
            pending.then_some(false)
        );
    }
}

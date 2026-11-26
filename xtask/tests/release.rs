use std::fs;

use clap::Parser;

use crate::tools::Credentials;
use crate::{Action, Cli, Command, ReleaseCommand};

fn command(args: &[&str]) -> ReleaseCommand {
    let Cli { action } = Cli::try_parse_from(args.iter().copied()).unwrap();
    match action {
        Command::Deploy(command) | Command::Pin(command) => command,
    }
}

fn kind(args: &[&str]) -> Action {
    match Cli::try_parse_from(args.iter().copied()).unwrap().action {
        Command::Deploy(_) => Action::Deploy,
        Command::Pin(_) => Action::Pin,
    }
}

#[test]
fn release_requires_inputs_for_its_command_and_network() {
    let sha = "1".repeat(40);
    let image = format!(
        "ghcr.io/helius-labs/spr-tvc-decryption-service:decryption-service-devnet-0123456789ab@sha256:{}",
        "ab".repeat(32)
    );
    let rejected: &[&[&str]] = &[
        &["xtask", "deploy", "--network", "devnet"],
        &[
            "xtask",
            "deploy",
            "--network",
            "devnet",
            "--source-commit",
            &sha,
        ],
        &["xtask", "pin", "--network", "devnet", "--image", &image],
        &[
            "xtask",
            "pin",
            "--network",
            "devnet",
            "--image",
            &image,
            "--deploy-id",
            "id",
            "--signed-policy",
            "signed.json",
        ],
        &["xtask", "deploy", "--network", "mainnet", "--image", &image],
        &[
            "xtask",
            "deploy",
            "--network",
            "mainnet",
            "--image",
            &image,
            "--source-commit",
            &sha[..12],
        ],
        &[
            "xtask",
            "pin",
            "--network",
            "mainnet",
            "--image",
            &image,
            "--source-commit",
            &sha,
        ],
    ];
    for args in rejected {
        assert!(command(args).validate(kind(args)).is_err(), "{args:?}");
    }
    command(&["xtask", "deploy", "--network", "devnet", "--image", &image])
        .validate(Action::Deploy)
        .unwrap();
    command(&[
        "xtask",
        "deploy",
        "--network",
        "mainnet",
        "--image",
        &image,
        "--source-commit",
        &sha,
    ])
    .validate(Action::Deploy)
    .unwrap();
    command(&[
        "xtask",
        "pin",
        "--network",
        "devnet",
        "--image",
        &image,
        "--deploy-id",
        "deployment",
    ])
    .validate(Action::Pin)
    .unwrap();
    command(&[
        "xtask",
        "pin",
        "--network",
        "mainnet",
        "--signed-policy",
        "signed.json",
    ])
    .validate(Action::Pin)
    .unwrap();
}

#[test]
fn tvc_uses_the_active_profile_and_ignores_nested_operator_ids() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.json");
    fs::write(&key, r#"{"public_key":"unused","private_key":"unused"}"#).unwrap();
    fs::write(
        dir.path().join("tvc.config.toml"),
        format!(
            r#"
        active_org = "active.profile"
        [orgs.inactive]
        id = "other-org"
        [orgs."active.profile"]
        id = "active-org"
        api_key_path = {:?}
        [[orgs."active.profile".operators]]
        id = "operator"
    "#,
            key.to_str().unwrap()
        ),
    )
    .unwrap();
    assert_eq!(
        Credentials::profile(dir.path()).unwrap().organization_id,
        "active-org"
    );
}

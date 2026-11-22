use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Parser;
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use spr_tvc_protocol::{
    digest::sha256,
    encoding::{decode_lower_hex, encode_lower_hex, is_rfc8785, jcs_serialize},
};

const MAX_POLICY_BYTES: usize = 32_768;

#[derive(Parser)]
#[command(bin_name = "cargo xtask nitro-sign")]
pub(crate) struct Args {
    /// Canonical JSON policy envelope with release and custody signature lists.
    policy: PathBuf,
    /// Immutable ARN of the signer's ECC_NIST_P256 key.
    #[arg(long)]
    key: String,
    /// Independently pinned uncompressed SEC1 public key in lowercase hex.
    #[arg(long)]
    public_key: String,
    /// Pinned custody trust file for an activation.
    #[arg(long)]
    custody_trust: Option<PathBuf>,
    /// Sign as a custody approver for an activation.
    #[arg(long)]
    custody: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignedPolicy {
    policy: serde_json::Value,
    signatures: Vec<Approval>,
    custody_signatures: Vec<Approval>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    key: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KmsSignature {
    key_id: String,
    signature: String,
    signing_algorithm: String,
}

fn digest(policy: &serde_json::Value, custody: bool) -> Result<[u8; 32]> {
    let domain = if custody {
        b"SPR/native-nitro/custody-release-policy/v1".as_slice()
    } else {
        b"SPR/native-nitro/release-policy/v1".as_slice()
    };
    let canonical = jcs_serialize(policy)?;
    Ok(sha256(&[domain, canonical.as_bytes()].concat()))
}

fn validate_action(policy: &serde_json::Value) -> Result<()> {
    ensure!(
        policy["recoveryOnly"].is_boolean(),
        "expected a recoveryOnly boolean"
    );
    let targets = policy["targets"]
        .as_array()
        .context("expected a release target list")?;
    ensure!(
        match policy["action"].as_str() {
            Some("activate") => (1..=8).contains(&targets.len()),
            Some("revoke") => targets.is_empty(),
            _ => false,
        },
        "activate with one to eight targets or revoke with an empty target list"
    );
    Ok(())
}

fn decode_signature(
    signed: &KmsSignature,
    arn: &str,
    pinned: &VerifyingKey,
    digest: &[u8; 32],
) -> Result<Signature> {
    ensure!(
        signed.key_id == arn && signed.signing_algorithm == "ECDSA_SHA_256",
        "unexpected KMS signing identity or algorithm"
    );
    let signed = Signature::from_der(&STANDARD.decode(&signed.signature)?)?.normalize_s();
    pinned.verify_prehash(digest, &signed)?;
    Ok(signed)
}

pub(crate) fn sign(args: Args) -> Result<()> {
    let path = std::path::absolute(args.policy)?;
    let mut text = String::new();
    std::fs::File::open(&path)?
        .take(MAX_POLICY_BYTES as u64 + 1)
        .read_to_string(&mut text)?;
    ensure!(
        text.len() <= MAX_POLICY_BYTES && is_rfc8785(&text),
        "use canonical policy JSON up to 32 KiB"
    );
    let mut manifest: SignedPolicy = serde_json::from_str(&text)?;
    validate_action(&manifest.policy)?;
    let activate = manifest.policy["action"] == "activate";
    ensure!(
        activate || (!args.custody && manifest.custody_signatures.is_empty()),
        "revocation accepts release signatures only"
    );
    let bytes = decode_lower_hex(&args.public_key)?;
    ensure!(
        bytes.len() == 65 && bytes[0] == 4,
        "expected an uncompressed P-256 key"
    );
    let public = VerifyingKey::from_sec1_bytes(&bytes)?;
    ensure!(
        !manifest
            .signatures
            .iter()
            .chain(&manifest.custody_signatures)
            .any(|prior| prior.key == args.public_key),
        "signing key already present"
    );
    let approvals = if args.custody {
        &mut manifest.custody_signatures
    } else {
        &mut manifest.signatures
    };
    ensure!(approvals.len() < 8, "too many approvals");

    let parts: Vec<_> = args.key.split(':').collect();
    let ["arn", "aws", "kms", region, account, key] = parts.as_slice() else {
        anyhow::bail!("expected an immutable KMS key ARN");
    };
    ensure!(
        !region.is_empty()
            && account.len() == 12
            && account.bytes().all(|byte| byte.is_ascii_digit())
            && key.strip_prefix("key/").is_some_and(|id| id.len() == 36),
        "expected an immutable KMS key ARN"
    );

    if activate {
        let trust = args
            .custody_trust
            .context("activation requires --custody-trust")?;
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../enclave/deploy/nitro/custody_ledger.py");
        let mut candidate = tempfile::NamedTempFile::new()?;
        candidate.write_all(text.as_bytes())?;
        let mut check = Command::new("python3");
        check
            .arg("-B")
            .arg(script)
            .arg(trust)
            .arg("check-serving-policy")
            .arg(candidate.path());
        if args.custody {
            check.args(["--custody-signer", &args.key, &args.public_key]);
        }
        crate::tools::capture_check(&mut check)?;
    }

    let digest = digest(&manifest.policy, args.custody)?;
    let mut command = Command::new("aws");
    command.env("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true");
    command.args([
        "--region",
        region,
        "--no-cli-pager",
        "--output",
        "json",
        "kms",
        "sign",
        "--key-id",
        &args.key,
        "--signing-algorithm",
        "ECDSA_SHA_256",
        "--message-type",
        "DIGEST",
        "--cli-binary-format",
        "base64",
        "--message",
        &STANDARD.encode(digest),
    ]);
    let signed: KmsSignature = serde_json::from_slice(&crate::tools::capture_check(&mut command)?)?;
    let signature = decode_signature(&signed, &args.key, &public, &digest)?;
    approvals.push(Approval {
        key: args.public_key,
        signature: encode_lower_hex(&signature.to_bytes()),
    });
    let canonical = jcs_serialize(&manifest)?;
    ensure!(
        canonical.len() <= MAX_POLICY_BYTES,
        "signed policy exceeds 32 KiB"
    );
    let mut output =
        tempfile::NamedTempFile::new_in(path.parent().context("missing policy parent")?)?;
    output.write_all(canonical.as_bytes())?;
    output.as_file().sync_all()?;
    output.persist(&path)?;
    println!("signed {}", path.display());
    Ok(())
}

#[cfg(test)]
#[path = "../tests/nitro_sign.rs"]
mod tests;

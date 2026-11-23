mod gateway;

use std::{cell::RefCell, env, path::Path};

use anyhow::{anyhow, ensure, Context, Result};
use gateway::{decrypt_item, Gateway};
use reqwest::Url;
use solana_keypair::{read_keypair_file, Keypair};
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::instruction::transfer;
use spr_client::{
    prover::tee::{SignedTeePolicy, TeeNetwork},
    user_registry::{register_if_absent, try_resolve_registered_address, StrictRegistration},
    HistoryFilters, IndexerRpcConfig, ProofDataSource, ProverClient, Rpc, SolanaRpc, SprClient,
    SprIndexer,
};
use spr_interface::{
    instruction::{instruction_data::transact::TransactIxData, tag},
    pda, SHIELDED_POOL_PROGRAM_ID,
};
use spr_keypair::{
    NullifierKey, ShieldedAddress, ShieldedKeypair, SigningKey, ViewingKey, X25519Pubkey,
};
use spr_program::instruction::{AssetDeposit, Deposit, DepositAsset, Transact};
use spr_transaction::{
    decrypt_spendable,
    instructions::transact::{ConfidentialTransaction, Shape},
    AssetRegistry, DecryptRequest, DeriveRequest, ShieldedKeys, ShieldedTransaction,
    TransactionError, TransactionKeyRequest, WalletUtxo,
};
use spr_tvc_protocol::DecryptItem;

const DEVNET: &str = "https://devnet.helius-rpc.com/";
const DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const TREE: u16 = 0;
const FUNDING: u64 = 10_000_000;
const SHIELD: u64 = 1_000_000;
const SEND: u64 = 400_000;

type Client = SprClient<SolanaRpc>;

#[test]
#[ignore = "submits funded transactions to Solana devnet"]
fn registered_sender_pays_unregistered_recipient() {
    let api_key = env::var("HELIUS_API_KEY")
        .or_else(|_| env::var("API_KEY"))
        .expect("set HELIUS_API_KEY or API_KEY");
    assert!(!api_key.is_empty(), "a Helius devnet API key is required");
    let payer =
        env::var_os("SPR_E2E_PAYER").expect("set SPR_E2E_PAYER to a funded devnet keypair file");
    if let Err(error) = run(&api_key, Path::new(&payer)) {
        panic!("{}", format!("{error:#}").replace(&api_key, "<redacted>"));
    }
}

fn run(api_key: &str, payer: &Path) -> Result<()> {
    let rpc = SolanaRpc::new(helius_url("", api_key)?.to_string());
    ensure!(
        rpc.client().get_genesis_hash()?.to_string() == DEVNET_GENESIS,
        "expected Solana devnet"
    );
    let indexer_url = helius_url("v1/spr", api_key)?.to_string();
    let prover = ProverClient::new(indexer_url.clone())
        .with_signed_tee(SignedTeePolicy::for_network(TeeNetwork::Devnet));
    prover.attest().context("attest the devnet prover")?;
    let client = SprClient::new(rpc, SprIndexer::new(&indexer_url), prover)
        .with_proof_data_source(ProofDataSource::Client);
    let gateway = Gateway::connect(api_key).context("attest the Gatekeeper decryption service")?;

    let a = Keypair::new();
    let b = Keypair::new();
    let local_a = local_keys(&a)?;
    let address_a = local_a.shielded_address()?;
    let address_b = gateway.public_keys(b.pubkey())?;
    assert_eq!(gateway.public_keys(b.pubkey())?, address_b);
    let service_a = gateway.public_keys(a.pubkey())?;
    assert_ne!(service_a.viewing_pubkey, address_b.viewing_pubkey);
    assert_ne!(service_a.nullifier_pubkey, address_b.nullifier_pubkey);
    assert_unregistered(&client, &a)?;
    assert_unregistered(&client, &b)?;
    let public_balance_b = client.get_balance(b.pubkey())?;

    let payer = read_keypair_file(payer).map_err(|error| anyhow!("read devnet payer: {error}"))?;
    let funding = transfer(&payer.pubkey(), &a.pubkey(), FUNDING);
    let funding_sig = client
        .create_and_send_transaction(
            &[funding],
            payer.pubkey(),
            &[&payer],
            client.compute_budget(),
        )
        .context("fund A on devnet")?;
    println!("Funded A: {funding_sig}");

    let StrictRegistration::Written(registration) = register_if_absent(client.rpc(), &a, &local_a)?
    else {
        anyhow::bail!("expected a new registry record");
    };
    assert_eq!(
        try_resolve_registered_address(client.rpc(), a.pubkey())?
            .context("A is unregistered")?
            .address,
        address_a
    );
    assert_eq!(
        register_if_absent(client.rpc(), &a, &local_a)?,
        StrictRegistration::Current
    );
    println!("Registered A: {registration}");

    let deposit = Deposit {
        tree: pda::tree(TREE),
        depositor: a.pubkey(),
        deposits: vec![AssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: address_a.confidential_view_tag()?,
            owner: address_a.owner_hash()?,
            amount: SHIELD,
            memo: None,
        }],
    }
    .instruction()?;
    let deposit_sig = client
        .create_and_send_transaction(&[deposit], a.pubkey(), &[&a], client.compute_budget())
        .context("shield SOL to A")?;
    let deposit_slot = landed_slot(&client, deposit_sig)?;
    println!("Shielded SOL to A: {deposit_sig}");
    let deposits = tagged_transactions(&client, &address_a, deposit_slot)?;
    let note = only_note(&local_a, &deposits, SHIELD)?;
    assert_eq!(note.tx_signature, deposit_sig);

    let mut transfer =
        ConfidentialTransaction::new(vec![note.clone()], a.pubkey())?.with_output_tree_id(TREE)?;
    transfer.transfer_sol(&address_b, SEND)?;
    transfer.pad_utxos(Shape::IN2_OUT4, &address_a)?;
    let data = client
        .prove_transact(
            transfer.encrypt(&local_a)?,
            Some(IndexerRpcConfig::at_slot(deposit_slot)),
            &local_a,
        )
        .context("prove the A-to-B confidential transfer")?;
    let send_ix = Transact {
        payer: a.pubkey(),
        input_trees: vec![pda::tree(note.tree_id())],
        output_tree: pda::tree(TREE),
        owner_signers: vec![a.pubkey()],
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction();
    let send_sig = client
        .create_and_send_transaction(&[send_ix], a.pubkey(), &[&a], client.compute_budget())
        .context("send shielded SOL to B")?;
    let send_slot = landed_slot(&client, send_sig)?;
    println!("Sent shielded SOL to B: {send_sig}");

    assert_unregistered(&client, &b)?;
    assert_eq!(client.get_balance(b.pubkey())?, public_balance_b);
    let mut received = tagged_transactions(&client, &address_b, send_slot)?;
    received.retain(|transaction| transaction.tx_signature == send_sig);
    assert_eq!(
        received.len(),
        1,
        "B must discover A's transfer by its owner tag"
    );
    assert!(received[0].nullifiers.contains(&note.nullifier));
    assert!(received[0]
        .output_slots
        .iter()
        .all(|slot| slot.proofless_output().is_none()));
    assert!(
        decrypt_spendable(&local_keys(&b)?, &received, &AssetRegistry::default())?
            .utxos()
            .next()
            .is_none()
    );
    let change = only_note(
        &local_a,
        &tagged_transactions(&client, &address_a, send_slot)?,
        SHIELD - SEND,
    )?;
    assert_eq!(change.tx_signature, send_sig);
    assert_ne!(change.nullifier, note.nullifier);

    let nullifier = NullifierKey::from_secret(gateway.decrypt(&b, Vec::new())?.nullifier_secret);
    assert_eq!(nullifier.pubkey()?, address_b.nullifier_pubkey);
    let remote_b = RecipientKeys {
        gateway: &gateway,
        owner: &b,
        address: address_b,
        nullifier,
        last_item: RefCell::new(None),
    };
    let incoming = only_note(&remote_b, &received, SEND)?;
    assert_eq!(incoming.tx_signature, send_sig);
    assert_eq!(incoming.slot, send_slot);
    assert_chain_commitment(&client, &address_b, &incoming)?;
    println!("B recovered the on-chain note through Gatekeeper");

    let item = remote_b
        .last_item
        .borrow_mut()
        .take()
        .context("B did not request decryption")?;
    gateway.check_authorization(&b, &a, &item)?;
    let b_plain = gateway.check_replay(&b, item.clone())?;
    let a_plain = gateway.decrypt(&a, vec![item])?;
    assert_ne!(
        b_plain.plaintexts, a_plain.plaintexts,
        "A's service key must not recover B's plaintext"
    );

    let output = &mut received[0].output_slots[incoming.slot_index as usize];
    output.output_context.hash[0] ^= 1;
    assert!(
        decrypt_spendable(&remote_b, &received, &AssetRegistry::default())?
            .utxos()
            .next()
            .is_none(),
        "wrong commitment credited B"
    );
    assert_unregistered(&client, &b)?;
    Ok(())
}

fn helius_url(path: &str, api_key: &str) -> Result<Url> {
    let mut url = Url::parse(DEVNET)?.join(path)?;
    url.query_pairs_mut().append_pair("api-key", api_key);
    Ok(url)
}

fn local_keys(owner: &Keypair) -> Result<ShieldedKeypair> {
    Ok(ShieldedKeypair::from_keypair(
        SigningKey::from_ed25519_bytes(owner.secret_bytes()),
    )?)
}

fn assert_unregistered(client: &Client, owner: &Keypair) -> Result<()> {
    ensure!(
        try_resolve_registered_address(client.rpc(), owner.pubkey())?.is_none(),
        "unexpected registry record for {}",
        owner.pubkey()
    );
    Ok(())
}

fn landed_slot(client: &Client, signature: Signature) -> Result<u64> {
    let statuses = client.get_signature_statuses(vec![signature])?;
    let status = statuses
        .first()
        .and_then(Option::as_ref)
        .context("no status for confirmed transaction")?;
    ensure!(status.status.is_ok(), "transaction {signature} failed");
    Ok(status.slot)
}

fn tagged_transactions(
    client: &Client,
    address: &ShieldedAddress,
    slot: u64,
) -> Result<Vec<ShieldedTransaction>> {
    Ok(client
        .get_shielded_transactions_by_tags(
            vec![address.confidential_view_tag()?],
            None,
            Some(20),
            HistoryFilters::default(),
            Some(IndexerRpcConfig::at_slot(slot)),
        )?
        .data
        .into_iter()
        .flat_map(|item| item.events)
        .collect())
}

fn only_note(
    keys: &impl ShieldedKeys,
    txs: &[ShieldedTransaction],
    amount: u64,
) -> Result<WalletUtxo> {
    let results = decrypt_spendable(keys, txs, &AssetRegistry::default())?;
    let notes: Vec<_> = results.utxos().collect();
    ensure!(
        notes.len() == 1,
        "expected one spendable note, got {}",
        notes.len()
    );
    let note = notes[0];
    assert_eq!(note.utxo.asset, spr_transaction::Mint::SOL);
    assert_eq!(note.utxo.amount, amount);
    Ok(note.clone())
}

fn assert_chain_commitment(
    client: &Client,
    address: &ShieldedAddress,
    note: &WalletUtxo,
) -> Result<()> {
    let groups = client
        .rpc()
        .fetch_confirmed_instruction_groups(&note.tx_signature)?;
    let instruction = groups
        .groups
        .iter()
        .map(|group| &group.outer)
        .find(|ix| {
            ix.program_id.to_bytes() == SHIELDED_POOL_PROGRAM_ID
                && ix.data.first() == Some(&tag::TRANSACT)
        })
        .context("confirmed transfer has no shielded-pool instruction")?;
    let data = TransactIxData::deserialize(&instruction.data[1..])
        .map_err(|error| anyhow!("decode confirmed transfer: {error:?}"))?;
    assert_eq!(
        data.outputs[note.slot_index as usize].utxo_hash,
        note.utxo_hash
    );
    assert!(client
        .rpc()
        .transact_output_view_tags_from_signature(&note.tx_signature)?
        .contains(&address.confidential_view_tag()?));
    Ok(())
}

struct RecipientKeys<'a> {
    gateway: &'a Gateway<'a>,
    owner: &'a Keypair,
    address: ShieldedAddress,
    nullifier: NullifierKey,
    last_item: RefCell<Option<DecryptItem>>,
}

impl ShieldedKeys for RecipientKeys<'_> {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        Ok(self.address)
    }

    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
        vec![self.address.viewing_pubkey]
    }

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        let items = requests.iter().map(decrypt_item).collect::<Vec<_>>();
        self.last_item.replace(items.first().cloned());
        let mut result = self
            .gateway
            .decrypt(self.owner, items)
            .map_err(|error| TransactionError::Authority(error.to_string()))?;
        let key = NullifierKey::from_secret(result.nullifier_secret);
        if key.pubkey()? != self.address.nullifier_pubkey {
            return Err(TransactionError::Authority(
                "service returned a different nullifier key".into(),
            ));
        }
        Ok(std::mem::take(&mut result.plaintexts))
    }

    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        requests
            .iter()
            .map(|request| match request {
                DeriveRequest::Nullifier {
                    utxo_hash,
                    blinding,
                } => Ok(self.nullifier.nullifier(utxo_hash, blinding)?),
                _ => Err(TransactionError::Authority(
                    "expected note nullifier derivation".into(),
                )),
            })
            .collect()
    }

    fn transaction_keys(
        &self,
        _: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        Err(TransactionError::Authority(
            "receiving does not derive transaction keys".into(),
        ))
    }
}

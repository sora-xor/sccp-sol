use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::program_pack::Pack;
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction, system_program, sysvar,
    transaction::{Transaction, TransactionError},
    transport::TransportError,
};
use spl_token::state::Account as TokenAccount;

use std::sync::OnceLock;
use tokio::sync::Mutex;

use sccp_sol::{
    burn_message_id, BurnPayloadV1, SCCP_DOMAIN_ETH, SCCP_DOMAIN_SOL, SCCP_DOMAIN_SORA,
};
use sccp_sol_program::{process_instruction, BurnRecord, Config, SccpError, SccpInstruction};
use sccp_sol_verifier_program::{
    process_instruction as verifier_process_instruction, Commitment as VerifierCommitment,
    MmrLeaf as VerifierMmrLeaf, MmrProof as VerifierMmrProof, SoraBurnProofV1,
    ValidatorProof as VerifierValidatorProof, ValidatorSet as VerifierValidatorSet, VerifierError,
    VerifierInstruction,
};

use libsecp256k1::{sign, Message, PublicKey, SecretKey};
use tiny_keccak::{Hasher, Keccak};

const SEED_PREFIX: &[u8] = b"sccp";
const SEED_VERIFIER: &[u8] = b"verifier";
const SEED_CONFIG: &[u8] = b"config";
const SEED_TOKEN: &[u8] = b"token";
const SEED_MINT: &[u8] = b"mint";
const SEED_BURN: &[u8] = b"burn";
const SEED_INBOUND: &[u8] = b"inbound";

// `solana-program-test` can be flaky under parallel test execution (shared global resources).
// Run these integration tests serially to keep CI/dev runs stable.
static PROGRAM_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

async fn program_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    PROGRAM_TEST_LOCK.get_or_init(|| Mutex::new(())).lock().await
}

fn config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_PREFIX, SEED_CONFIG], program_id)
}

fn verifier_config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_PREFIX, SEED_VERIFIER, SEED_CONFIG], program_id)
}

fn token_config_pda(program_id: &Pubkey, sora_asset_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_PREFIX, SEED_TOKEN, sora_asset_id], program_id)
}

fn mint_pda(program_id: &Pubkey, sora_asset_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_PREFIX, SEED_MINT, sora_asset_id], program_id)
}

fn burn_record_pda(program_id: &Pubkey, message_id: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_PREFIX, SEED_BURN, message_id], program_id)
}

fn inbound_marker_pda(
    program_id: &Pubkey,
    source_domain: u32,
    message_id: &[u8; 32],
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            SEED_PREFIX,
            SEED_INBOUND,
            &source_domain.to_le_bytes(),
            message_id,
        ],
        program_id,
    )
}

fn expect_custom(err: TransportError, code: u32) {
    match err {
        TransportError::TransactionError(TransactionError::InstructionError(
            _,
            InstructionError::Custom(got),
        )) => assert_eq!(got, code),
        other => panic!("unexpected error: {other:?}"),
    }
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

const SECP256K1N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn sub_be_32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    // Returns a - b for 256-bit big-endian numbers; assumes a >= b.
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let ai = a[i] as i16;
        let bi = b[i] as i16;
        let mut v = ai - bi - borrow;
        if v < 0 {
            v += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = v as u8;
    }
    out
}

fn eth_address_from_secret(sk: &SecretKey) -> ([u8; 20], [u8; 64]) {
    let pk = PublicKey::from_secret_key(sk);
    let uncompressed = pk.serialize(); // 65 bytes, 0x04 || x || y
    let mut pubkey64 = [0u8; 64];
    pubkey64.copy_from_slice(&uncompressed[1..65]);

    let h = keccak256(&pubkey64);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..32]);
    (addr, pubkey64)
}

fn merkle_layers(mut leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    let mut layers = Vec::new();
    layers.push(leaves.clone());
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        let mut i = 0usize;
        while i < leaves.len() {
            let a = leaves[i];
            let b = if i + 1 < leaves.len() {
                Some(leaves[i + 1])
            } else {
                None
            };
            if let Some(b) = b {
                let mut combined = [0u8; 64];
                // Substrate `binary_merkle_tree`: ordered hashing (no sorting).
                combined[0..32].copy_from_slice(&a);
                combined[32..64].copy_from_slice(&b);
                next.push(keccak256(&combined));
            } else {
                next.push(a); // promote odd leaf
            }
            i += 2;
        }
        layers.push(next.clone());
        leaves = next;
    }
    layers
}

fn merkle_proof(layers: &[Vec<[u8; 32]>], mut idx: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();
    for level in 0..layers.len().saturating_sub(1) {
        let layer = &layers[level];
        let sib = if (idx % 2) == 1 { idx - 1 } else { idx + 1 };
        if sib < layer.len() {
            proof.push(layer[sib]);
        }
        idx /= 2;
    }
    proof
}

fn hash_commitment(c: &VerifierCommitment) -> [u8; 32] {
    let mut out = [0u8; 48];
    out[0] = 0x04; // compact(vec len=1)
    out[1] = b'm';
    out[2] = b'h';
    out[3] = 0x80; // compact(vec<u8> len=32)
    out[4..36].copy_from_slice(&c.mmr_root);
    out[36..40].copy_from_slice(&c.block_number.to_le_bytes());
    out[40..48].copy_from_slice(&c.validator_set_id.to_le_bytes());
    keccak256(&out)
}

fn hash_leaf(leaf: &VerifierMmrLeaf) -> [u8; 32] {
    let mut out = [0u8; 145];
    out[0] = leaf.version;
    out[1..5].copy_from_slice(&leaf.parent_number.to_le_bytes());
    out[5..37].copy_from_slice(&leaf.parent_hash);
    out[37..45].copy_from_slice(&leaf.next_authority_set_id.to_le_bytes());
    out[45..49].copy_from_slice(&leaf.next_authority_set_len.to_le_bytes());
    out[49..81].copy_from_slice(&leaf.next_authority_set_root);
    out[81..113].copy_from_slice(&leaf.random_seed);
    out[113..145].copy_from_slice(&leaf.digest_hash);
    keccak256(&out)
}

#[tokio::test]
async fn solana_verifier_rejects_duplicate_validator_keys() {
    let test_lock = program_test_lock().await;
    let verifier_program_id = Pubkey::new_unique();
    let pt = ProgramTest::new(
        "sccp_sol_verifier_program",
        verifier_program_id,
        processor!(verifier_process_instruction),
    );
    let (mut banks_client, payer, _recent_blockhash) = pt.start().await;

    let (verifier_config, _verifier_config_bump) = verifier_config_pda(&verifier_program_id);

    // Initialize the verifier light client.
    let validator_sks: Vec<SecretKey> = vec![
        SecretKey::parse(&[1u8; 32]).unwrap(),
        SecretKey::parse(&[2u8; 32]).unwrap(),
        SecretKey::parse(&[3u8; 32]).unwrap(),
        SecretKey::parse(&[4u8; 32]).unwrap(),
    ];
    let mut validator_addrs: Vec<[u8; 20]> = Vec::new();
    let mut validator_leaf_hashes: Vec<[u8; 32]> = Vec::new();
    for sk in validator_sks.iter() {
        let (addr, _pk64) = eth_address_from_secret(sk);
        validator_addrs.push(addr);
        validator_leaf_hashes.push(keccak256(&addr)); // leaf hash = keccak(address20)
    }
    let validator_layers = merkle_layers(validator_leaf_hashes);
    let vset_root = validator_layers.last().unwrap()[0];
    let current_vset = VerifierValidatorSet {
        id: 1,
        len: 4,
        root: vset_root,
    };
    let next_vset = VerifierValidatorSet {
        id: 2,
        len: 4,
        root: vset_root,
    };
    {
        let ix = Instruction {
            program_id: verifier_program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(verifier_config, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: VerifierInstruction::Initialize {
                governor: payer.pubkey(),
                latest_beefy_block: 0,
                current_validator_set: current_vset,
                next_validator_set: next_vset,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // Build a minimal commitment where MMR root == leaf hash (single-leaf proof).
    let leaf = VerifierMmrLeaf {
        version: 0,
        parent_number: 123,
        parent_hash: [0x55u8; 32],
        next_authority_set_id: next_vset.id,
        next_authority_set_len: next_vset.len,
        next_authority_set_root: vset_root,
        random_seed: [0x66u8; 32],
        digest_hash: [0x77u8; 32],
    };
    let leaf_hash = hash_leaf(&leaf);
    let commitment = VerifierCommitment {
        mmr_root: leaf_hash,
        block_number: 1,
        validator_set_id: current_vset.id,
    };
    let commitment_hash = hash_commitment(&commitment);
    let msg = Message::parse(&commitment_hash);

    // Duplicate validator key should be rejected even when positions are unique.
    let (sig, recid) = sign(&msg, &validator_sks[0]);
    let mut sig65 = Vec::with_capacity(65);
    sig65.extend_from_slice(&sig.serialize());
    sig65.push(recid.serialize());

    let validator_proof = VerifierValidatorProof {
        signatures: vec![sig65.clone(), sig65.clone(), sig65],
        positions: vec![0, 1, 2],
        public_keys: vec![validator_addrs[0], validator_addrs[0], validator_addrs[0]],
        public_key_merkle_proofs: vec![
            merkle_proof(&validator_layers, 0),
            merkle_proof(&validator_layers, 0),
            merkle_proof(&validator_layers, 0),
        ],
    };
    let mmr_proof = VerifierMmrProof {
        leaf_index: 0,
        leaf_count: 1,
        items: vec![],
    };
    {
        let ix = Instruction {
            program_id: verifier_program_id,
            accounts: vec![AccountMeta::new(verifier_config, false)],
            data: VerifierInstruction::SubmitSignatureCommitment {
                commitment,
                validator_proof,
                latest_mmr_leaf: leaf,
                proof: mmr_proof,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(err.into(), VerifierError::InvalidValidatorProof as u32);
    }

    drop(test_lock);
}

#[tokio::test]
async fn solana_verifier_rejects_insufficient_signatures() {
    let test_lock = program_test_lock().await;
    let verifier_program_id = Pubkey::new_unique();
    let pt = ProgramTest::new(
        "sccp_sol_verifier_program",
        verifier_program_id,
        processor!(verifier_process_instruction),
    );
    let (mut banks_client, payer, _recent_blockhash) = pt.start().await;

    let (verifier_config, _verifier_config_bump) = verifier_config_pda(&verifier_program_id);

    // Initialize the verifier light client.
    let validator_sks: Vec<SecretKey> = vec![
        SecretKey::parse(&[1u8; 32]).unwrap(),
        SecretKey::parse(&[2u8; 32]).unwrap(),
        SecretKey::parse(&[3u8; 32]).unwrap(),
        SecretKey::parse(&[4u8; 32]).unwrap(),
    ];
    let mut validator_addrs: Vec<[u8; 20]> = Vec::new();
    let mut validator_leaf_hashes: Vec<[u8; 32]> = Vec::new();
    for sk in validator_sks.iter() {
        let (addr, _pk64) = eth_address_from_secret(sk);
        validator_addrs.push(addr);
        validator_leaf_hashes.push(keccak256(&addr)); // leaf hash = keccak(address20)
    }
    let validator_layers = merkle_layers(validator_leaf_hashes);
    let vset_root = validator_layers.last().unwrap()[0];
    let current_vset = VerifierValidatorSet {
        id: 1,
        len: 4,
        root: vset_root,
    };
    let next_vset = VerifierValidatorSet {
        id: 2,
        len: 4,
        root: vset_root,
    };
    {
        let ix = Instruction {
            program_id: verifier_program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(verifier_config, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: VerifierInstruction::Initialize {
                governor: payer.pubkey(),
                latest_beefy_block: 0,
                current_validator_set: current_vset,
                next_validator_set: next_vset,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // Build a minimal commitment where MMR root == leaf hash (single-leaf proof).
    let leaf = VerifierMmrLeaf {
        version: 0,
        parent_number: 123,
        parent_hash: [0x55u8; 32],
        next_authority_set_id: next_vset.id,
        next_authority_set_len: next_vset.len,
        next_authority_set_root: vset_root,
        random_seed: [0x66u8; 32],
        digest_hash: [0x77u8; 32],
    };
    let leaf_hash = hash_leaf(&leaf);
    let commitment = VerifierCommitment {
        mmr_root: leaf_hash,
        block_number: 1,
        validator_set_id: current_vset.id,
    };
    let commitment_hash = hash_commitment(&commitment);
    let msg = Message::parse(&commitment_hash);

    // Threshold for 4 validators is 3; submit only 2 signatures.
    let mut sigs: Vec<Vec<u8>> = Vec::new();
    let mut positions: Vec<u64> = Vec::new();
    let mut pub_keys: Vec<[u8; 20]> = Vec::new();
    let mut merkle_proofs: Vec<Vec<[u8; 32]>> = Vec::new();
    for i in 0..2 {
        let (sig, recid) = sign(&msg, &validator_sks[i]);
        let mut sig65 = Vec::with_capacity(65);
        sig65.extend_from_slice(&sig.serialize());
        sig65.push(recid.serialize());
        sigs.push(sig65);
        positions.push(i as u64);
        pub_keys.push(validator_addrs[i]);
        merkle_proofs.push(merkle_proof(&validator_layers, i));
    }
    let validator_proof = VerifierValidatorProof {
        signatures: sigs,
        positions,
        public_keys: pub_keys,
        public_key_merkle_proofs: merkle_proofs,
    };
    let mmr_proof = VerifierMmrProof {
        leaf_index: 0,
        leaf_count: 1,
        items: vec![],
    };
    {
        let ix = Instruction {
            program_id: verifier_program_id,
            accounts: vec![AccountMeta::new(verifier_config, false)],
            data: VerifierInstruction::SubmitSignatureCommitment {
                commitment,
                validator_proof,
                latest_mmr_leaf: leaf,
                proof: mmr_proof,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(
            err.into(),
            VerifierError::NotEnoughValidatorSignatures as u32,
        );
    }

    drop(test_lock);
}

#[tokio::test]
async fn solana_verifier_rejects_unsupported_source_domain_in_burn_proof_path() {
    let test_lock = program_test_lock().await;
    let verifier_program_id = Pubkey::new_unique();
    let pt = ProgramTest::new(
        "sccp_sol_verifier_program",
        verifier_program_id,
        processor!(verifier_process_instruction),
    );
    let (mut banks_client, payer, _recent_blockhash) = pt.start().await;

    let (verifier_config, _verifier_config_bump) = verifier_config_pda(&verifier_program_id);

    // Minimal initialize for verifier config.
    {
        let empty_set = VerifierValidatorSet {
            id: 1,
            len: 1,
            root: [0u8; 32],
        };
        let next_set = VerifierValidatorSet {
            id: 2,
            len: 1,
            root: [0u8; 32],
        };
        let ix = Instruction {
            program_id: verifier_program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(verifier_config, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: VerifierInstruction::Initialize {
                governor: payer.pubkey(),
                latest_beefy_block: 0,
                current_validator_set: empty_set,
                next_validator_set: next_set,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // Build VerifyBurnProof raw payload:
    // [1-byte tag=1] [u32 source_domain] [message_id] [97-byte payload] [proof_bytes...]
    let payload = BurnPayloadV1 {
        version: 1,
        source_domain: 99, // unsupported domain
        dest_domain: SCCP_DOMAIN_SOL,
        nonce: 1,
        sora_asset_id: [0x11u8; 32],
        amount: 1u128,
        recipient: [0x22u8; 32],
    };
    let payload_bytes = payload.encode_scale();
    let message_id = burn_message_id(&payload_bytes);

    let mut data = Vec::with_capacity(1 + 4 + 32 + BurnPayloadV1::ENCODED_LEN);
    data.push(1u8);
    data.extend_from_slice(&99u32.to_le_bytes());
    data.extend_from_slice(&message_id);
    data.extend_from_slice(&payload_bytes);

    let ix = Instruction {
        program_id: verifier_program_id,
        accounts: vec![AccountMeta::new(verifier_config, false)],
        data,
    };
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        banks_client.get_latest_blockhash().await.unwrap(),
    );
    let err = banks_client.process_transaction(tx).await.unwrap_err();
    expect_custom(err.into(), VerifierError::SourceDomainUnsupported as u32);

    drop(test_lock);
}

#[tokio::test]
async fn solana_verifier_rejects_malleable_high_s_signatures() {
    let test_lock = program_test_lock().await;
    let verifier_program_id = Pubkey::new_unique();
    let pt = ProgramTest::new(
        "sccp_sol_verifier_program",
        verifier_program_id,
        processor!(verifier_process_instruction),
    );
    let (mut banks_client, payer, _recent_blockhash) = pt.start().await;

    let (verifier_config, _verifier_config_bump) = verifier_config_pda(&verifier_program_id);

    // Initialize verifier.
    let validator_sks: Vec<SecretKey> = vec![
        SecretKey::parse(&[1u8; 32]).unwrap(),
        SecretKey::parse(&[2u8; 32]).unwrap(),
        SecretKey::parse(&[3u8; 32]).unwrap(),
        SecretKey::parse(&[4u8; 32]).unwrap(),
    ];
    let mut validator_addrs: Vec<[u8; 20]> = Vec::new();
    let mut validator_leaf_hashes: Vec<[u8; 32]> = Vec::new();
    for sk in validator_sks.iter() {
        let (addr, _pk64) = eth_address_from_secret(sk);
        validator_addrs.push(addr);
        validator_leaf_hashes.push(keccak256(&addr));
    }
    let validator_layers = merkle_layers(validator_leaf_hashes);
    let vset_root = validator_layers.last().unwrap()[0];
    let current_vset = VerifierValidatorSet {
        id: 1,
        len: 4,
        root: vset_root,
    };
    let next_vset = VerifierValidatorSet {
        id: 2,
        len: 4,
        root: vset_root,
    };
    {
        let ix = Instruction {
            program_id: verifier_program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(verifier_config, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: VerifierInstruction::Initialize {
                governor: payer.pubkey(),
                latest_beefy_block: 0,
                current_validator_set: current_vset,
                next_validator_set: next_vset,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // Build a minimal commitment where MMR root == leaf hash (single-leaf proof).
    let leaf = VerifierMmrLeaf {
        version: 0,
        parent_number: 123,
        parent_hash: [0x55u8; 32],
        next_authority_set_id: next_vset.id,
        next_authority_set_len: next_vset.len,
        next_authority_set_root: vset_root,
        random_seed: [0x66u8; 32],
        digest_hash: [0x77u8; 32],
    };
    let leaf_hash = hash_leaf(&leaf);
    let commitment = VerifierCommitment {
        mmr_root: leaf_hash,
        block_number: 1,
        validator_set_id: current_vset.id,
    };
    let commitment_hash = hash_commitment(&commitment);
    let msg = Message::parse(&commitment_hash);

    // Build one high-s malleable signature and two regular ones.
    let (sig0, recid0) = sign(&msg, &validator_sks[0]);
    let sig0raw = sig0.serialize();
    let mut s0 = [0u8; 32];
    s0.copy_from_slice(&sig0raw[32..64]);
    let high_s0 = sub_be_32(SECP256K1N, s0);
    let mut sig0_high = vec![0u8; 65];
    sig0_high[0..32].copy_from_slice(&sig0raw[0..32]);
    sig0_high[32..64].copy_from_slice(&high_s0);
    sig0_high[64] = recid0.serialize() ^ 1; // malleated recovery id

    let mut sigs: Vec<Vec<u8>> = vec![sig0_high];
    let mut positions: Vec<u64> = vec![0];
    let mut pub_keys: Vec<[u8; 20]> = vec![validator_addrs[0]];
    let mut merkle_proofs: Vec<Vec<[u8; 32]>> = vec![merkle_proof(&validator_layers, 0)];
    for i in 1..=2 {
        let (sig, recid) = sign(&msg, &validator_sks[i]);
        let mut sig65 = Vec::with_capacity(65);
        sig65.extend_from_slice(&sig.serialize());
        sig65.push(recid.serialize());
        sigs.push(sig65);
        positions.push(i as u64);
        pub_keys.push(validator_addrs[i]);
        merkle_proofs.push(merkle_proof(&validator_layers, i));
    }
    let validator_proof = VerifierValidatorProof {
        signatures: sigs,
        positions,
        public_keys: pub_keys,
        public_key_merkle_proofs: merkle_proofs,
    };
    let mmr_proof = VerifierMmrProof {
        leaf_index: 0,
        leaf_count: 1,
        items: vec![],
    };
    {
        let ix = Instruction {
            program_id: verifier_program_id,
            accounts: vec![AccountMeta::new(verifier_config, false)],
            data: VerifierInstruction::SubmitSignatureCommitment {
                commitment,
                validator_proof,
                latest_mmr_leaf: leaf,
                proof: mmr_proof,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(err.into(), VerifierError::InvalidSignature as u32);
    }

    drop(test_lock);
}

#[tokio::test]
async fn solana_program_flow_burn_and_mint_with_incident_controls() {
    let test_lock = program_test_lock().await;
    let program_id = Pubkey::new_unique();
    let verifier_program_id = Pubkey::new_unique();

    let mut pt = ProgramTest::new(
        "sccp_sol_program",
        program_id,
        processor!(process_instruction),
    );
    pt.add_program(
        "spl_token",
        spl_token::id(),
        processor!(spl_token::processor::Processor::process),
    );
    pt.add_program(
        "sccp_sol_verifier_program",
        verifier_program_id,
        processor!(verifier_process_instruction),
    );

    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (config, _config_bump) = config_pda(&program_id);
    let (verifier_config, _verifier_config_bump) = verifier_config_pda(&verifier_program_id);

    // Initialize.
    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: SccpInstruction::Initialize {
                governor: payer.pubkey(),
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // Set verifier program (governor-only).
    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
            ],
            data: SccpInstruction::SetVerifierProgram {
                verifier_program: verifier_program_id,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // Initialize the verifier light client (bootstrap with a synthetic validator set).
    // In production, this must be bootstrapped from SORA chain state (validator sets + latest beefy block).
    let validator_sks: Vec<SecretKey> = vec![
        SecretKey::parse(&[1u8; 32]).unwrap(),
        SecretKey::parse(&[2u8; 32]).unwrap(),
        SecretKey::parse(&[3u8; 32]).unwrap(),
        SecretKey::parse(&[4u8; 32]).unwrap(),
    ];
    let mut validator_addrs: Vec<[u8; 20]> = Vec::new();
    let mut validator_leaf_hashes: Vec<[u8; 32]> = Vec::new();
    for sk in validator_sks.iter() {
        let (addr, _pk64) = eth_address_from_secret(sk);
        validator_addrs.push(addr);
        validator_leaf_hashes.push(keccak256(&addr)); // leaf hash = keccak(address20)
    }
    let validator_layers = merkle_layers(validator_leaf_hashes);
    let vset_root = validator_layers.last().unwrap()[0];
    let current_vset = VerifierValidatorSet {
        id: 1,
        len: 4,
        root: vset_root,
    };
    let next_vset = VerifierValidatorSet {
        id: 2,
        len: 4,
        root: vset_root,
    };
    {
        let ix = Instruction {
            program_id: verifier_program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(verifier_config, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: VerifierInstruction::Initialize {
                governor: payer.pubkey(),
                latest_beefy_block: 0,
                current_validator_set: current_vset,
                next_validator_set: next_vset,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // Deploy token (mint PDA + token config PDA).
    let sora_asset_id = [0x11u8; 32];
    let (token_cfg, _token_cfg_bump) = token_config_pda(&program_id, &sora_asset_id);
    let (mint, _mint_bump) = mint_pda(&program_id, &sora_asset_id);
    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(token_cfg, false),
                AccountMeta::new(mint, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(sysvar::rent::id(), false),
            ],
            data: SccpInstruction::DeployToken {
                sora_asset_id,
                decimals: 6,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // Create recipient wallet + token account.
    let alice = Keypair::new();
    let alice_token = Keypair::new();
    {
        let rent = banks_client.get_rent().await.unwrap();
        let lamports = rent.minimum_balance(TokenAccount::LEN);
        let create_ix = system_instruction::create_account(
            &payer.pubkey(),
            &alice_token.pubkey(),
            lamports,
            TokenAccount::LEN as u64,
            &spl_token::id(),
        );
        let init_ix = spl_token::instruction::initialize_account(
            &spl_token::id(),
            &alice_token.pubkey(),
            &mint,
            &alice.pubkey(),
        )
        .unwrap();
        let tx = Transaction::new_signed_with_payer(
            &[create_ix, init_ix],
            Some(&payer.pubkey()),
            &[&payer, &alice_token],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // MintFromProof (verified by on-chain SORA BEEFY+MMR light client):
    // - SORA -> SOL
    // - ETH -> SOL (attested/finalized by SORA and committed in its digest)
    let mint_amount: u64 = 100;
    let mint_amount_eth: u64 = 7;

    let inbound_payload_sora = BurnPayloadV1 {
        version: 1,
        source_domain: SCCP_DOMAIN_SORA,
        dest_domain: SCCP_DOMAIN_SOL,
        nonce: 1,
        sora_asset_id,
        amount: mint_amount as u128,
        recipient: alice.pubkey().to_bytes(),
    };
    let inbound_payload_sora_bytes = inbound_payload_sora.encode_scale();
    let inbound_message_id_sora = burn_message_id(&inbound_payload_sora_bytes);
    let (marker_sora, _marker_sora_bump) =
        inbound_marker_pda(&program_id, SCCP_DOMAIN_SORA, &inbound_message_id_sora);

    let inbound_payload_eth = BurnPayloadV1 {
        version: 1,
        source_domain: SCCP_DOMAIN_ETH,
        dest_domain: SCCP_DOMAIN_SOL,
        nonce: 2,
        sora_asset_id,
        amount: mint_amount_eth as u128,
        recipient: alice.pubkey().to_bytes(),
    };
    let inbound_payload_eth_bytes = inbound_payload_eth.encode_scale();
    let inbound_message_id_eth = burn_message_id(&inbound_payload_eth_bytes);
    let (marker_eth, _marker_eth_bump) =
        inbound_marker_pda(&program_id, SCCP_DOMAIN_ETH, &inbound_message_id_eth);

    // Import a synthetic "finalized" MMR root into verifier state, then construct the proof bytes.
    let mut digest_scale: Vec<u8> = Vec::with_capacity(1 + 2 * (7 + 32));
    // SCALE(Vec<AuxiliaryDigestItem>) with 2 items:
    // compact(len=2)=0x08 | item1 | item2
    digest_scale.push(0x08);
    for msg_id in [&inbound_message_id_sora, &inbound_message_id_eth] {
        // Commitment(0) | GenericNetworkId::EVMLegacy(2) | u32('SCCP') LE | message_id (H256)
        digest_scale.extend_from_slice(&[0x00, 0x02, 0x50, 0x43, 0x43, 0x53]);
        digest_scale.extend_from_slice(msg_id);
    }
    let digest_hash = keccak256(&digest_scale);

    let leaf = VerifierMmrLeaf {
        version: 0,
        parent_number: 123,
        parent_hash: [0x55u8; 32],
        next_authority_set_id: next_vset.id,
        next_authority_set_len: next_vset.len,
        next_authority_set_root: vset_root,
        random_seed: [0x66u8; 32],
        digest_hash,
    };
    let leaf_hash = hash_leaf(&leaf);
    let commitment = VerifierCommitment {
        mmr_root: leaf_hash,
        block_number: 1,
        validator_set_id: current_vset.id,
    };
    let commitment_hash = hash_commitment(&commitment);
    let msg = Message::parse(&commitment_hash);

    let mut sigs: Vec<Vec<u8>> = Vec::new();
    let mut positions: Vec<u64> = Vec::new();
    let mut pub_keys: Vec<[u8; 20]> = Vec::new();
    let mut merkle_proofs: Vec<Vec<[u8; 32]>> = Vec::new();
    for i in 0..3 {
        let (sig, recid) = sign(&msg, &validator_sks[i]);
        let mut sig65 = Vec::with_capacity(65);
        sig65.extend_from_slice(&sig.serialize());
        sig65.push(recid.serialize());
        sigs.push(sig65);
        positions.push(i as u64);
        pub_keys.push(validator_addrs[i]);
        merkle_proofs.push(merkle_proof(&validator_layers, i));
    }
    let validator_proof = VerifierValidatorProof {
        signatures: sigs,
        positions,
        public_keys: pub_keys,
        public_key_merkle_proofs: merkle_proofs,
    };
    let mmr_proof = VerifierMmrProof {
        leaf_index: 0,
        leaf_count: 1,
        items: vec![],
    };
    {
        let ix = Instruction {
            program_id: verifier_program_id,
            accounts: vec![AccountMeta::new(verifier_config, false)],
            data: VerifierInstruction::SubmitSignatureCommitment {
                commitment,
                validator_proof: validator_proof.clone(),
                latest_mmr_leaf: leaf,
                proof: mmr_proof.clone(),
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    let burn_proof_bytes = SoraBurnProofV1 {
        mmr_proof,
        leaf,
        digest_scale,
    }
    .try_to_vec()
    .unwrap();

    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(token_cfg, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(alice_token.pubkey(), false),
                AccountMeta::new(marker_sora, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(verifier_program_id, false),
                AccountMeta::new_readonly(verifier_config, false),
            ],
            data: SccpInstruction::MintFromProof {
                source_domain: SCCP_DOMAIN_SORA,
                payload: inbound_payload_sora_bytes.to_vec(),
                proof: burn_proof_bytes.clone(),
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // ETH -> SOL (attested by SORA).
    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(token_cfg, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(alice_token.pubkey(), false),
                AccountMeta::new(marker_eth, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(verifier_program_id, false),
                AccountMeta::new_readonly(verifier_config, false),
            ],
            data: SccpInstruction::MintFromProof {
                source_domain: SCCP_DOMAIN_ETH,
                payload: inbound_payload_eth_bytes.to_vec(),
                proof: burn_proof_bytes,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        banks_client.process_transaction(tx).await.unwrap();
    }
    {
        let acct = banks_client
            .get_account(alice_token.pubkey())
            .await
            .unwrap()
            .unwrap();
        let ta = TokenAccount::unpack(&acct.data).unwrap();
        assert_eq!(ta.amount, mint_amount + mint_amount_eth);
        assert_eq!(ta.owner, alice.pubkey());
        assert_eq!(ta.mint, mint);
    }

    // Unsupported source domain must fail-closed in mint path.
    {
        let unsupported_source_domain: u32 = 99;
        let (unsupported_marker, _unsupported_marker_bump) =
            inbound_marker_pda(&program_id, unsupported_source_domain, &inbound_message_id_sora);
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(token_cfg, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(alice_token.pubkey(), false),
                AccountMeta::new(unsupported_marker, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(verifier_program_id, false),
                AccountMeta::new_readonly(verifier_config, false),
            ],
            data: SccpInstruction::MintFromProof {
                source_domain: unsupported_source_domain,
                payload: inbound_payload_sora_bytes.to_vec(),
                proof: vec![],
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(err.into(), SccpError::DomainUnsupported as u32);
    }

    // Governance pause controls must reject unsupported domain ids.
    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
            ],
            data: SccpInstruction::SetInboundDomainPaused {
                source_domain: 99,
                paused: true,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(err.into(), SccpError::DomainUnsupported as u32);
    }
    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
            ],
            data: SccpInstruction::SetOutboundDomainPaused {
                dest_domain: 99,
                paused: true,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(err.into(), SccpError::DomainUnsupported as u32);
    }

    // Unsupported burn destination domain must fail-closed.
    {
        let unsupported_burn_rec = burn_record_pda(&program_id, &[0xBBu8; 32]).0;
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(alice.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(token_cfg, false),
                AccountMeta::new(alice_token.pubkey(), false),
                AccountMeta::new(mint, false),
                AccountMeta::new(unsupported_burn_rec, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data: SccpInstruction::Burn {
                sora_asset_id,
                amount: 1,
                dest_domain: 99,
                recipient: [0x22u8; 32],
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer, &alice],
            recent_blockhash,
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(err.into(), SccpError::DomainUnsupported as u32);
    }

    // Burn to an EVM domain must enforce canonical recipient encoding (high 12 bytes must be zero).
    {
        let burn_amount: u64 = 1;
        let mut bad_recipient = [0u8; 32];
        bad_recipient[0] = 1; // non-zero high bytes => non-canonical EVM encoding

        let dummy_burn_rec = burn_record_pda(&program_id, &[0xAAu8; 32]).0;
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(alice.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(token_cfg, false),
                AccountMeta::new(alice_token.pubkey(), false),
                AccountMeta::new(mint, false),
                AccountMeta::new(dummy_burn_rec, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data: SccpInstruction::Burn {
                sora_asset_id,
                amount: burn_amount,
                dest_domain: SCCP_DOMAIN_ETH,
                recipient: bad_recipient,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer, &alice],
            recent_blockhash,
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(err.into(), SccpError::RecipientNotCanonical as u32);
    }

    // Replay must fail: InboundAlreadyProcessed.
    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(token_cfg, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(alice_token.pubkey(), false),
                AccountMeta::new(marker_sora, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(verifier_program_id, false),
                AccountMeta::new_readonly(verifier_config, false),
            ],
            data: SccpInstruction::MintFromProof {
                source_domain: SCCP_DOMAIN_SORA,
                payload: inbound_payload_sora_bytes.to_vec(),
                proof: vec![],
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(err.into(), SccpError::InboundAlreadyProcessed as u32);
    }

    // Invalidate a different messageId (ETH -> SOL), then mint must fail: ProofInvalidated.
    let inv_payload = BurnPayloadV1 {
        version: 1,
        source_domain: SCCP_DOMAIN_ETH,
        dest_domain: SCCP_DOMAIN_SOL,
        nonce: 2,
        sora_asset_id,
        amount: 1u128,
        recipient: alice.pubkey().to_bytes(),
    };
    let inv_payload_bytes = inv_payload.encode_scale();
    let inv_message_id = burn_message_id(&inv_payload_bytes);
    let (inv_marker, _inv_marker_bump) =
        inbound_marker_pda(&program_id, SCCP_DOMAIN_ETH, &inv_message_id);
    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(inv_marker, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: SccpInstruction::InvalidateInboundMessage {
                source_domain: SCCP_DOMAIN_ETH,
                message_id: inv_message_id,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();
    }
    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(token_cfg, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(alice_token.pubkey(), false),
                AccountMeta::new(inv_marker, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(verifier_program_id, false),
                AccountMeta::new_readonly(verifier_config, false),
            ],
            data: SccpInstruction::MintFromProof {
                source_domain: SCCP_DOMAIN_ETH,
                payload: inv_payload_bytes.to_vec(),
                proof: vec![],
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(err.into(), SccpError::ProofInvalidated as u32);
    }

    // Pause inbound from SORA; mint must fail: InboundDomainPaused.
    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
            ],
            data: SccpInstruction::SetInboundDomainPaused {
                source_domain: SCCP_DOMAIN_SORA,
                paused: true,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();
    }
    {
        let fresh_payload = BurnPayloadV1 {
            version: 1,
            source_domain: SCCP_DOMAIN_SORA,
            dest_domain: SCCP_DOMAIN_SOL,
            nonce: 3,
            sora_asset_id,
            amount: 1u128,
            recipient: alice.pubkey().to_bytes(),
        };
        let fresh_payload_bytes = fresh_payload.encode_scale();
        let fresh_message_id = burn_message_id(&fresh_payload_bytes);
        let (fresh_marker, _fresh_marker_bump) =
            inbound_marker_pda(&program_id, SCCP_DOMAIN_SORA, &fresh_message_id);
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(token_cfg, false),
                AccountMeta::new(mint, false),
                AccountMeta::new(alice_token.pubkey(), false),
                AccountMeta::new(fresh_marker, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new_readonly(verifier_program_id, false),
                AccountMeta::new_readonly(verifier_config, false),
            ],
            data: SccpInstruction::MintFromProof {
                source_domain: SCCP_DOMAIN_SORA,
                payload: fresh_payload_bytes.to_vec(),
                proof: vec![],
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(err.into(), SccpError::InboundDomainPaused as u32);
    }

    // Burn SOL -> SORA: creates burn record PDA keyed by messageId.
    let burn_amount: u64 = 10;
    let recipient_on_sora = [0x22u8; 32];

    // Fund alice so she can pay rent for the burn record PDA creation (burn uses `user` as payer).
    {
        let ix = system_instruction::transfer(&payer.pubkey(), &alice.pubkey(), 1_000_000_000);
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    // Read outbound nonce before burn (should start at 0 and become 1 after burn).
    let cfg_before = banks_client.get_account(config).await.unwrap().unwrap();
    let cfg_before = Config::try_from_slice(&cfg_before.data).unwrap();
    assert_eq!(cfg_before.outbound_nonce, 0);

    let burn_payload = BurnPayloadV1 {
        version: 1,
        source_domain: SCCP_DOMAIN_SOL,
        dest_domain: SCCP_DOMAIN_SORA,
        nonce: 1, // cfg.outbound_nonce increments from 0 -> 1
        sora_asset_id,
        amount: burn_amount as u128,
        recipient: recipient_on_sora,
    };
    let burn_payload_bytes = burn_payload.encode_scale();
    let burn_message_id = burn_message_id(&burn_payload_bytes);
    let (burn_rec, _burn_rec_bump) = burn_record_pda(&program_id, &burn_message_id);

    // Outbound pause (to SORA) must block burns and must not increment the outbound nonce.
    {
        // Pause outbound to SORA (governor-only).
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
            ],
            data: SccpInstruction::SetOutboundDomainPaused {
                dest_domain: SCCP_DOMAIN_SORA,
                paused: true,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks_client.process_transaction(tx).await.unwrap();

        // Attempt burn (SOL -> SORA) must fail.
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(alice.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(token_cfg, false),
                AccountMeta::new(alice_token.pubkey(), false),
                AccountMeta::new(mint, false),
                AccountMeta::new(burn_rec, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data: SccpInstruction::Burn {
                sora_asset_id,
                amount: burn_amount,
                dest_domain: SCCP_DOMAIN_SORA,
                recipient: recipient_on_sora,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer, &alice],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        let err = banks_client.process_transaction(tx).await.unwrap_err();
        expect_custom(err.into(), SccpError::OutboundDomainPaused as u32);

        // Balance unchanged.
        let acct = banks_client
            .get_account(alice_token.pubkey())
            .await
            .unwrap()
            .unwrap();
        let ta = TokenAccount::unpack(&acct.data).unwrap();
        assert_eq!(ta.amount, mint_amount + mint_amount_eth);

        // Nonce unchanged, pause bit set.
        let cfg_mid = banks_client.get_account(config).await.unwrap().unwrap();
        let cfg_mid = Config::try_from_slice(&cfg_mid.data).unwrap();
        assert_eq!(cfg_mid.outbound_nonce, 0);
        assert_eq!(cfg_mid.outbound_paused_mask, 1);

        // Unpause.
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(config, false),
            ],
            data: SccpInstruction::SetOutboundDomainPaused {
                dest_domain: SCCP_DOMAIN_SORA,
                paused: false,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        banks_client.process_transaction(tx).await.unwrap();

        // Pause bit cleared.
        let cfg_after = banks_client.get_account(config).await.unwrap().unwrap();
        let cfg_after = Config::try_from_slice(&cfg_after.data).unwrap();
        assert_eq!(cfg_after.outbound_paused_mask, 0);
    }

    // Outbound pause should now be cleared.
    {
        let cfg = banks_client.get_account(config).await.unwrap().unwrap();
        let cfg = Config::try_from_slice(&cfg.data).unwrap();
        assert_eq!(cfg.outbound_paused_mask, 0);
    }

    {
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(alice.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new(token_cfg, false),
                AccountMeta::new(alice_token.pubkey(), false),
                AccountMeta::new(mint, false),
                AccountMeta::new(burn_rec, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data: SccpInstruction::Burn {
                sora_asset_id,
                amount: burn_amount,
                dest_domain: SCCP_DOMAIN_SORA,
                recipient: recipient_on_sora,
            }
            .try_to_vec()
            .unwrap(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer, &alice],
            banks_client.get_latest_blockhash().await.unwrap(),
        );
        banks_client.process_transaction(tx).await.unwrap();
    }

    {
        let acct = banks_client
            .get_account(alice_token.pubkey())
            .await
            .unwrap()
            .unwrap();
        let ta = TokenAccount::unpack(&acct.data).unwrap();
        assert_eq!(ta.amount, mint_amount + mint_amount_eth - burn_amount);
    }

    // Burn record exists and matches expected message id.
    {
        let rec_acc = banks_client.get_account(burn_rec).await.unwrap().unwrap();
        let rec = BurnRecord::try_from_slice(&rec_acc.data).unwrap();
        assert_eq!(rec.message_id, burn_message_id);
        assert_eq!(rec.payload, burn_payload_bytes);
        assert_eq!(rec.sender, alice.pubkey());
        assert_eq!(rec.mint, mint);
        assert_eq!(rec.version, 1);
    }

    // Config outbound nonce updated.
    {
        let cfg_after = banks_client.get_account(config).await.unwrap().unwrap();
        let cfg_after = Config::try_from_slice(&cfg_after.data).unwrap();
        assert_eq!(cfg_after.outbound_nonce, 1);
    }

    drop(test_lock);
}

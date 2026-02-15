#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

extern crate alloc;

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program::{invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction,
    sysvar::{rent::Rent, Sysvar},
};

use solana_program::keccak::hashv as keccak_hashv;
use solana_program::secp256k1_recover::secp256k1_recover;

use sccp_sol::{
    burn_message_id, decode_burn_payload_v1, BurnPayloadV1, H256, SCCP_DOMAIN_BSC,
    SCCP_DOMAIN_ETH, SCCP_DOMAIN_SOL, SCCP_DOMAIN_SORA, SCCP_DOMAIN_TON, SCCP_DOMAIN_TRON,
};

const SEED_PREFIX: &[u8] = b"sccp";
const SEED_VERIFIER: &[u8] = b"verifier";
const SEED_CONFIG: &[u8] = b"config";

const ACCOUNT_VERSION_V1: u8 = 1;

const MMR_ROOT_HISTORY_SIZE: usize = 30;
const SECP256K1N_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

// Leaf provider digest commitment network id sentinel (matches SORA pallet `SCCP_DIGEST_NETWORK_ID`).
const SCCP_DIGEST_NETWORK_ID: u32 = 0x5343_4350; // 'SCCP'

// SCALE enum discriminants (bridge-types v1.0.27):
const AUX_DIGEST_ITEM_COMMITMENT: u8 = 0;
const GENERIC_NETWORK_ID_EVM: u8 = 0;
const GENERIC_NETWORK_ID_SUB: u8 = 1;
const GENERIC_NETWORK_ID_EVM_LEGACY: u8 = 2;
const GENERIC_NETWORK_ID_TON: u8 = 3;

#[repr(u32)]
pub enum VerifierError {
    InvalidInstructionData = 1,
    AlreadyInitialized = 2,
    InvalidPda = 3,
    InvalidOwner = 4,
    InvalidAccountSize = 5,
    NotGovernor = 6,
    ConfigNotInitialized = 7,
    PayloadInvalidLength = 8,
    ProofTooLarge = 9,
    SourceDomainUnsupported = 10,
    UnknownMmrRoot = 11,
    InvalidDigestHash = 12,
    CommitmentNotFoundInDigest = 13,
    InvalidValidatorSetId = 14,
    PayloadBlocknumberTooOld = 15,
    NotEnoughValidatorSignatures = 16,
    InvalidValidatorProof = 17,
    InvalidSignature = 18,
    InvalidMerkleProof = 19,
    InvalidMmrProof = 20,
}

impl From<VerifierError> for ProgramError {
    fn from(e: VerifierError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    pub id: u64,
    pub len: u32,
    pub root: [u8; 32],
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub mmr_root: [u8; 32],
    pub block_number: u32,
    pub validator_set_id: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ValidatorProof {
    pub signatures: Vec<Vec<u8>>, // 65 bytes each
    pub positions: Vec<u64>, // not used for membership, but checked for bounds/uniqueness
    pub public_keys: Vec<[u8; 20]>, // Ethereum addresses
    pub public_key_merkle_proofs: Vec<Vec<[u8; 32]>>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct MmrProof {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub items: Vec<[u8; 32]>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmrLeaf {
    pub version: u8,
    pub parent_number: u32,
    pub parent_hash: [u8; 32],
    pub next_authority_set_id: u64,
    pub next_authority_set_len: u32,
    pub next_authority_set_root: [u8; 32],
    pub random_seed: [u8; 32],
    pub digest_hash: [u8; 32],
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SoraBurnProofV1 {
    pub mmr_proof: MmrProof,
    pub leaf: MmrLeaf,
    pub digest_scale: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub version: u8,
    pub bump: u8,
    pub governor: Pubkey,
    pub latest_beefy_block: u64,
    pub current_validator_set: ValidatorSet,
    pub next_validator_set: ValidatorSet,
    pub mmr_roots_pos: u32,
    pub mmr_roots: [[u8; 32]; MMR_ROOT_HISTORY_SIZE],
}

impl Config {
    // 1 + 1 + 32 + 8 + (8+4+32)*2 + 4 + 30*32
    pub const LEN: usize = 1094;
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum VerifierInstruction {
    /// Create config PDA and set initial validator sets (governor-signed).
    Initialize {
        governor: Pubkey,
        latest_beefy_block: u64,
        current_validator_set: ValidatorSet,
        next_validator_set: ValidatorSet,
    },
    /// Reserved discriminator; `VerifyBurnProof` is parsed from raw bytes produced by SCCP router CPI.
    VerifyBurnProof,
    /// Import a new finalized MMR root by verifying a BEEFY commitment + signatures (permissionless).
    SubmitSignatureCommitment {
        commitment: Commitment,
        validator_proof: ValidatorProof,
        latest_mmr_leaf: MmrLeaf,
        proof: MmrProof,
    },
    /// Governor rotation (governor-signed).
    SetGovernor { governor: Pubkey },
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(VerifierError::InvalidInstructionData.into());
    }

    // `VerifyBurnProof` is invoked by the SCCP router CPI using a custom byte layout (not Borsh).
    if instruction_data[0] == 1u8 {
        return verify_burn_proof(program_id, accounts, instruction_data);
    }

    let ix = VerifierInstruction::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::from(VerifierError::InvalidInstructionData))?;

    match ix {
        VerifierInstruction::Initialize {
            governor,
            latest_beefy_block,
            current_validator_set,
            next_validator_set,
        } => initialize(
            program_id,
            accounts,
            governor,
            latest_beefy_block,
            current_validator_set,
            next_validator_set,
        ),
        VerifierInstruction::SubmitSignatureCommitment {
            commitment,
            validator_proof,
            latest_mmr_leaf,
            proof,
        } => submit_signature_commitment(
            program_id,
            accounts,
            commitment,
            validator_proof,
            latest_mmr_leaf,
            proof,
        ),
        VerifierInstruction::SetGovernor { governor } => set_governor(program_id, accounts, governor),
        VerifierInstruction::VerifyBurnProof => Err(VerifierError::InvalidInstructionData.into()),
    }
}

fn initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    governor: Pubkey,
    latest_beefy_block: u64,
    current_validator_set: ValidatorSet,
    next_validator_set: ValidatorSet,
) -> ProgramResult {
    let mut it = accounts.iter();
    let payer = next_account_info(&mut it)?;
    let config_acc = next_account_info(&mut it)?;
    let system_program = next_account_info(&mut it)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *system_program.key != solana_program::system_program::id() {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (expected, bump) = config_pda(program_id);
    if *config_acc.key != expected {
        return Err(VerifierError::InvalidPda.into());
    }

    // Refuse re-init if already owned by this program.
    if config_acc.owner == program_id {
        return Err(VerifierError::AlreadyInitialized.into());
    }

    create_pda_account(
        payer,
        config_acc,
        Config::LEN,
        program_id,
        &[SEED_PREFIX, SEED_VERIFIER, SEED_CONFIG, &[bump]],
    )?;

    let cfg = Config {
        version: ACCOUNT_VERSION_V1,
        bump,
        governor,
        latest_beefy_block,
        current_validator_set,
        next_validator_set,
        mmr_roots_pos: 0,
        mmr_roots: [[0u8; 32]; MMR_ROOT_HISTORY_SIZE],
    };
    write_borsh::<Config>(config_acc, &cfg)?;
    Ok(())
}

fn set_governor(program_id: &Pubkey, accounts: &[AccountInfo], governor: Pubkey) -> ProgramResult {
    let mut it = accounts.iter();
    let signer = next_account_info(&mut it)?;
    let config_acc = next_account_info(&mut it)?;

    let mut cfg = load_config(program_id, config_acc)?;
    ensure_governor(signer, &cfg)?;
    cfg.governor = governor;
    write_borsh::<Config>(config_acc, &cfg)?;
    Ok(())
}

fn submit_signature_commitment(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    commitment: Commitment,
    validator_proof: ValidatorProof,
    latest_mmr_leaf: MmrLeaf,
    proof: MmrProof,
) -> ProgramResult {
    let mut it = accounts.iter();
    let config_acc = next_account_info(&mut it)?;

    let mut cfg = load_config(program_id, config_acc)?;

    // Basic freshness check (fail fast).
    if (commitment.block_number as u64) <= cfg.latest_beefy_block {
        return Err(VerifierError::PayloadBlocknumberTooOld.into());
    }

    let vset = if commitment.validator_set_id == cfg.current_validator_set.id {
        cfg.current_validator_set
    } else if commitment.validator_set_id == cfg.next_validator_set.id {
        cfg.next_validator_set
    } else {
        return Err(VerifierError::InvalidValidatorSetId.into());
    };

    verify_commitment_signatures(&commitment, &validator_proof, vset)?;

    // Verify the provided MMR leaf is included under the payload root.
    let leaf_hash = hash_leaf(&latest_mmr_leaf);
    let root = mmr_proof_root(leaf_hash, &proof).map_err(|_| ProgramError::from(VerifierError::InvalidMmrProof))?;
    if root != commitment.mmr_root {
        return Err(VerifierError::InvalidMmrProof.into());
    }

    add_known_mmr_root(&mut cfg, commitment.mmr_root);
    cfg.latest_beefy_block = commitment.block_number as u64;

    // Apply validator set changes (if any) from the leaf.
    let new_vset = ValidatorSet {
        id: latest_mmr_leaf.next_authority_set_id,
        len: latest_mmr_leaf.next_authority_set_len,
        root: latest_mmr_leaf.next_authority_set_root,
    };
    if new_vset.id > cfg.next_validator_set.id {
        cfg.current_validator_set = cfg.next_validator_set;
        cfg.next_validator_set = new_vset;
    }

    write_borsh::<Config>(config_acc, &cfg)?;
    Ok(())
}

fn verify_burn_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Layout (produced by SCCP router CPI):
    // 1 byte version (1)
    // u32 source_domain LE
    // [32] message_id
    // payload (97 bytes)
    // proof (rest)
    if data.len() < 1 + 4 + 32 + BurnPayloadV1::ENCODED_LEN {
        return Err(VerifierError::InvalidInstructionData.into());
    }

    let mut it = accounts.iter();
    let config_acc = next_account_info(&mut it)?;
    let cfg = load_config(program_id, config_acc)?;

    // The first u32 is the burn origin domain.
    // This verifier only supports SCCP-known domains and rejects local SOL-as-source loopbacks.
    let source_domain = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let supported = matches!(
        source_domain,
        SCCP_DOMAIN_SORA | SCCP_DOMAIN_ETH | SCCP_DOMAIN_BSC | SCCP_DOMAIN_TON | SCCP_DOMAIN_TRON
    );
    if !supported || source_domain == SCCP_DOMAIN_SOL {
        return Err(VerifierError::SourceDomainUnsupported.into());
    }

    let message_id: H256 = data[5..37]
        .try_into()
        .map_err(|_| VerifierError::InvalidInstructionData)?;
    let payload = &data[37..37 + BurnPayloadV1::ENCODED_LEN];

    // Ensure payload matches message_id (fail closed).
    let computed = burn_message_id(payload);
    if computed != message_id {
        return Err(VerifierError::InvalidInstructionData.into());
    }

    // Ensure payload has the expected version.
    let p = decode_burn_payload_v1(payload).map_err(|_| ProgramError::from(VerifierError::PayloadInvalidLength))?;
    if p.version != 1 {
        return Err(VerifierError::PayloadInvalidLength.into());
    }
    // The caller-provided source domain must match payload source domain.
    if p.source_domain != source_domain {
        return Err(VerifierError::InvalidInstructionData.into());
    }
    // This verifier is for minting on Solana only.
    if p.dest_domain != SCCP_DOMAIN_SOL {
        return Err(VerifierError::InvalidInstructionData.into());
    }

    let proof_bytes = &data[37 + BurnPayloadV1::ENCODED_LEN..];
    if proof_bytes.len() > 16 * 1024 {
        return Err(VerifierError::ProofTooLarge.into());
    }
    let proof = SoraBurnProofV1::try_from_slice(proof_bytes)
        .map_err(|_| ProgramError::from(VerifierError::InvalidInstructionData))?;
    if proof.mmr_proof.items.len() >= 64 {
        return Err(VerifierError::InvalidMmrProof.into());
    }

    let leaf_hash = hash_leaf(&proof.leaf);
    let root =
        mmr_proof_root(leaf_hash, &proof.mmr_proof).map_err(|_| ProgramError::from(VerifierError::InvalidMmrProof))?;
    if !is_known_root(&cfg, &root) {
        return Err(VerifierError::UnknownMmrRoot.into());
    }

    let digest_hash = keccak256(&proof.digest_scale);
    if digest_hash != proof.leaf.digest_hash {
        return Err(VerifierError::InvalidDigestHash.into());
    }

    if !digest_has_sccp_commitment(&proof.digest_scale, &message_id) {
        return Err(VerifierError::CommitmentNotFoundInDigest.into());
    }

    Ok(())
}

fn config_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_PREFIX, SEED_VERIFIER, SEED_CONFIG], program_id)
}

fn load_config(program_id: &Pubkey, acc: &AccountInfo) -> Result<Config, ProgramError> {
    let (expected, _bump) = config_pda(program_id);
    if *acc.key != expected {
        return Err(VerifierError::InvalidPda.into());
    }
    if acc.owner != program_id {
        return Err(VerifierError::ConfigNotInitialized.into());
    }
    read_borsh::<Config>(acc)
}

fn ensure_governor(signer: &AccountInfo, cfg: &Config) -> Result<(), ProgramError> {
    if !signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *signer.key != cfg.governor {
        return Err(VerifierError::NotGovernor.into());
    }
    Ok(())
}

fn add_known_mmr_root(cfg: &mut Config, root: [u8; 32]) {
    // A small fixed ring buffer; O(30) scan is cheap.
    if is_known_root(cfg, &root) {
        return;
    }
    let pos = (cfg.mmr_roots_pos as usize) % MMR_ROOT_HISTORY_SIZE;
    cfg.mmr_roots[pos] = root;
    cfg.mmr_roots_pos = ((pos + 1) % MMR_ROOT_HISTORY_SIZE) as u32;
}

fn is_known_root(cfg: &Config, root: &[u8; 32]) -> bool {
    cfg.mmr_roots.iter().any(|x| x == root)
}

fn verify_commitment_signatures(
    commitment: &Commitment,
    proof: &ValidatorProof,
    vset: ValidatorSet,
) -> Result<(), ProgramError> {
    let num = vset.len as usize;
    let threshold = vset.len - (vset.len.saturating_sub(1) / 3); // >=2/3

    let n = proof.signatures.len();
    if proof.positions.len() != n || proof.public_keys.len() != n || proof.public_key_merkle_proofs.len() != n {
        return Err(VerifierError::InvalidValidatorProof.into());
    }
    if n < threshold as usize {
        return Err(VerifierError::NotEnoughValidatorSignatures.into());
    }

    // Ensure unique positions and unique public keys.
    let mut seen_pos = vec![false; num];
    for i in 0..n {
        let pos = proof.positions[i] as usize;
        if pos >= num {
            return Err(VerifierError::InvalidValidatorProof.into());
        }
        if seen_pos[pos] {
            return Err(VerifierError::InvalidValidatorProof.into());
        }
        seen_pos[pos] = true;

        for j in 0..i {
            if proof.public_keys[j] == proof.public_keys[i] {
                return Err(VerifierError::InvalidValidatorProof.into());
            }
        }
    }

    let commitment_hash = hash_commitment(commitment);

    for i in 0..n {
        let addr = proof.public_keys[i];

        // Membership proof against the validator set root.
        let pos = proof.positions[i];
        if !verify_beefy_merkle_proof(vset.root, vset.len, pos, &addr, &proof.public_key_merkle_proofs[i]) {
            return Err(VerifierError::InvalidMerkleProof.into());
        }

        // Signature check against commitment hash.
        let sig = &proof.signatures[i];
        if sig.len() != 65 {
            return Err(VerifierError::InvalidSignature.into());
        }
        let (sig64, rec_id) = parse_eth_signature(sig)?;
        let pk = secp256k1_recover(&commitment_hash, rec_id, &sig64)
            .map_err(|_| ProgramError::from(VerifierError::InvalidSignature))?;
        let recovered = eth_address_from_pubkey(&pk.to_bytes());
        if recovered != addr {
            return Err(VerifierError::InvalidSignature.into());
        }
    }

    Ok(())
}

fn parse_eth_signature(sig65: &[u8]) -> Result<([u8; 64], u8), ProgramError> {
    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(&sig65[0..64]);

    let mut r = [0u8; 32];
    r.copy_from_slice(&sig64[0..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig64[32..64]);

    // Reject malleable / invalid ECDSA signatures (EIP-2 style).
    if r == [0u8; 32] || s == [0u8; 32] || s > SECP256K1N_HALF_ORDER {
        return Err(VerifierError::InvalidSignature.into());
    }

    let mut v = sig65[64];
    if v >= 27 {
        v = v.wrapping_sub(27);
    }
    if v > 3 {
        return Err(VerifierError::InvalidSignature.into());
    }
    Ok((sig64, v))
}

fn eth_address_from_pubkey(pubkey64: &[u8; 64]) -> [u8; 20] {
    let h = keccak256(pubkey64);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[12..32]);
    out
}

fn verify_beefy_merkle_proof(
    root: [u8; 32],
    set_len: u32,
    pos: u64,
    addr20: &[u8; 20],
    proof: &Vec<[u8; 32]>,
) -> bool {
    // Substrate `binary_merkle_tree` (ordered, no sorting):
    // - leafHash = keccak256(leaf_bytes) where leaf_bytes = bytes20(address)
    // - internal: keccak256(left || right)
    // - if odd number of nodes: last node is promoted
    if pos >= set_len as u64 {
        return false;
    }

    let mut current = keccak256(addr20);
    let mut idx = pos;
    let mut n = set_len as u64;
    let mut used: usize = 0;

    while n > 1 {
        let is_right = (idx & 1) == 1;
        if is_right {
            if used >= proof.len() {
                return false;
            }
            let sibling = proof[used];
            used += 1;
            let mut combined = [0u8; 64];
            combined[0..32].copy_from_slice(&sibling);
            combined[32..64].copy_from_slice(&current);
            current = keccak256(&combined);
        } else {
            // If this is the last odd node, it is promoted without hashing.
            if idx != n.saturating_sub(1) {
                if used >= proof.len() {
                    return false;
                }
                let sibling = proof[used];
                used += 1;
                let mut combined = [0u8; 64];
                combined[0..32].copy_from_slice(&current);
                combined[32..64].copy_from_slice(&sibling);
                current = keccak256(&combined);
            }
        }
        idx >>= 1;
        n = (n + 1) / 2;
    }

    used == proof.len() && current == root
}

fn hash_commitment(c: &Commitment) -> [u8; 32] {
    // SCALE(sp_beefy::Commitment<u32>) with payload restricted to one entry:
    // "mh" -> Vec<u8> of length 32 (mmr_root bytes).
    //
    // Layout (48 bytes):
    // [0] compact(vec len=1)=0x04
    // [1..3] "mh"
    // [3] compact(vec<u8> len=32)=0x80
    // [4..36] mmr_root
    // [36..40] u32 block_number (LE)
    // [40..48] u64 validator_set_id (LE)
    let mut out = [0u8; 48];
    out[0] = 0x04;
    out[1] = b'm';
    out[2] = b'h';
    out[3] = 0x80;
    out[4..36].copy_from_slice(&c.mmr_root);
    out[36..40].copy_from_slice(&c.block_number.to_le_bytes());
    out[40..48].copy_from_slice(&c.validator_set_id.to_le_bytes());
    keccak256(&out)
}

fn hash_leaf(leaf: &MmrLeaf) -> [u8; 32] {
    let scale = encode_leaf_scale(leaf);
    keccak256(&scale)
}

fn encode_leaf_scale(leaf: &MmrLeaf) -> [u8; 145] {
    // SCALE(sp_beefy::mmr::MmrLeaf<u32, H256, H256, LeafExtraData<H256,H256>>)
    // (fixed-width encoding):
    // version:u8
    // parent_number:u32 (LE)
    // parent_hash:[32]
    // next_authority_set_id:u64 (LE)
    // next_authority_set_len:u32 (LE)
    // next_authority_set_root:[32]
    // random_seed:[32]
    // digest_hash:[32]
    let mut out = [0u8; 145];
    out[0] = leaf.version;
    out[1..5].copy_from_slice(&leaf.parent_number.to_le_bytes());
    out[5..37].copy_from_slice(&leaf.parent_hash);
    out[37..45].copy_from_slice(&leaf.next_authority_set_id.to_le_bytes());
    out[45..49].copy_from_slice(&leaf.next_authority_set_len.to_le_bytes());
    out[49..81].copy_from_slice(&leaf.next_authority_set_root);
    out[81..113].copy_from_slice(&leaf.random_seed);
    out[113..145].copy_from_slice(&leaf.digest_hash);
    out
}

fn mmr_proof_root(leaf_hash: [u8; 32], proof: &MmrProof) -> Result<[u8; 32], VerifierError> {
    if proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count {
        return Err(VerifierError::InvalidMmrProof);
    }

    let mmr_size = leaf_index_to_mmr_size(proof.leaf_count - 1);
    let leaf_pos = leaf_index_to_pos(proof.leaf_index);

    let peaks = get_peaks(mmr_size);
    let mut peaks_hashes: Vec<[u8; 32]> = Vec::with_capacity(peaks.len() + 1);

    let mut proof_idx: usize = 0;
    let mut leaf_used = false;
    for peak_pos in peaks.into_iter() {
        if !leaf_used && leaf_pos <= peak_pos {
            let peak_root = if leaf_pos == peak_pos {
                leaf_hash
            } else {
                let (r, next) =
                    calculate_peak_root_single(leaf_pos, leaf_hash, peak_pos, &proof.items, proof_idx)?;
                proof_idx = next;
                r
            };
            leaf_used = true;
            peaks_hashes.push(peak_root);
        } else {
            // No leaf for this peak: proof carries the peak hash, or a bagged RHS peaks hash.
            if proof_idx < proof.items.len() {
                peaks_hashes.push(proof.items[proof_idx]);
                proof_idx += 1;
            } else {
                break;
            }
        }
    }

    if !leaf_used {
        return Err(VerifierError::InvalidMmrProof);
    }

    // Optional bagged RHS peaks hash (see `ckb-merkle-mountain-range` proof generation).
    if proof_idx < proof.items.len() {
        peaks_hashes.push(proof.items[proof_idx]);
        proof_idx += 1;
    }
    if proof_idx != proof.items.len() || peaks_hashes.is_empty() {
        return Err(VerifierError::InvalidMmrProof);
    }

    // Bag peaks right-to-left via hash(right, left).
    while peaks_hashes.len() > 1 {
        let right = peaks_hashes.pop().ok_or(VerifierError::InvalidMmrProof)?;
        let left = peaks_hashes.pop().ok_or(VerifierError::InvalidMmrProof)?;
        peaks_hashes.push(keccak256_two(right, left));
    }
    peaks_hashes.pop().ok_or(VerifierError::InvalidMmrProof)
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    keccak_hashv(&[data]).0
}

fn keccak256_two(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[0..32].copy_from_slice(&a);
    combined[32..64].copy_from_slice(&b);
    keccak256(&combined)
}

// --- MMR helpers (ported from `ckb-merkle-mountain-range`) ---

fn leaf_index_to_pos(index: u64) -> u64 {
    leaf_index_to_mmr_size(index) - ((index + 1).trailing_zeros() as u64) - 1
}

fn leaf_index_to_mmr_size(index: u64) -> u64 {
    let leaves_count = index + 1;
    let peak_count = leaves_count.count_ones() as u64;
    2 * leaves_count - peak_count
}

fn pos_height_in_tree(mut pos: u64) -> u32 {
    pos += 1;
    fn all_ones(num: u64) -> bool {
        num != 0 && num.count_zeros() == num.leading_zeros()
    }
    fn jump_left(pos: u64) -> u64 {
        let bit_length = 64 - pos.leading_zeros();
        let most_significant_bits = 1 << (bit_length - 1);
        pos - (most_significant_bits - 1)
    }

    while !all_ones(pos) {
        pos = jump_left(pos)
    }

    64 - pos.leading_zeros() - 1
}

fn parent_offset(height: u32) -> u64 {
    2u64 << height
}

fn sibling_offset(height: u32) -> u64 {
    (2u64 << height) - 1
}

fn get_peaks(mmr_size: u64) -> Vec<u64> {
    let mut pos_s = Vec::new();
    let (mut height, mut pos) = left_peak_height_pos(mmr_size);
    pos_s.push(pos);
    while height > 0 {
        let peak = match get_right_peak(height, pos, mmr_size) {
            Some(peak) => peak,
            None => break,
        };
        height = peak.0;
        pos = peak.1;
        pos_s.push(pos);
    }
    pos_s
}

fn get_right_peak(mut height: u32, mut pos: u64, mmr_size: u64) -> Option<(u32, u64)> {
    // move to right sibling pos
    pos += sibling_offset(height);
    // loop until we find a pos in mmr
    while pos > mmr_size - 1 {
        if height == 0 {
            return None;
        }
        // move to left child
        pos -= parent_offset(height - 1);
        height -= 1;
    }
    Some((height, pos))
}

fn get_peak_pos_by_height(height: u32) -> u64 {
    (1u64 << (height + 1)) - 2
}

fn left_peak_height_pos(mmr_size: u64) -> (u32, u64) {
    let mut height = 1;
    let mut prev_pos = 0;
    let mut pos = get_peak_pos_by_height(height);
    while pos < mmr_size {
        height += 1;
        prev_pos = pos;
        pos = get_peak_pos_by_height(height);
    }
    (height - 1, prev_pos)
}

fn calculate_peak_root_single(
    mut pos: u64,
    mut item: [u8; 32],
    peak_pos: u64,
    proof_items: &[[u8; 32]],
    mut proof_idx: usize,
) -> Result<([u8; 32], usize), VerifierError> {
    let mut height: u32 = 0;
    loop {
        if pos == peak_pos {
            return Ok((item, proof_idx));
        }

        let next_height = pos_height_in_tree(pos + 1);
        let pos_is_right = next_height > height;
        let parent_pos = if pos_is_right {
            pos + 1
        } else {
            pos + parent_offset(height)
        };

        let sibling = *proof_items.get(proof_idx).ok_or(VerifierError::InvalidMmrProof)?;
        proof_idx = proof_idx.saturating_add(1);

        let parent_item = if pos_is_right {
            keccak256_two(sibling, item)
        } else {
            keccak256_two(item, sibling)
        };

        if parent_pos > peak_pos {
            return Err(VerifierError::InvalidMmrProof);
        }

        pos = parent_pos;
        item = parent_item;
        height = height.saturating_add(1);
    }
}

fn digest_has_sccp_commitment(digest_scale: &[u8], message_id: &H256) -> bool {
    let (n, mut off) = match read_compact_u32(digest_scale, 0) {
        Some(x) => x,
        None => return false,
    };

    let mut found = 0u32;
    for _ in 0..n {
        if off >= digest_scale.len() {
            return false;
        }
        let item_kind = digest_scale[off];
        off += 1;
        if item_kind != AUX_DIGEST_ITEM_COMMITMENT {
            return false;
        }

        if off >= digest_scale.len() {
            return false;
        }
        let network_kind = digest_scale[off];
        off += 1;

        let mut network_id = u32::MAX;
        match network_kind {
            GENERIC_NETWORK_ID_EVM_LEGACY => {
                if off + 4 > digest_scale.len() {
                    return false;
                }
                network_id = u32::from_le_bytes([
                    digest_scale[off],
                    digest_scale[off + 1],
                    digest_scale[off + 2],
                    digest_scale[off + 3],
                ]);
                off += 4;
            }
            GENERIC_NETWORK_ID_EVM => {
                // EVMChainId = H256 (32 bytes)
                if off + 32 > digest_scale.len() {
                    return false;
                }
                off += 32;
            }
            GENERIC_NETWORK_ID_SUB => {
                // SubNetworkId enum (1 byte)
                if off + 1 > digest_scale.len() {
                    return false;
                }
                off += 1;
            }
            GENERIC_NETWORK_ID_TON => {
                // TonNetworkId enum (1 byte)
                if off + 1 > digest_scale.len() {
                    return false;
                }
                off += 1;
            }
            _ => return false,
        }

        if off + 32 > digest_scale.len() {
            return false;
        }
        let item_hash: H256 = match digest_scale[off..off + 32].try_into() {
            Ok(x) => x,
            Err(_) => return false,
        };
        off += 32;

        if network_id == SCCP_DIGEST_NETWORK_ID && &item_hash == message_id {
            found = found.saturating_add(1);
        }
    }

    found == 1
}

fn read_compact_u32(data: &[u8], off: usize) -> Option<(u32, usize)> {
    if off >= data.len() {
        return None;
    }
    let b0 = data[off];
    let mode = b0 & 0x03;
    if mode == 0 {
        return Some(((b0 >> 2) as u32, off + 1));
    }
    if mode == 1 {
        if off + 2 > data.len() {
            return None;
        }
        let b1 = data[off + 1] as u32;
        let v = ((b0 as u32) >> 2) | (b1 << 6);
        return Some((v, off + 2));
    }
    if mode == 2 {
        if off + 4 > data.len() {
            return None;
        }
        let v = ((b0 as u32) >> 2)
            | ((data[off + 1] as u32) << 6)
            | ((data[off + 2] as u32) << 14)
            | ((data[off + 3] as u32) << 22);
        return Some((v, off + 4));
    }
    None // mode == 3 (big int) not supported
}

fn read_borsh<T: BorshDeserialize>(acc: &AccountInfo) -> Result<T, ProgramError> {
    T::try_from_slice(&acc.data.borrow()).map_err(|_| ProgramError::from(VerifierError::InvalidAccountSize))
}

fn write_borsh<T: BorshSerialize>(acc: &AccountInfo, v: &T) -> Result<(), ProgramError> {
    let mut data = acc.data.borrow_mut();
    v.serialize(&mut &mut data[..])
        .map_err(|_| ProgramError::from(VerifierError::InvalidAccountSize))
}

fn create_pda_account<'a>(
    payer: &AccountInfo<'a>,
    pda: &AccountInfo<'a>,
    space: usize,
    owner: &Pubkey,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    if pda.owner != &solana_program::system_program::id() {
        return Err(VerifierError::InvalidOwner.into());
    }
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(space);
    let ix = system_instruction::create_account(payer.key, pda.key, lamports, space as u64, owner);
    invoke_signed(&ix, &[payer.clone(), pda.clone()], &[signer_seeds])?;
    Ok(())
}

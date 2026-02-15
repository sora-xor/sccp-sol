# sccp-sol

SORA Cross-Chain Protocol (SCCP) code for Solana.

Current contents:
- A small Rust `no_std` crate implementing SCCP `BurnPayloadV1` SCALE encoding and `messageId`
  computation (`keccak256(b"sccp:burn:v1" || payload)`).

- A Solana program crate under `program/`:
  - governance-owned config PDA (governor, outbound nonce, inbound pause mask, verifier program id)
  - per-asset token registry PDA (`sora_asset_id -> SPL mint`)
  - `Burn` burns SPL tokens via CPI and stores an on-chain burn record PDA keyed by `messageId`
  - `MintFromProof` is implemented but **fail-closed** until a verifier program is configured
  - domain hardening: burn/mint/pause/invalidation paths reject unsupported domain IDs

## Build / Test

```bash
cargo test
```

Program tests:

```bash
cd program
cargo test
```

Current verifier coverage includes:
- positive import-root + mint proof verification flow
- duplicate validator key rejection
- insufficient-signature threshold rejection
- high-`s` ECDSA signature rejection (malleability hardening)
- unsupported/loopback source-domain rejection in verifier burn-proof path

## Non-SORA -> Solana (Via SORA Attestation)

The Solana `MintFromProof` path is not limited to burns that originated on SORA.

If SORA verifies a burn that originated on another chain (e.g., `ETH -> SOL`) and commits the burn `messageId`
into its auxiliary digest (via the SORA runtime extrinsic `sccp.attest_burn`), users can mint on Solana by
submitting:

- `source_domain = <burn origin domain>`
- `payload = SCALE(BurnPayloadV1)`
- `proof = SORA BEEFY+MMR proof that the digest commits `messageId``

## Proofs To SORA (SOL As Source Chain)

Inbound proofs from Solana to SORA are defined on SORA as:

- default mode: `SolanaLightClient` for `DOMAIN_SOL`
- semantics: burn must be included in a Solana finalized slot
- current runtime status: fail-closed on SORA until Solana finalized-slot light-client verification is integrated
- practical fallback: SORA governance can switch `DOMAIN_SOL` to `AttesterQuorum` (CCTP-style threshold signatures over `messageId`)

So this repo supports trustless SORA -> Solana mint verification today, while Solana -> SORA mint/attestation remains intentionally disabled until the SORA-side Solana light client lands.

### AttesterQuorum Proof Bytes

When SORA uses `InboundFinalityMode::AttesterQuorum`, users submit only attester signatures to SORA (no Solana light-client proof).

Signatures are over:

`attestHash = keccak256("sccp:attest:v1" || messageId)`

Proof bytes passed to `sccp.mint_from_proof` are:

`0x01 || SCALE(Vec<[u8;65]>)`

Helper (encode from collected signatures):

```bash
cargo run --bin encode_attester_quorum_proof -- --message-id 0x<messageId32> --sig 0x<sig65> --sig 0x<sig65>
```

## Proof Inputs From `bridge-relayer`

Use the sibling `bridge-relayer` repo to fetch SORA-finality proof components:

- `sccp sol init --governor-hex 0x<32-byte-pubkey-hex> --block <sora_block>`
- `sccp sol import-root --justification-block <beefy_block>`
- `sccp sol mint-proof --burn-block <burn_block> --beefy-block <beefy_block> --message-id 0x...`

`sccp sol init` outputs verifier-ready `Initialize` Borsh instruction bytes:
- `instruction_data_hex`
- `instruction_data_base64`

`sccp sol import-root` outputs verifier-ready `SubmitSignatureCommitment` Borsh instruction bytes:
- `instruction_data_hex`
- `instruction_data_base64`

This command already outputs the verifier-ready `SoraBurnProofV1` Borsh bytes:
- `borsh_proof_hex`
- `borsh_proof_base64`

The helper script is still available for re-encoding historical JSON:
- `python3 scripts/encode_sora_burn_proof.py --input ./mint-proof.json --format both`

## SORA Config Notes

On SORA (runtime pallet `sccp`), for Solana:
- `domain_endpoint` for `SCCP_DOMAIN_SOL` is 32 bytes: the SCCP Solana program id.
- `remote_token_id` for a given `asset_id` is 32 bytes: the SPL mint pubkey for that asset.

SORA token activation also requires `set_domain_endpoint(SCCP_DOMAIN_SOL, <program_id_bytes>)`.

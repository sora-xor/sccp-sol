#![no_std]

extern crate alloc;

use tiny_keccak::{Hasher, Keccak};

pub const SCCP_DOMAIN_SORA: u32 = 0;
pub const SCCP_DOMAIN_ETH: u32 = 1;
pub const SCCP_DOMAIN_BSC: u32 = 2;
pub const SCCP_DOMAIN_SOL: u32 = 3;
pub const SCCP_DOMAIN_TON: u32 = 4;
pub const SCCP_DOMAIN_TRON: u32 = 5;

pub const SCCP_MSG_PREFIX_BURN_V1: &[u8] = b"sccp:burn:v1";
pub const SCCP_MSG_PREFIX_ATTEST_V1: &[u8] = b"sccp:attest:v1";

pub type H256 = [u8; 32];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BurnPayloadV1 {
    pub version: u8,
    pub source_domain: u32,
    pub dest_domain: u32,
    pub nonce: u64,
    pub sora_asset_id: [u8; 32],
    pub amount: u128,
    pub recipient: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CodecError {
    InvalidLength,
}

impl BurnPayloadV1 {
    pub const ENCODED_LEN: usize = 97;

    /// SCALE encoding for fixed-width primitives (matches Substrate `parity-scale-codec`).
    pub fn encode_scale(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0] = self.version;
        out[1..5].copy_from_slice(&self.source_domain.to_le_bytes());
        out[5..9].copy_from_slice(&self.dest_domain.to_le_bytes());
        out[9..17].copy_from_slice(&self.nonce.to_le_bytes());
        out[17..49].copy_from_slice(&self.sora_asset_id);
        out[49..65].copy_from_slice(&self.amount.to_le_bytes());
        out[65..97].copy_from_slice(&self.recipient);
        out
    }
}

pub fn decode_burn_payload_v1(payload_scale: &[u8]) -> Result<BurnPayloadV1, CodecError> {
    if payload_scale.len() != BurnPayloadV1::ENCODED_LEN {
        return Err(CodecError::InvalidLength);
    }
    let mut b4 = [0u8; 4];
    let mut b8 = [0u8; 8];
    let mut b16 = [0u8; 16];

    b4.copy_from_slice(&payload_scale[1..5]);
    let source_domain = u32::from_le_bytes(b4);

    b4.copy_from_slice(&payload_scale[5..9]);
    let dest_domain = u32::from_le_bytes(b4);

    b8.copy_from_slice(&payload_scale[9..17]);
    let nonce = u64::from_le_bytes(b8);

    let mut sora_asset_id = [0u8; 32];
    sora_asset_id.copy_from_slice(&payload_scale[17..49]);

    b16.copy_from_slice(&payload_scale[49..65]);
    let amount = u128::from_le_bytes(b16);

    let mut recipient = [0u8; 32];
    recipient.copy_from_slice(&payload_scale[65..97]);

    Ok(BurnPayloadV1 {
        version: payload_scale[0],
        source_domain,
        dest_domain,
        nonce,
        sora_asset_id,
        amount,
        recipient,
    })
}

pub fn burn_message_id(payload_scale: &[u8]) -> H256 {
    let mut k = Keccak::v256();
    k.update(SCCP_MSG_PREFIX_BURN_V1);
    k.update(payload_scale);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

pub fn attest_hash(message_id: &H256) -> H256 {
    let mut k = Keccak::v256();
    k.update(SCCP_MSG_PREFIX_ATTEST_V1);
    k.update(message_id);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use hex::FromHex;
    use parity_scale_codec::Encode;

    #[derive(Encode)]
    struct RefPayload {
        version: u8,
        source_domain: u32,
        dest_domain: u32,
        nonce: u64,
        sora_asset_id: [u8; 32],
        amount: u128,
        recipient: [u8; 32],
    }

    #[test]
    fn manual_scale_encoding_matches_parity_scale_codec() {
        let p = BurnPayloadV1 {
            version: 1,
            source_domain: SCCP_DOMAIN_ETH,
            dest_domain: SCCP_DOMAIN_SORA,
            nonce: 777,
            sora_asset_id: [0x11u8; 32],
            amount: 10,
            recipient: [0x22u8; 32],
        };

        let manual = p.encode_scale();
        let ref_bytes = RefPayload {
            version: p.version,
            source_domain: p.source_domain,
            dest_domain: p.dest_domain,
            nonce: p.nonce,
            sora_asset_id: p.sora_asset_id,
            amount: p.amount,
            recipient: p.recipient,
        }
        .encode();

        assert_eq!(ref_bytes.len(), BurnPayloadV1::ENCODED_LEN);
        assert_eq!(manual.as_slice(), ref_bytes.as_slice());
    }

    #[test]
    fn fixtures_match_reference_vectors() {
        // Generated with a parity-scale-codec + tiny-keccak reference (see SPEC.md).
        let expected_payload = Vec::from_hex(
            "010100000000000000090300000000000011111111111111111111111111111111111111111111111111111111111111110a0000000000000000000000000000002222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let expected_message_id =
            Vec::from_hex("f3cac8c5acfb0670a24e9ffeab7e409a9d54d1dc5e6dbaf0ee986462fe1ffb3a")
                .unwrap();

        let p = BurnPayloadV1 {
            version: 1,
            source_domain: SCCP_DOMAIN_ETH,
            dest_domain: SCCP_DOMAIN_SORA,
            nonce: 777,
            sora_asset_id: [0x11u8; 32],
            amount: 10,
            recipient: [0x22u8; 32],
        };

        let payload = p.encode_scale();
        assert_eq!(payload.as_slice(), expected_payload.as_slice());

        let decoded = decode_burn_payload_v1(&payload).unwrap();
        assert_eq!(decoded, p);

        let msg_id = burn_message_id(&payload);
        assert_eq!(msg_id.as_slice(), expected_message_id.as_slice());
    }
}

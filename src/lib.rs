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
    use tiny_keccak::{Hasher, Keccak};

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

    #[test]
    fn decode_rejects_incorrect_payload_length() {
        let short = [0u8; BurnPayloadV1::ENCODED_LEN - 1];
        let long = [0u8; BurnPayloadV1::ENCODED_LEN + 1];
        assert_eq!(
            decode_burn_payload_v1(&short),
            Err(CodecError::InvalidLength)
        );
        assert_eq!(
            decode_burn_payload_v1(&long),
            Err(CodecError::InvalidLength)
        );
    }

    #[test]
    fn encode_decode_round_trip_with_extreme_values() {
        let payload = BurnPayloadV1 {
            version: 1,
            source_domain: SCCP_DOMAIN_TRON,
            dest_domain: SCCP_DOMAIN_TON,
            nonce: u64::MAX,
            sora_asset_id: [0xffu8; 32],
            amount: u128::MAX,
            recipient: [0xaau8; 32],
        };
        let encoded = payload.encode_scale();
        let decoded = decode_burn_payload_v1(&encoded).expect("payload must decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn message_id_changes_when_payload_changes() {
        let mut payload_a = BurnPayloadV1 {
            version: 1,
            source_domain: SCCP_DOMAIN_ETH,
            dest_domain: SCCP_DOMAIN_SORA,
            nonce: 1,
            sora_asset_id: [0x11u8; 32],
            amount: 10,
            recipient: [0x22u8; 32],
        };
        let message_a = burn_message_id(&payload_a.encode_scale());

        payload_a.nonce = 2;
        let message_b = burn_message_id(&payload_a.encode_scale());

        assert_ne!(message_a, message_b);
    }

    #[test]
    fn attest_hash_is_domain_separated_from_burn_prefix() {
        let payload = BurnPayloadV1 {
            version: 1,
            source_domain: SCCP_DOMAIN_ETH,
            dest_domain: SCCP_DOMAIN_SORA,
            nonce: 777,
            sora_asset_id: [0x11u8; 32],
            amount: 10,
            recipient: [0x22u8; 32],
        };
        let message_id = burn_message_id(&payload.encode_scale());
        let burn_of_message_id = burn_message_id(&message_id);
        let attested = attest_hash(&message_id);

        assert_ne!(attested, burn_of_message_id);
    }

    #[test]
    fn decode_interprets_fixed_width_fields_as_little_endian() {
        let mut payload = [0u8; BurnPayloadV1::ENCODED_LEN];
        payload[0] = 1;
        payload[1..5].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        payload[5..9].copy_from_slice(&0x5566_7788u32.to_le_bytes());
        payload[9..17].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        payload[17..49].copy_from_slice(&[0xabu8; 32]);
        payload[49..65]
            .copy_from_slice(&0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10u128.to_le_bytes());
        payload[65..97].copy_from_slice(&[0xcdu8; 32]);

        let decoded = decode_burn_payload_v1(&payload).expect("payload must decode");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.source_domain, 0x1122_3344);
        assert_eq!(decoded.dest_domain, 0x5566_7788);
        assert_eq!(decoded.nonce, 0x0102_0304_0506_0708);
        assert_eq!(decoded.sora_asset_id, [0xabu8; 32]);
        assert_eq!(
            decoded.amount,
            0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10u128
        );
        assert_eq!(decoded.recipient, [0xcdu8; 32]);
    }

    #[test]
    fn burn_message_id_is_domain_separated_from_plain_payload_hash() {
        let payload = BurnPayloadV1 {
            version: 1,
            source_domain: SCCP_DOMAIN_ETH,
            dest_domain: SCCP_DOMAIN_SORA,
            nonce: 777,
            sora_asset_id: [0x11u8; 32],
            amount: 10,
            recipient: [0x22u8; 32],
        };
        let payload_bytes = payload.encode_scale();
        let with_prefix = burn_message_id(&payload_bytes);

        let mut k = Keccak::v256();
        k.update(&payload_bytes);
        let mut plain = [0u8; 32];
        k.finalize(&mut plain);

        assert_ne!(with_prefix, plain);
    }
}

use crate::{
    helpers::{pack_fee_amount, pack_token_amount, unpack_fee_amount, unpack_token_amount},
    Exchange,
};
use crate::{AccountId, Address, Nonce, TokenId};
use anyhow::{ensure, format_err};
use serde::{Deserialize, Serialize};
use zkdpos_crypto::params::{
    ACCOUNT_ID_BIT_WIDTH, AMOUNT_EXPONENT_BIT_WIDTH, AMOUNT_MANTISSA_BIT_WIDTH, CHUNK_BYTES,
    FEE_EXPONENT_BIT_WIDTH, FEE_MANTISSA_BIT_WIDTH, TOKEN_BIT_WIDTH,
};
use zkdpos_crypto::primitives::FromBytes;

/// Exchange operation. For details, see the documentation of [`ZkDposOp`](./operations/enum.ZkDposOp.html).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeOp {
    pub tx: Exchange,
    pub from: AccountId,
    pub to: AccountId,
}

impl ExchangeOp {
    pub const CHUNKS: usize = 2;
    pub const OP_CODE: u8 = 0x05;

    pub(crate) fn get_public_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(Self::OP_CODE); // opcode
        data.extend_from_slice(&self.from.to_be_bytes());
        data.extend_from_slice(&self.tx.token_a.to_be_bytes());
        data.extend_from_slice(&self.tx.token_b.to_be_bytes());
        data.extend_from_slice(&pack_token_amount(&self.tx.amount_a));
        data.extend_from_slice(&pack_token_amount(&self.tx.amount_b));
        data.extend_from_slice(&pack_fee_amount(&self.tx.price));
        data.extend_from_slice(&pack_fee_amount(&self.tx.fee));
        data.resize(Self::CHUNKS * CHUNK_BYTES, 0x00);
        data
    }

    pub fn from_public_data(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        ensure!(
            bytes.len() == Self::CHUNKS * CHUNK_BYTES,
            "Wrong bytes length for exchange pubdata"
        );

        let from_offset = 1;
        let token_id_offset = from_offset + ACCOUNT_ID_BIT_WIDTH / 8;
        let to_offset = token_id_offset + TOKEN_BIT_WIDTH / 8;
        let amount_offset = to_offset + ACCOUNT_ID_BIT_WIDTH / 8;
        let fee_offset =
            amount_offset + (AMOUNT_EXPONENT_BIT_WIDTH + AMOUNT_MANTISSA_BIT_WIDTH) / 8;

        let from_address = Address::zero(); // From pubdata its unknown
        let token_a = u16::from_bytes(&bytes[token_id_offset..token_id_offset + TOKEN_BIT_WIDTH / 8])
            .ok_or_else(|| format_err!("Cant get token id from exchange pubdata"))?;
        let token_b = u16::from_bytes(&bytes[token_id_offset..token_id_offset + TOKEN_BIT_WIDTH / 8])
            .ok_or_else(|| format_err!("Cant get token id from exchange pubdata"))?;
        let amount_a = unpack_token_amount(
            &bytes[amount_offset
                ..amount_offset + (AMOUNT_EXPONENT_BIT_WIDTH + AMOUNT_MANTISSA_BIT_WIDTH) / 8],
        ).ok_or_else(|| format_err!("Cant get amount from exchange pubdata"))?;
        let amount_b = unpack_token_amount(
            &bytes[amount_offset
                ..amount_offset + (AMOUNT_EXPONENT_BIT_WIDTH + AMOUNT_MANTISSA_BIT_WIDTH) / 8],
        )
        .ok_or_else(|| format_err!("Cant get amount from exchange pubdata"))?;
        let price = unpack_fee_amount(
            &bytes[fee_offset..fee_offset + (FEE_EXPONENT_BIT_WIDTH + FEE_MANTISSA_BIT_WIDTH) / 8],
        )
        .ok_or_else(|| format_err!("Cant get price from exchange pubdata"))?;
        let fee = unpack_fee_amount(
            &bytes[fee_offset..fee_offset + (FEE_EXPONENT_BIT_WIDTH + FEE_MANTISSA_BIT_WIDTH) / 8],
        )
        .ok_or_else(|| format_err!("Cant get fee from exchange pubdata"))?;
        let nonce = 0; // It is unknown from pubdata
        let from_id = u32::from_bytes(&bytes[from_offset..from_offset + ACCOUNT_ID_BIT_WIDTH / 8])
            .ok_or_else(|| format_err!("Cant get from account id from exchange pubdata"))?;
        let to_id = u32::from_bytes(&bytes[to_offset..to_offset + ACCOUNT_ID_BIT_WIDTH / 8])
            .ok_or_else(|| format_err!("Cant get to account id from exchange pubdata"))?;
        let time_range = Default::default();

        Ok(Self {
            tx: Exchange::new(
                AccountId(from_id),
                from_address,
                TokenId(token_a),
                TokenId(token_b),
                amount_a,
                amount_b,
                price,
                fee,
                Nonce(nonce),
                time_range,
                None,
            ),
            from: AccountId(from_id),
            to: AccountId(to_id),
        })
    }

    pub fn get_updated_account_ids(&self) -> Vec<AccountId> {
        vec![self.from, self.to]
    }
}

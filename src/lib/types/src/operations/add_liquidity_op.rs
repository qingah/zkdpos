use crate::{
    helpers::{pack_fee_amount, pack_token_amount, unpack_fee_amount, unpack_token_amount},
    AddLiquidity,
};
use crate::{AccountId, Address, Nonce, LiquidityId, TokenId};
use anyhow::{ensure, format_err};
use serde::{Deserialize, Serialize};
use zkdpos_crypto::params::{
    ACCOUNT_ID_BIT_WIDTH, AMOUNT_EXPONENT_BIT_WIDTH, AMOUNT_MANTISSA_BIT_WIDTH, CHUNK_BYTES,
    FEE_EXPONENT_BIT_WIDTH, FEE_MANTISSA_BIT_WIDTH, TOKEN_BIT_WIDTH,
};
use zkdpos_crypto::primitives::FromBytes;

/// AddLiquidity operation. For details, see the documentation of [`ZkDposOp`](./operations/enum.ZkDposOp.html).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddLiquidityOp {
    pub tx: AddLiquidity,
    pub from: AccountId,
    pub to: AccountId,
}

impl AddLiquidityOp {
    pub const CHUNKS: usize = 2;
    pub const OP_CODE: u8 = 0x05;

    pub(crate) fn get_public_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(Self::OP_CODE); // opcode
        data.extend_from_slice(&self.from.to_be_bytes());
        data.extend_from_slice(&self.to.to_be_bytes());
        data.extend_from_slice(&pack_token_amount(&self.tx.amount_a_desired));
        data.extend_from_slice(&pack_token_amount(&self.tx.amount_b_desired));
        data.extend_from_slice(&pack_token_amount(&self.tx.amount_a_min));
        data.extend_from_slice(&pack_token_amount(&self.tx.amount_b_min));
        data.extend_from_slice(&pack_fee_amount(&self.tx.fee_a));
        data.extend_from_slice(&pack_fee_amount(&self.tx.fee_b));
        data.resize(Self::CHUNKS * CHUNK_BYTES, 0x00);
        data
    }

    pub fn from_public_data(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        ensure!(
            bytes.len() == Self::CHUNKS * CHUNK_BYTES,
            "Wrong bytes length for remove liquidity pubdata"
        );

        let from_offset = 1;
        let token_id_offset = from_offset + ACCOUNT_ID_BIT_WIDTH / 8;
        let to_offset = token_id_offset + TOKEN_BIT_WIDTH / 8;
        let amount_offset = to_offset + ACCOUNT_ID_BIT_WIDTH / 8;
        let fee_offset =
            amount_offset + (AMOUNT_EXPONENT_BIT_WIDTH + AMOUNT_MANTISSA_BIT_WIDTH) / 8;

        // let from_address = Address::zero(); // From pubdata its unknown
        let to_address = Address::zero(); // From pubdata its unknown
        let liquidity_id =
            u16::from_bytes(&bytes[token_id_offset..token_id_offset + TOKEN_BIT_WIDTH / 8])
                .ok_or_else(|| {
                    format_err!("Cant get liquidity id from remove liquidity pubdata")
                })?;
        let token =
            u16::from_bytes(&bytes[token_id_offset..token_id_offset + TOKEN_BIT_WIDTH / 8])
                .ok_or_else(|| {
                    format_err!("Cant get liquidity id from remove liquidity pubdata")
                })?;
        let amount_a_desired = unpack_token_amount(
            &bytes[amount_offset
                ..amount_offset + (AMOUNT_EXPONENT_BIT_WIDTH + AMOUNT_MANTISSA_BIT_WIDTH) / 8],
        )
        .ok_or_else(|| format_err!("Cant get amount_a_desired from remove liquidity pubdata"))?;
        let amount_b_desired = unpack_token_amount(
            &bytes[amount_offset
                ..amount_offset + (AMOUNT_EXPONENT_BIT_WIDTH + AMOUNT_MANTISSA_BIT_WIDTH) / 8],
        )
        .ok_or_else(|| format_err!("Cant get amount_b_desired from remove liquidity pubdata"))?;
        let amount_a_min = unpack_token_amount(
            &bytes[amount_offset
                ..amount_offset + (AMOUNT_EXPONENT_BIT_WIDTH + AMOUNT_MANTISSA_BIT_WIDTH) / 8],
        )
        .ok_or_else(|| format_err!("Cant get amount_a_min from remove liquidity pubdata"))?;
        let amount_b_min = unpack_token_amount(
            &bytes[amount_offset
                ..amount_offset + (AMOUNT_EXPONENT_BIT_WIDTH + AMOUNT_MANTISSA_BIT_WIDTH) / 8],
        )
        .ok_or_else(|| format_err!("Cant get amount_b_min from remove liquidity pubdata"))?;
        let fee_a = unpack_fee_amount(
            &bytes[fee_offset..fee_offset + (FEE_EXPONENT_BIT_WIDTH + FEE_MANTISSA_BIT_WIDTH) / 8],
        )
        .ok_or_else(|| format_err!("Cant get fee a from remove liquidity pubdata"))?;
        let fee_b = unpack_fee_amount(
            &bytes[fee_offset..fee_offset + (FEE_EXPONENT_BIT_WIDTH + FEE_MANTISSA_BIT_WIDTH) / 8],
        )
        .ok_or_else(|| format_err!("Cant get fee b from remove liquidity pubdata"))?;
        let nonce = 0; // It is unknown from pubdata
        let from_id = u32::from_bytes(&bytes[from_offset..from_offset + ACCOUNT_ID_BIT_WIDTH / 8])
            .ok_or_else(|| format_err!("Cant get from account id from remove liquidity pubdata"))?;
        let to_id = u32::from_bytes(&bytes[to_offset..to_offset + ACCOUNT_ID_BIT_WIDTH / 8])
            .ok_or_else(|| format_err!("Cant get to account id from remove liquidity pubdata"))?;
        let time_range = Default::default();

        Ok(Self {
            tx: AddLiquidity::new(
                AccountId(from_id),
                LiquidityId(liquidity_id),
                to_address,
                amount_a_desired,
                amount_b_desired,
                amount_a_min,
                amount_b_min,
                TokenId(token),
                fee_a,
                fee_b,
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

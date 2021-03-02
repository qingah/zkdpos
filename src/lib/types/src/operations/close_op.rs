use crate::tx::TxSignature;
use crate::Close;
use crate::{AccountId, Address, Nonce};
use anyhow::{ensure, format_err};
use serde::{Deserialize, Serialize};
use zkdpos_crypto::params::{ACCOUNT_ID_BIT_WIDTH, CHUNK_BYTES};
use zkdpos_crypto::primitives::FromBytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseOp {
    pub tx: Close,
    pub account_id: AccountId,
}

impl CloseOp {
    pub const CHUNKS: usize = 1;
    pub const OP_CODE: u8 = 0x04;

    pub(crate) fn get_public_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(Self::OP_CODE); // opcode
        data.extend_from_slice(&self.account_id.to_be_bytes());
        data.resize(Self::CHUNKS * CHUNK_BYTES, 0x00);
        data
    }

    pub fn from_public_data(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        ensure!(
            bytes.len() == Self::CHUNKS * CHUNK_BYTES,
            "Wrong bytes length for close pubdata"
        );

        let account_id_offset = 1;
        let account_id = u32::from_bytes(
            &bytes[account_id_offset..account_id_offset + ACCOUNT_ID_BIT_WIDTH / 8],
        )
        .ok_or_else(|| format_err!("Cant get from account id from close pubdata"))?;
        let account_address = Address::zero(); // From pubdata it is unknown
        let nonce = 0; // From pubdata it is unknown
        let signature = TxSignature::default(); // From pubdata it is unknown
        let time_range = Default::default();
        Ok(Self {
            tx: Close {
                account: account_address,
                nonce: Nonce(nonce),
                signature,
                time_range,
            },
            account_id: AccountId(account_id),
        })
    }

    pub fn get_updated_account_ids(&self) -> Vec<AccountId> {
        vec![self.account_id]
    }
}

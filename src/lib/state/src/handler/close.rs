use anyhow::{bail, ensure};
use num::BigUint;
use zkdpos_crypto::params::{self, max_account_id};
use zkdpos_types::{AccountUpdate, AccountUpdates, Close, CloseOp, TokenId};

use crate::{
    handler::TxHandler,
    state::{CollectedFee, OpSuccess, ZkDposState},
};

impl TxHandler<Close> for ZkDposState {
    type Op = CloseOp;

    fn create_op(&self, _tx: Close) -> Result<Self::Op, anyhow::Error> {
        panic!("Attempt to create disabled closed op");
    }

    fn apply_tx(&mut self, _tx: Close) -> Result<OpSuccess, anyhow::Error> {
        bail!("Account closing is disabled");
    }

    fn apply_op(
        &mut self,
        op: &Self::Op,
    ) -> Result<(Option<CollectedFee>, AccountUpdates), anyhow::Error> {
        ensure!(
            op.account_id <= max_account_id(),
            "Close account id is bigger than max supported"
        );

        let mut updates = Vec::new();
        let account = self.get_account(op.account_id).unwrap();

        for token in 0..params::total_tokens() {
            if account.get_balance(TokenId(token as u16)) != BigUint::from(0u32) {
                bail!("Account is not empty, token id: {}", token);
            }
        }

        ensure!(op.tx.nonce == account.nonce, "Nonce mismatch");

        self.remove_account(op.account_id);

        updates.push((
            op.account_id,
            AccountUpdate::Delete {
                address: account.address,
                nonce: account.nonce,
            },
        ));

        let fee = CollectedFee {
            token: params::ATP_TOKEN_ID,
            amount: BigUint::from(0u32),
        };

        Ok((Some(fee), updates))
    }
}

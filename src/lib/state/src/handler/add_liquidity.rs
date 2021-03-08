use anyhow::{ensure, format_err};
use std::time::Instant;
use zkdpos_crypto::params::{max_account_id};
use zkdpos_types::{
    AccountUpdate, AccountUpdates, AddLiquidity, AddLiquidityOp, Address, PubKeyHash, ZkDposOp,
};

use crate::{
    handler::TxHandler,
    state::{CollectedFee, OpSuccess, ZkDposState},
};

impl TxHandler<AddLiquidity> for ZkDposState {
    type Op = AddLiquidityOp;

    fn create_op(&self, tx: AddLiquidity) -> Result<Self::Op, anyhow::Error> {
        ensure!(
            tx.to != Address::zero(),
            "AddLiquidity to Account with address 0 is not allowed"
        );
        let from = tx.account_id;
        let from_account = self
            .get_account(tx.account_id)
            .ok_or_else(|| format_err!("From account does not exist"))?;
        ensure!(
            from_account.pub_key_hash != PubKeyHash::default(),
            "Account is locked"
        );
        ensure!(
            tx.verify_signature() == Some(from_account.pub_key_hash),
            "AddLiquidity signature is incorrect"
        );
        ensure!(
            from == tx.account_id,
            "AddLiquidity account id is incorrect"
        );

        let add_liquidity_op = AddLiquidityOp { tx, from, to: from };

        Ok(add_liquidity_op)
    }

    fn apply_tx(&mut self, tx: AddLiquidity) -> Result<OpSuccess, anyhow::Error> {
        let op = self.create_op(tx)?;

        let (fee, updates) = <Self as TxHandler<AddLiquidity>>::apply_op(self, &op)?;
        Ok(OpSuccess {
            fee,
            updates,
            executed_op: ZkDposOp::AddLiquidity(Box::new(op)),
        })
    }

    fn apply_op(
        &mut self,
        op: &Self::Op,
    ) -> Result<(Option<CollectedFee>, AccountUpdates), anyhow::Error> {
        let start = Instant::now();
        ensure!(
            op.from <= max_account_id(),
            "AddLiquidity from account id is bigger than max supported"
        );
        ensure!(
            op.to <= max_account_id(),
            "AddLiquidity to account id is bigger than max supported"
        );

        let mut updates = Vec::new();
        let mut from_account = self.get_account(op.from).unwrap();
        let mut to_account = self.get_account(op.to).unwrap();

        let from_old_balance = from_account.get_balance(op.tx.token);
        let from_old_nonce = from_account.nonce;

        ensure!(op.tx.nonce == from_old_nonce, "Nonce mismatch");
        ensure!(
            from_old_balance >= &op.tx.amount_a_min + &op.tx.fee_a,
            "Not enough balance"
        );

        from_account.sub_balance(op.tx.token, &(&op.tx.amount_a_desired + &op.tx.fee_a));
        *from_account.nonce += 1;

        let from_new_balance = from_account.get_balance(op.tx.token);
        let from_new_nonce = from_account.nonce;

        let to_old_balance = to_account.get_balance(op.tx.token);
        let to_account_nonce = to_account.nonce;

        to_account.add_balance(op.tx.token, &op.tx.amount_b_desired);

        let to_new_balance = to_account.get_balance(op.tx.token);

        self.insert_account(op.from, from_account);
        self.insert_account(op.to, to_account);

        updates.push((
            op.from,
            AccountUpdate::UpdateBalance {
                balance_update: (op.tx.token, from_old_balance, from_new_balance),
                old_nonce: from_old_nonce,
                new_nonce: from_new_nonce,
            },
        ));

        updates.push((
            op.to,
            AccountUpdate::UpdateBalance {
                balance_update: (op.tx.token, to_old_balance, to_new_balance),
                old_nonce: to_account_nonce,
                new_nonce: to_account_nonce,
            },
        ));

        let fee = CollectedFee {
            token: op.tx.token,
            amount: op.tx.fee_a.clone(),
        };

        metrics::histogram!("state.add_liquidity", start.elapsed());
        Ok((Some(fee), updates))
    }
}

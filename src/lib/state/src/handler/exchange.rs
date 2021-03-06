use anyhow::{ensure, format_err};
use std::time::Instant;
use zkdpos_crypto::params::{self, max_account_id};
use zkdpos_types::{
    AccountUpdate, AccountUpdates, Address, PubKeyHash, Exchange, ExchangeOp,
};

use crate::{
    handler::TxHandler,
    state::{CollectedFee, OpSuccess, ExchangeOutcome, ZkDposState},
};

impl TxHandler<Exchange> for ZkDposState {
    type Op = ExchangeOutcome;

    fn create_op(&self, tx: Exchange) -> Result<Self::Op, anyhow::Error> {
        ensure!(
            tx.token <= params::max_token_id(),
            "Token id is not supported"
        );
        ensure!(
            tx.to != Address::zero(),
            "Exchange to Account with address 0 is not allowed"
        );
        let (from, from_account) = self
            .get_account_by_address(&tx.from)
            .ok_or_else(|| format_err!("From account does not exist"))?;
        ensure!(
            from_account.pub_key_hash != PubKeyHash::default(),
            "Account is locked"
        );
        ensure!(
            tx.verify_signature() == Some(from_account.pub_key_hash),
            "Exchange signature is incorrect"
        );
        ensure!(from == tx.account_id, "Exchange account id is incorrect");


        let exchange_op = ExchangeOp { tx, from, to: from };

        let outcome = ExchangeOutcome::Exchange(exchange_op);

        Ok(outcome)
    }

    fn apply_tx(&mut self, tx: Exchange) -> Result<OpSuccess, anyhow::Error> {
        let op = self.create_op(tx)?;

        let (fee, updates) = <Self as TxHandler<Exchange>>::apply_op(self, &op)?;
        Ok(OpSuccess {
            fee,
            updates,
            executed_op: op.into_franklin_op(),
        })
    }

    fn apply_op(
        &mut self,
        op: &Self::Op,
    ) -> Result<(Option<CollectedFee>, AccountUpdates), anyhow::Error> {
        match op {
            ExchangeOutcome::Exchange(exchange_op) => self.apply_exchange_op(&exchange_op),
        }
    }

}

impl ZkDposState {
    fn apply_exchange_op(
        &mut self,
        op: &ExchangeOp,
    ) -> Result<(Option<CollectedFee>, AccountUpdates), anyhow::Error> {
        let start = Instant::now();
        ensure!(
            op.from <= max_account_id(),
            "Exchange from account id is bigger than max supported"
        );
        ensure!(
            op.to <= max_account_id(),
            "Exchange to account id is bigger than max supported"
        );


        let mut updates = Vec::new();
        let mut from_account = self.get_account(op.from).unwrap();
        let mut to_account = self.get_account(op.to).unwrap();

        let from_old_balance = from_account.get_balance(op.tx.token);
        let from_old_nonce = from_account.nonce;

        ensure!(op.tx.nonce == from_old_nonce, "Nonce mismatch");
        ensure!(
            from_old_balance >= &op.tx.amount + &op.tx.fee,
            "Not enough balance"
        );

        from_account.sub_balance(op.tx.token, &(&op.tx.amount + &op.tx.fee));
        *from_account.nonce += 1;

        let from_new_balance = from_account.get_balance(op.tx.token);
        let from_new_nonce = from_account.nonce;

        let to_old_balance = to_account.get_balance(op.tx.token);
        let to_account_nonce = to_account.nonce;

        to_account.add_balance(op.tx.token, &op.tx.amount);

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
            amount: op.tx.fee.clone(),
        };

        metrics::histogram!("state.exchange", start.elapsed());
        Ok((Some(fee), updates))
    }
    
}

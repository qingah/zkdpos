//! Set of all the operations supported by the zkDpos network.

use super::ZkDposTx;
use crate::ZkDposPriorityOp;
use anyhow::format_err;
use serde::{Deserialize, Serialize};
use zkdpos_crypto::params::CHUNK_BYTES;

mod change_pubkey_op;
mod close_op;
mod deposit_op;
mod forced_exit;
mod full_exit_op;
mod noop_op;
mod transfer_op;
mod transfer_to_new_op;
mod withdraw_op;
mod exchange_op;
mod add_liquidity_op;
mod remove_liquidity_op;


#[doc(hidden)]
pub use self::close_op::CloseOp;
pub use self::{
    change_pubkey_op::ChangePubKeyOp, deposit_op::DepositOp, forced_exit::ForcedExitOp,
    full_exit_op::FullExitOp, noop_op::NoopOp, transfer_op::TransferOp, exchange_op::ExchangeOp,
    transfer_to_new_op::TransferToNewOp, withdraw_op::WithdrawOp, add_liquidity_op::AddLiquidityOp, remove_liquidity_op::RemoveLiquidityOp
};
use zkdpos_basic_types::AccountId;

/// zkDpos network operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ZkDposOp {
    Deposit(Box<DepositOp>),
    Transfer(Box<TransferOp>),
    /// Transfer to new operation is represented by `Transfer` transaction,
    /// same as `Transfer` operation. The difference is that for `TransferToNew` operation
    /// recipient account doesn't exist and has to be created.
    TransferToNew(Box<TransferToNewOp>),
    Withdraw(Box<WithdrawOp>),
    #[doc(hidden)]
    Close(Box<CloseOp>),
    FullExit(Box<FullExitOp>),
    ChangePubKeyOffchain(Box<ChangePubKeyOp>),
    ForcedExit(Box<ForcedExitOp>),
    /// `NoOp` operation cannot be directly created, but it's used to fill the block capacity.
    Noop(NoopOp),
    Exchange(Box<ExchangeOp>),
    AddLiquidity(Box<AddLiquidityOp>),
    RemoveLiquidity(Box<RemoveLiquidityOp>),
}

impl ZkDposOp {
    /// Returns the number of block chunks required for the operation.
    pub fn chunks(&self) -> usize {
        match self {
            ZkDposOp::Noop(_) => NoopOp::CHUNKS,
            ZkDposOp::Deposit(_) => DepositOp::CHUNKS,
            ZkDposOp::TransferToNew(_) => TransferToNewOp::CHUNKS,
            ZkDposOp::Withdraw(_) => WithdrawOp::CHUNKS,
            ZkDposOp::Close(_) => CloseOp::CHUNKS,
            ZkDposOp::Transfer(_) => TransferOp::CHUNKS,
            ZkDposOp::Exchange(_) => ExchangeOp::CHUNKS,
            ZkDposOp::AddLiquidity(_) => AddLiquidityOp::CHUNKS,
            ZkDposOp::RemoveLiquidity(_) => RemoveLiquidityOp::CHUNKS,
            ZkDposOp::FullExit(_) => FullExitOp::CHUNKS,
            ZkDposOp::ChangePubKeyOffchain(_) => ChangePubKeyOp::CHUNKS,
            ZkDposOp::ForcedExit(_) => ForcedExitOp::CHUNKS,
        }
    }

    /// Returns the public data required for the Alaya smart contract to commit the operation.
    pub fn public_data(&self) -> Vec<u8> {
        match self {
            ZkDposOp::Noop(op) => op.get_public_data(),
            ZkDposOp::Deposit(op) => op.get_public_data(),
            ZkDposOp::TransferToNew(op) => op.get_public_data(),
            ZkDposOp::Withdraw(op) => op.get_public_data(),
            ZkDposOp::Close(op) => op.get_public_data(),
            ZkDposOp::Transfer(op) => op.get_public_data(),
            ZkDposOp::Exchange(op) => op.get_public_data(),
            ZkDposOp::AddLiquidity(op) => op.get_public_data(),
            ZkDposOp::RemoveLiquidity(op) => op.get_public_data(),
            ZkDposOp::FullExit(op) => op.get_public_data(),
            ZkDposOp::ChangePubKeyOffchain(op) => op.get_public_data(),
            ZkDposOp::ForcedExit(op) => op.get_public_data(),
        }
    }

    /// Gets the witness required for the Alaya smart contract.
    /// Unlike public data, some operations may not have a witness.
    ///
    /// Operations that have witness data:
    ///
    /// - `ChangePubKey`;
    pub fn atp_witness(&self) -> Option<Vec<u8>> {
        match self {
            ZkDposOp::ChangePubKeyOffchain(op) => Some(op.get_atp_witness()),
            _ => None,
        }
    }

    /// Returns atp_witness data and data_size for operation, if any.
    ///
    /// Operations that have withdrawal data:
    ///
    /// - `Withdraw`;
    /// - `FullExit`;
    /// - `ForcedExit`.
    pub fn withdrawal_data(&self) -> Option<Vec<u8>> {
        match self {
            ZkDposOp::Withdraw(op) => Some(op.get_withdrawal_data()),
            ZkDposOp::FullExit(op) => Some(op.get_withdrawal_data()),
            ZkDposOp::ForcedExit(op) => Some(op.get_withdrawal_data()),
            _ => None,
        }
    }

    /// Attempts to restore the operation from the public data committed on the Alaya smart contract.
    pub fn from_public_data(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        let op_type: u8 = *bytes.first().ok_or_else(|| format_err!("Empty pubdata"))?;
        match op_type {
            NoopOp::OP_CODE => Ok(ZkDposOp::Noop(NoopOp::from_public_data(&bytes)?)),
            DepositOp::OP_CODE => Ok(ZkDposOp::Deposit(Box::new(DepositOp::from_public_data(
                &bytes,
            )?))),
            TransferToNewOp::OP_CODE => Ok(ZkDposOp::TransferToNew(Box::new(
                TransferToNewOp::from_public_data(&bytes)?,
            ))),
            WithdrawOp::OP_CODE => Ok(ZkDposOp::Withdraw(Box::new(WithdrawOp::from_public_data(
                &bytes,
            )?))),
            CloseOp::OP_CODE => Ok(ZkDposOp::Close(Box::new(CloseOp::from_public_data(
                &bytes,
            )?))),
            TransferOp::OP_CODE => Ok(ZkDposOp::Transfer(Box::new(TransferOp::from_public_data(
                &bytes,
            )?))),
            FullExitOp::OP_CODE => Ok(ZkDposOp::FullExit(Box::new(FullExitOp::from_public_data(
                &bytes,
            )?))),
            ChangePubKeyOp::OP_CODE => Ok(ZkDposOp::ChangePubKeyOffchain(Box::new(
                ChangePubKeyOp::from_public_data(&bytes)?,
            ))),
            ForcedExitOp::OP_CODE => Ok(ZkDposOp::ForcedExit(Box::new(
                ForcedExitOp::from_public_data(&bytes)?,
            ))),
            _ => Err(format_err!("Wrong operation type: {}", &op_type)),
        }
    }

    /// Returns the expected number of chunks for a certain type of operation.
    pub fn public_data_length(op_type: u8) -> Result<usize, anyhow::Error> {
        match op_type {
            NoopOp::OP_CODE => Ok(NoopOp::CHUNKS),
            DepositOp::OP_CODE => Ok(DepositOp::CHUNKS),
            TransferToNewOp::OP_CODE => Ok(TransferToNewOp::CHUNKS),
            WithdrawOp::OP_CODE => Ok(WithdrawOp::CHUNKS),
            CloseOp::OP_CODE => Ok(CloseOp::CHUNKS),
            TransferOp::OP_CODE => Ok(TransferOp::CHUNKS),
            FullExitOp::OP_CODE => Ok(FullExitOp::CHUNKS),
            ChangePubKeyOp::OP_CODE => Ok(ChangePubKeyOp::CHUNKS),
            ForcedExitOp::OP_CODE => Ok(ForcedExitOp::CHUNKS),
            _ => Err(format_err!("Wrong operation type: {}", &op_type)),
        }
        .map(|chunks| chunks * CHUNK_BYTES)
    }

    /// Attempts to interpret the operation as the L2 transaction.
    pub fn try_get_tx(&self) -> Result<ZkDposTx, anyhow::Error> {
        match self {
            ZkDposOp::Transfer(op) => Ok(ZkDposTx::Transfer(Box::new(op.tx.clone()))),
            ZkDposOp::TransferToNew(op) => Ok(ZkDposTx::Transfer(Box::new(op.tx.clone()))),
            ZkDposOp::Withdraw(op) => Ok(ZkDposTx::Withdraw(Box::new(op.tx.clone()))),
            ZkDposOp::Close(op) => Ok(ZkDposTx::Close(Box::new(op.tx.clone()))),
            ZkDposOp::ChangePubKeyOffchain(op) => {
                Ok(ZkDposTx::ChangePubKey(Box::new(op.tx.clone())))
            }
            ZkDposOp::ForcedExit(op) => Ok(ZkDposTx::ForcedExit(Box::new(op.tx.clone()))),
            _ => Err(format_err!("Wrong tx type")),
        }
    }

    /// Attempts to interpret the operation as the L1 priority operation.
    pub fn try_get_priority_op(&self) -> Result<ZkDposPriorityOp, anyhow::Error> {
        match self {
            ZkDposOp::Deposit(op) => Ok(ZkDposPriorityOp::Deposit(op.priority_op.clone())),
            ZkDposOp::FullExit(op) => Ok(ZkDposPriorityOp::FullExit(op.priority_op.clone())),
            _ => Err(format_err!("Wrong operation type")),
        }
    }

    /// Returns the list of account IDs affected by this operation.
    pub fn get_updated_account_ids(&self) -> Vec<AccountId> {
        match self {
            ZkDposOp::Noop(op) => op.get_updated_account_ids(),
            ZkDposOp::Deposit(op) => op.get_updated_account_ids(),
            ZkDposOp::TransferToNew(op) => op.get_updated_account_ids(),
            ZkDposOp::Withdraw(op) => op.get_updated_account_ids(),
            ZkDposOp::Close(op) => op.get_updated_account_ids(),
            ZkDposOp::Transfer(op) => op.get_updated_account_ids(),
            ZkDposOp::Exchange(op) => op.get_updated_account_ids(),
            ZkDposOp::AddLiquidity(op) => op.get_updated_account_ids(),
            ZkDposOp::RemoveLiquidity(op) => op.get_updated_account_ids(),
            ZkDposOp::FullExit(op) => op.get_updated_account_ids(),
            ZkDposOp::ChangePubKeyOffchain(op) => op.get_updated_account_ids(),
            ZkDposOp::ForcedExit(op) => op.get_updated_account_ids(),
        }
    }

    pub fn is_onchain_operation(&self) -> bool {
        matches!(
            self,
            &ZkDposOp::Deposit(_)
                | &ZkDposOp::Withdraw(_)
                | &ZkDposOp::FullExit(_)
                | &ZkDposOp::ChangePubKeyOffchain(_)
                | &ZkDposOp::ForcedExit(_)
        )
    }

    pub fn is_processable_onchain_operation(&self) -> bool {
        matches!(
            self,
            &ZkDposOp::Withdraw(_) | &ZkDposOp::FullExit(_) | &ZkDposOp::ForcedExit(_)
        )
    }

    pub fn is_priority_op(&self) -> bool {
        matches!(self, &ZkDposOp::Deposit(_) | &ZkDposOp::FullExit(_))
    }
}

impl From<NoopOp> for ZkDposOp {
    fn from(op: NoopOp) -> Self {
        Self::Noop(op)
    }
}

impl From<DepositOp> for ZkDposOp {
    fn from(op: DepositOp) -> Self {
        Self::Deposit(Box::new(op))
    }
}

impl From<TransferToNewOp> for ZkDposOp {
    fn from(op: TransferToNewOp) -> Self {
        Self::TransferToNew(Box::new(op))
    }
}

impl From<WithdrawOp> for ZkDposOp {
    fn from(op: WithdrawOp) -> Self {
        Self::Withdraw(Box::new(op))
    }
}

impl From<CloseOp> for ZkDposOp {
    fn from(op: CloseOp) -> Self {
        Self::Close(Box::new(op))
    }
}

impl From<TransferOp> for ZkDposOp {
    fn from(op: TransferOp) -> Self {
        Self::Transfer(Box::new(op))
    }
}

impl From<FullExitOp> for ZkDposOp {
    fn from(op: FullExitOp) -> Self {
        Self::FullExit(Box::new(op))
    }
}

impl From<ChangePubKeyOp> for ZkDposOp {
    fn from(op: ChangePubKeyOp) -> Self {
        Self::ChangePubKeyOffchain(Box::new(op))
    }
}

impl From<ForcedExitOp> for ZkDposOp {
    fn from(op: ForcedExitOp) -> Self {
        Self::ForcedExit(Box::new(op))
    }
}

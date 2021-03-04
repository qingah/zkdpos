//! zkDpos types: essential type definitions for zkDpos network.
//!
//! `zkdpos_types` is a crate containing essential zkDpos network types, such as transactions, operations and
//! blockchain primitives.
//!
//! zkDpos operations are split into the following categories:
//!
//! - **transactions**: operations of zkDpos network existing purely in the L2.
//!   Currently includes [`Transfer`], [`Withdraw`], [`ChangePubKey`], [`Exchange`] and [`ForcedExit`].
//!   All the transactions form an enum named [`ZkDposTx`].
//! - **priority operations**: operations of zkDpos network which are triggered by
//!   invoking the zkDpos smart contract method in L1. These operations are disovered by
//!   the zkDpos server and included into the block just like L2 transactions.
//!   Currently includes [`Deposit`] and [`FullExit`].
//!   All the priority operations form an enum named [`ZkDposPriorityOp`].
//! - **operations**: a superset of [`ZkDposTx`] and [`ZkDposPriorityOp`]
//!   All the operations are included into an enum named [`ZkDposOp`]. This enum contains
//!   all the items that can be included into the block, together with meta-information
//!   about each transaction.
//!   Main difference of operation from transaction/priority operation is that it can form
//!   public data required for the committing the block on the L1.
//!
//! [`Transfer`]: ./tx/struct.Transfer.html
//! [`Withdraw`]: ./tx/struct.Withdraw.html
//! [`ChangePubKey`]: ./tx/struct.ChangePubKey.html
//! [`ForcedExit`]: ./tx/struct.ForcedExit.html
//! [`ZkDposTx`]: ./tx/enum.ZkDposTx.html
//! [`Deposit`]: ./priority_ops/struct.Deposit.html
//! [`FullExit`]: ./priority_ops/struct.FullExit.html
//! [`ZkDposPriorityOp`]: ./priority_ops/enum.ZkDposPriorityOp.html
//! [`ZkDposOp`]: ./operations/enum.ZkDposOp.html
//! [`Exchange`]: ./tx/struct.Exchange.html
//!
//! Aside from transactions, this crate provides definitions for other zkDpos network items, such as
//! [`Block`] and [`Account`].
//!
//! [`Block`]: ./block/struct.Block.html
//! [`Account`]: ./account/struct.Account.html

pub mod account;
pub mod aggregated_operations;
pub mod block;
pub mod config;
pub mod alaya;
pub mod fee;
pub mod gas_counter;
pub mod helpers;
pub mod mempool;
pub mod network;
pub mod operations;
pub mod priority_ops;
pub mod prover;
pub mod tokens;
pub mod tx;
mod utils;

// #[cfg(test)]
// mod tests;

pub use self::account::{Account, AccountUpdate, PubKeyHash};
pub use self::block::{ExecutedOperations, ExecutedPriorityOp, ExecutedTx};
pub use self::fee::{BatchFee, Fee, OutputFeeType};
pub use self::operations::{
    ChangePubKeyOp, DepositOp, ForcedExitOp, FullExitOp, TransferOp, TransferToNewOp, WithdrawOp, ExchangeOp, AddLiquidityOp, RemoveLiquidityOp, 
    ZkDposOp,
};
pub use self::priority_ops::{Deposit, FullExit, PriorityOp, ZkDposPriorityOp};
pub use self::tokens::{Token, TokenGenesisListItem, TokenLike, TokenPrice, TxFeeTypes};
pub use self::tx::{ForcedExit, SignedZkDposTx, Transfer, Withdraw, Exchange, AddLiquidity, RemoveLiquidity, ZkDposTx};

#[doc(hidden)]
pub use self::{operations::CloseOp, tx::Close};

pub use zkdpos_basic_types::*;

pub type AccountMap = zkdpos_crypto::fnv::FnvHashMap<AccountId, Account>;
pub type AccountUpdates = Vec<(AccountId, AccountUpdate)>;
pub type AccountTree = SparseMerkleTree<Account, Fr, RescueHasher<Engine>>;
pub type SerialId = u64;

use crate::block::Block;
pub use zkdpos_crypto::{
    merkle_tree::{RescueHasher, SparseMerkleTree},
    Engine, Fr,
};

use serde::{Deserialize, Serialize};
use zkdpos_crypto::proof::SingleProof;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    Commit,
    Verify { proof: Box<SingleProof> },
}

impl Action {
    pub fn get_type(&self) -> ActionType {
        match self {
            Action::Commit => ActionType::COMMIT,
            Action::Verify { .. } => ActionType::VERIFY,
        }
    }
}

impl std::string::ToString for Action {
    fn to_string(&self) -> String {
        self.get_type().to_string()
    }
}

impl std::fmt::Debug for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub id: Option<i64>,
    pub action: Action,
    pub block: Block,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Serialize, Deserialize)]
pub enum ActionType {
    COMMIT,
    VERIFY,
}

impl std::string::ToString for ActionType {
    fn to_string(&self) -> String {
        match self {
            ActionType::COMMIT => "COMMIT".to_owned(),
            ActionType::VERIFY => "VERIFY".to_owned(),
        }
    }
}

impl std::str::FromStr for ActionType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "COMMIT" => Ok(Self::COMMIT),
            "VERIFY" => Ok(Self::VERIFY),
            _ => Err("Should be either: COMMIT or VERIFY".to_owned()),
        }
    }
}

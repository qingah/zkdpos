use num::BigUint;
use parity_crypto::digest::sha256;
use serde::{Deserialize, Serialize};

use zkdpos_basic_types::{AccountId, Address};

use crate::{
    operations::ChangePubKeyOp,
    tx::{ChangePubKey, Close, ForcedExit, Transfer, TxAtpSignature, TxHash, Withdraw, Exchange},
    utils::deserialize_atp_message,
    CloseOp, ForcedExitOp, Nonce, Token, TokenId, TokenLike, TransferOp, TxFeeTypes, WithdrawOp,
};
use zkdpos_crypto::params::ATP_TOKEN_ID;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AtpSignData {
    pub signature: TxAtpSignature,
    #[serde(deserialize_with = "deserialize_atp_message")]
    pub message: Vec<u8>,
}

/// Represents transaction with the corresponding Alaya signature and the message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedZkDposTx {
    /// Underlying zkDpos transaction.
    pub tx: ZkDposTx,
    /// `atp_sign_data` is a tuple of the Alaya signature and the message
    /// which user should have signed with their private key.
    /// Can be `None` if the Alaya signature is not required.
    pub atp_sign_data: Option<AtpSignData>,
}

/// A set of L2 transaction supported by the zkDpos network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ZkDposTx {
    Transfer(Box<Transfer>),
    Withdraw(Box<Withdraw>),
    Exchange(Box<Exchange>),
    #[doc(hidden)]
    Close(Box<Close>),
    ChangePubKey(Box<ChangePubKey>),
    ForcedExit(Box<ForcedExit>),
}

impl From<Transfer> for ZkDposTx {
    fn from(transfer: Transfer) -> Self {
        Self::Transfer(Box::new(transfer))
    }
}

impl From<Withdraw> for ZkDposTx {
    fn from(withdraw: Withdraw) -> Self {
        Self::Withdraw(Box::new(withdraw))
    }
}

impl From<Close> for ZkDposTx {
    fn from(close: Close) -> Self {
        Self::Close(Box::new(close))
    }
}

impl From<ChangePubKey> for ZkDposTx {
    fn from(change_pub_key: ChangePubKey) -> Self {
        Self::ChangePubKey(Box::new(change_pub_key))
    }
}

impl From<ForcedExit> for ZkDposTx {
    fn from(tx: ForcedExit) -> Self {
        Self::ForcedExit(Box::new(tx))
    }
}

impl From<ZkDposTx> for SignedZkDposTx {
    fn from(tx: ZkDposTx) -> Self {
        Self {
            tx,
            atp_sign_data: None,
        }
    }
}

impl std::ops::Deref for SignedZkDposTx {
    type Target = ZkDposTx;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl ZkDposTx {
    /// Returns the hash of the transaction.
    pub fn hash(&self) -> TxHash {
        let bytes = match self {
            ZkDposTx::Transfer(tx) => tx.get_bytes(),
            ZkDposTx::Exchange(tx) => tx.get_bytes(),
            ZkDposTx::Withdraw(tx) => tx.get_bytes(),
            ZkDposTx::Close(tx) => tx.get_bytes(),
            ZkDposTx::ChangePubKey(tx) => tx.get_bytes(),
            ZkDposTx::ForcedExit(tx) => tx.get_bytes(),
        };

        let hash = sha256(&bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        TxHash { data: out }
    }

    /// Returns the account affected by the transaction.
    pub fn account(&self) -> Address {
        match self {
            ZkDposTx::Transfer(tx) => tx.from,
            ZkDposTx::Exchange(tx) => tx.from,
            ZkDposTx::Withdraw(tx) => tx.from,
            ZkDposTx::Close(tx) => tx.account,
            ZkDposTx::ChangePubKey(tx) => tx.account,
            ZkDposTx::ForcedExit(tx) => tx.target,
        }
    }

    pub fn account_id(&self) -> anyhow::Result<AccountId> {
        match self {
            ZkDposTx::Transfer(tx) => Ok(tx.account_id),
            ZkDposTx::Exchange(tx) => Ok(tx.account_id),
            ZkDposTx::Withdraw(tx) => Ok(tx.account_id),
            ZkDposTx::ChangePubKey(tx) => Ok(tx.account_id),
            ZkDposTx::ForcedExit(tx) => Ok(tx.initiator_account_id),
            ZkDposTx::Close(_) => Err(anyhow::anyhow!("Close operations are disabled")),
        }
    }

    /// Returns the account nonce associated with transaction.
    pub fn nonce(&self) -> Nonce {
        match self {
            ZkDposTx::Transfer(tx) => tx.nonce,
            ZkDposTx::Exchange(tx) => tx.nonce,
            ZkDposTx::Withdraw(tx) => tx.nonce,
            ZkDposTx::Close(tx) => tx.nonce,
            ZkDposTx::ChangePubKey(tx) => tx.nonce,
            ZkDposTx::ForcedExit(tx) => tx.nonce,
        }
    }

    /// Returns the token used to pay the transaction fee with.
    ///
    /// For `Close` we return 0 and expect the server to decline
    /// the transaction before the call to this method.
    pub fn token_id(&self) -> TokenId {
        match self {
            ZkDposTx::Transfer(tx) => tx.token,
            ZkDposTx::Exchange(tx) => tx.token,
            ZkDposTx::Withdraw(tx) => tx.token,
            ZkDposTx::Close(_) => ATP_TOKEN_ID,
            ZkDposTx::ChangePubKey(tx) => tx.fee_token,
            ZkDposTx::ForcedExit(tx) => tx.token,
        }
    }

    /// Checks whether transaction is well-formed and can be executed.
    ///
    /// Note that this method doesn't check whether transaction will succeed, so transaction
    /// can fail even if this method returned `true` (i.e., if account didn't have enough balance).
    pub fn check_correctness(&mut self) -> bool {
        match self {
            ZkDposTx::Transfer(tx) => tx.check_correctness(),
            ZkDposTx::Exchange(tx) => tx.check_correctness(),
            ZkDposTx::Withdraw(tx) => tx.check_correctness(),
            ZkDposTx::Close(tx) => tx.check_correctness(),
            ZkDposTx::ChangePubKey(tx) => tx.check_correctness(),
            ZkDposTx::ForcedExit(tx) => tx.check_correctness(),
        }
    }

    /// Returns a message that user has to sign to send the transaction.
    /// If the transaction doesn't need a message signature, returns `None`.
    /// `ChangePubKey` message is handled separately since its Alaya signature
    /// is passed to the contract.
    pub fn get_alaya_sign_message(&self, token: Token) -> Option<String> {
        match self {
            ZkDposTx::Transfer(tx) => {
                Some(tx.get_alaya_sign_message(&token.symbol, token.decimals))
            }
            ZkDposTx::Withdraw(tx) => {
                Some(tx.get_alaya_sign_message(&token.symbol, token.decimals))
            }
            ZkDposTx::ForcedExit(tx) => {
                Some(tx.get_alaya_sign_message(&token.symbol, token.decimals))
            }
            _ => None,
        }
    }

    /// Returns a message that user has to sign to send the transaction in the old format.
    /// If the transaction doesn't need a message signature, returns `None`.
    /// Needed for backwards compatibility.
    pub fn get_old_alaya_sign_message(&self, token: Token) -> Option<String> {
        match self {
            ZkDposTx::Transfer(tx) => {
                Some(tx.get_old_alaya_sign_message(&token.symbol, token.decimals))
            }
            ZkDposTx::Withdraw(tx) => {
                Some(tx.get_old_alaya_sign_message(&token.symbol, token.decimals))
            }
            _ => None,
        }
    }

    /// Returns the corresponding part of the batch message user has to sign in order
    /// to send it. In this case we handle `ChangePubKey` on the server side and
    /// expect a line in the message for it.
    pub fn get_alaya_sign_message_part(&self, token: Token) -> Option<String> {
        match self {
            ZkDposTx::Transfer(tx) => {
                Some(tx.get_alaya_sign_message_part(&token.symbol, token.decimals))
            }
            ZkDposTx::Withdraw(tx) => {
                Some(tx.get_alaya_sign_message_part(&token.symbol, token.decimals))
            }
            ZkDposTx::ChangePubKey(tx) => {
                Some(tx.get_alaya_sign_message_part(&token.symbol, token.decimals))
            }
            ZkDposTx::ForcedExit(tx) => {
                Some(tx.get_alaya_sign_message_part(&token.symbol, token.decimals))
            }
            _ => None,
        }
    }

    /// Encodes the transaction data as the byte sequence according to the zkDpos protocol.
    pub fn get_bytes(&self) -> Vec<u8> {
        match self {
            ZkDposTx::Transfer(tx) => tx.get_bytes(),
            ZkDposTx::Exchange(tx) => tx.get_bytes(),
            ZkDposTx::Withdraw(tx) => tx.get_bytes(),
            ZkDposTx::Close(tx) => tx.get_bytes(),
            ZkDposTx::ChangePubKey(tx) => tx.get_bytes(),
            ZkDposTx::ForcedExit(tx) => tx.get_bytes(),
        }
    }

    /// Returns the minimum amount of block chunks required for this operation.
    /// Maximum amount of chunks in block is a part of  the server and provers configuration,
    /// and this value determines the block capacity.
    pub fn min_chunks(&self) -> usize {
        match self {
            ZkDposTx::Transfer(_) => TransferOp::CHUNKS,
            ZkDposTx::Exchange(_) => TransferOp::CHUNKS,
            ZkDposTx::Withdraw(_) => WithdrawOp::CHUNKS,
            ZkDposTx::Close(_) => CloseOp::CHUNKS,
            ZkDposTx::ChangePubKey(_) => ChangePubKeyOp::CHUNKS,
            ZkDposTx::ForcedExit(_) => ForcedExitOp::CHUNKS,
        }
    }

    /// Returns `true` if transaction is `ZkDposTx::Withdraw`.
    pub fn is_withdraw(&self) -> bool {
        matches!(self, ZkDposTx::Withdraw(_) | ZkDposTx::ForcedExit(_))
    }

    /// Returns `true` if transaction is `ZkDposTx::Withdraw`.
    #[doc(hidden)]
    pub fn is_close(&self) -> bool {
        matches!(self, ZkDposTx::Close(_))
    }

    /// Returns the data required to calculate fee for the transaction.
    ///
    /// Response includes the following items:
    ///
    /// - Fee type.
    /// - Token to pay fees in.
    /// - Fee provided in the transaction.
    ///
    /// Returns `None` if transaction doesn't require fee.
    pub fn get_fee_info(&self) -> Option<(TxFeeTypes, TokenLike, Address, BigUint)> {
        match self {
            ZkDposTx::Withdraw(withdraw) => {
                let fee_type = if withdraw.fast {
                    TxFeeTypes::FastWithdraw
                } else {
                    TxFeeTypes::Withdraw
                };

                Some((
                    fee_type,
                    TokenLike::Id(withdraw.token),
                    withdraw.to,
                    withdraw.fee.clone(),
                ))
            }
            ZkDposTx::ForcedExit(forced_exit) => Some((
                TxFeeTypes::Withdraw,
                TokenLike::Id(forced_exit.token),
                forced_exit.target,
                forced_exit.fee.clone(),
            )),
            ZkDposTx::Transfer(transfer) => Some((
                TxFeeTypes::Transfer,
                TokenLike::Id(transfer.token),
                transfer.to,
                transfer.fee.clone(),
            )),
            ZkDposTx::ChangePubKey(change_pubkey) => Some((
                change_pubkey.get_fee_type(),
                TokenLike::Id(change_pubkey.fee_token),
                change_pubkey.account,
                change_pubkey.fee.clone(),
            )),
            _ => None,
        }
    }

    /// Returns the unix format timestamp of the first moment when transaction execution is valid.
    pub fn valid_from(&self) -> u64 {
        match self {
            ZkDposTx::Transfer(tx) => tx.time_range.unwrap_or_default().valid_from,
            ZkDposTx::Exchange(tx) => tx.time_range.unwrap_or_default().valid_from,
            ZkDposTx::Withdraw(tx) => tx.time_range.unwrap_or_default().valid_from,
            ZkDposTx::ChangePubKey(tx) => tx.time_range.unwrap_or_default().valid_from,
            ZkDposTx::ForcedExit(tx) => tx.time_range.valid_from,
            ZkDposTx::Close(tx) => tx.time_range.valid_from,
        }
    }
}

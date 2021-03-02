use crate::{
    helpers::{is_fee_amount_packable, pack_fee_amount},
    AccountId, Nonce, TokenId,
};
use num::{BigUint, ToPrimitive};

use crate::account::PubKeyHash;
use crate::utils::alaya_sign_message_part;
use crate::Engine;
use serde::{Deserialize, Serialize};
use zkdpos_basic_types::Address;
use zkdpos_crypto::franklin_crypto::eddsa::PrivateKey;
use zkdpos_crypto::params::{max_account_id, max_token_id};
use zkdpos_utils::{format_units, BigUintSerdeAsRadix10Str};

use super::{TimeRange, TxSignature, VerifiedSignatureCache};

/// `Withdraw` transaction performs a withdrawal of funds from zkDpos account to L1 account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Withdraw {
    /// zkDpos network account ID of the transaction initiator.
    pub account_id: AccountId,
    /// Address of L2 account to withdraw funds from.
    pub from: Address,
    /// Address of L1 account to withdraw funds to.
    pub to: Address,
    /// Type of token for withdrawal. Also represents the token in which fee will be paid.
    pub token: TokenId,
    /// Amount of funds to withdraw.
    #[serde(with = "BigUintSerdeAsRadix10Str")]
    pub amount: BigUint,
    /// Fee for the transaction.
    #[serde(with = "BigUintSerdeAsRadix10Str")]
    pub fee: BigUint,
    /// Current account nonce.
    pub nonce: Nonce,
    /// Transaction zkDpos signature.
    pub signature: TxSignature,
    #[serde(skip)]
    cached_signer: VerifiedSignatureCache,
    /// Optional setting signalizing state keeper to speed up creation
    /// of the block with provided transaction.
    /// This field is only set by the server. Transaction with this field set manually will be
    /// rejected.
    #[serde(default)]
    pub fast: bool,
    /// Time range when the transaction is valid
    /// This fields must be Option<...> because of backward compatibility with first version of zkDpos
    #[serde(flatten)]
    pub time_range: Option<TimeRange>,
}

impl Withdraw {
    /// Unique identifier of the transaction type in zkDpos network.
    pub const TX_TYPE: u8 = 3;

    /// Creates transaction from all the required fields.
    ///
    /// While `signature` field is mandatory for new transactions, it may be `None`
    /// in some cases (e.g. when restoring the network state from the L1 contract data).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        from: Address,
        to: Address,
        token: TokenId,
        amount: BigUint,
        fee: BigUint,
        nonce: Nonce,
        time_range: TimeRange,
        signature: Option<TxSignature>,
    ) -> Self {
        let mut tx = Self {
            account_id,
            from,
            to,
            token,
            amount,
            fee,
            nonce,
            signature: signature.clone().unwrap_or_default(),
            cached_signer: VerifiedSignatureCache::NotCached,
            fast: false,
            time_range: Some(time_range),
        };
        if signature.is_some() {
            tx.cached_signer = VerifiedSignatureCache::Cached(tx.verify_signature());
        }
        tx
    }

    /// Creates a signed transaction using private key and
    /// checks for the transaction correcteness.
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed(
        account_id: AccountId,
        from: Address,
        to: Address,
        token: TokenId,
        amount: BigUint,
        fee: BigUint,
        nonce: Nonce,
        time_range: TimeRange,
        private_key: &PrivateKey<Engine>,
    ) -> Result<Self, anyhow::Error> {
        let mut tx = Self::new(
            account_id, from, to, token, amount, fee, nonce, time_range, None,
        );
        tx.signature = TxSignature::sign_musig(private_key, &tx.get_bytes());
        if !tx.check_correctness() {
            anyhow::bail!(crate::tx::TRANSACTION_SIGNATURE_ERROR);
        }
        Ok(tx)
    }

    /// Encodes the transaction data as the byte sequence according to the zkDpos protocol.
    pub fn get_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[Self::TX_TYPE]);
        out.extend_from_slice(&self.account_id.to_be_bytes());
        out.extend_from_slice(&self.from.as_bytes());
        out.extend_from_slice(self.to.as_bytes());
        out.extend_from_slice(&self.token.to_be_bytes());
        out.extend_from_slice(&self.amount.to_u128().unwrap().to_be_bytes());
        out.extend_from_slice(&pack_fee_amount(&self.fee));
        out.extend_from_slice(&self.nonce.to_be_bytes());
        if let Some(time_range) = &self.time_range {
            out.extend_from_slice(&time_range.to_be_bytes());
        }
        out
    }

    /// Verifies the transaction correctness:
    ///
    /// - `account_id` field must be within supported range.
    /// - `token` field must be within supported range.
    /// - `amount` field must represent a packable value.
    /// - `fee` field must represent a packable value.
    /// - zkDpos signature must correspond to the PubKeyHash of the account.
    pub fn check_correctness(&mut self) -> bool {
        let mut valid = self.amount <= BigUint::from(u128::max_value())
            && is_fee_amount_packable(&self.fee)
            && self.account_id <= max_account_id()
            && self.token <= max_token_id()
            && self
                .time_range
                .map(|t| t.check_correctness())
                .unwrap_or(true);

        if valid {
            let signer = self.verify_signature();
            valid = valid && signer.is_some();
            self.cached_signer = VerifiedSignatureCache::Cached(signer);
        }
        valid
    }

    /// Restores the `PubKeyHash` from the transaction signature.
    pub fn verify_signature(&self) -> Option<PubKeyHash> {
        if let VerifiedSignatureCache::Cached(cached_signer) = &self.cached_signer {
            *cached_signer
        } else {
            self.signature
                .verify_musig(&self.get_bytes())
                .map(|pub_key| PubKeyHash::from_pubkey(&pub_key))
        }
    }

    /// Get the first part of the message we expect to be signed by Alaya account key.
    /// The only difference is the missing `nonce` since it's added at the end of the transactions
    /// batch message.
    pub fn get_alaya_sign_message_part(&self, token_symbol: &str, decimals: u8) -> String {
        alaya_sign_message_part(
            "Withdraw",
            token_symbol,
            decimals,
            &self.amount,
            &self.fee,
            &self.to,
        )
    }

    /// Get message that should be signed by Alaya keys of the account for 2-Factor authentication.
    pub fn get_alaya_sign_message(&self, token_symbol: &str, decimals: u8) -> String {
        let mut message = self.get_alaya_sign_message_part(token_symbol, decimals);
        if !message.is_empty() {
            message.push('\n');
        }
        message.push_str(format!("Nonce: {}", self.nonce).as_str());
        message
    }

    /// Returns an old-format message that should be signed by Alaya account key.
    /// Needed for backwards compatibility.
    pub fn get_old_alaya_sign_message(&self, token_symbol: &str, decimals: u8) -> String {
        format!(
            "Withdraw {amount} {token}\n\
            To: {to:?}\n\
            Nonce: {nonce}\n\
            Fee: {fee} {token}\n\
            Account Id: {account_id}",
            amount = format_units(&self.amount, decimals),
            token = token_symbol,
            to = self.to,
            nonce = *self.nonce,
            fee = format_units(&self.fee, decimals),
            account_id = *self.account_id,
        )
    }
}

use crate::{
    helpers::{
        is_fee_amount_packable, is_token_amount_packable, pack_fee_amount, pack_token_amount,
    },
    tx::TimeRange,
    AccountId, LiquidityId, Nonce, TokenId,
};
use num::BigUint;

use crate::account::PubKeyHash;
use crate::Engine;
use serde::{Deserialize, Serialize};
use zkdpos_basic_types::Address;
use zkdpos_crypto::franklin_crypto::eddsa::PrivateKey;
use zkdpos_crypto::params::{max_account_id};
use zkdpos_utils::{format_units, BigUintSerdeAsRadix10Str};

use super::{TxSignature, VerifiedSignatureCache};

/// `AddLiquidity` transaction performs a move of funds from one zkDpos account to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddLiquidity {
    /// zkDpos network account ID of the transaction initiator.
    pub account_id: AccountId,
    /// zkDpos network account ID of the transaction initiator.
    pub liquidity_id: LiquidityId,
    /// Address of account to add liquidity funds to.
    pub to: Address,
    /// AmountA Desired of funds to add liquidity.
    #[serde(with = "BigUintSerdeAsRadix10Str")]
    pub amount_a_desired: BigUint,
    /// AmountB Desired of funds to add liquidity.
    #[serde(with = "BigUintSerdeAsRadix10Str")]
    pub amount_b_desired: BigUint,
    /// amountA Min of funds to add liquidity.
    #[serde(with = "BigUintSerdeAsRadix10Str")]
    pub amount_a_min: BigUint,
    /// amountB Min of funds to add liquidity.
    #[serde(with = "BigUintSerdeAsRadix10Str")]
    pub amount_b_min: BigUint,
    /// Type of token for transfer. Also represents the token in which fee will be paid.
    pub token: TokenId,
    /// Fee A for the transaction.
    #[serde(with = "BigUintSerdeAsRadix10Str")]
    pub fee_a: BigUint,
    /// Fee B for the transaction.
    #[serde(with = "BigUintSerdeAsRadix10Str")]
    pub fee_b: BigUint,
    /// Current account nonce.
    pub nonce: Nonce,
    /// Time range when the transaction is valid
    /// This fields must be Option<...> because of backward compatibility with first version of ZkDpos
    #[serde(flatten)]
    pub time_range: Option<TimeRange>,
    /// Transaction zkDpos signature.
    pub signature: TxSignature,
    #[serde(skip)]
    cached_signer: VerifiedSignatureCache,
}

impl AddLiquidity {
    /// Unique identifier of the transaction type in zkDpos network.
    pub const TX_TYPE: u8 = 5;

    /// Creates transaction from all the required fields.
    ///
    /// While `signature` field is mandatory for new transactions, it may be `None`
    /// in some cases (e.g. when restoring the network state from the L1 contract data).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        liquidity_id: LiquidityId,
        to: Address,
        amount_a_desired: BigUint,
        amount_b_desired: BigUint,
        amount_a_min: BigUint,
        amount_b_min: BigUint,
        token: TokenId,
        fee_a: BigUint,
        fee_b: BigUint,
        nonce: Nonce,
        time_range: TimeRange,
        signature: Option<TxSignature>,
    ) -> Self {
        let mut tx = Self {
            account_id,
            liquidity_id,
            to,
            amount_a_desired,
            amount_b_desired,
            amount_a_min,
            amount_b_min,
            token,
            fee_a,
            fee_b,
            nonce,
            time_range: Some(time_range),
            signature: signature.clone().unwrap_or_default(),
            cached_signer: VerifiedSignatureCache::NotCached,
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
        liquidity_id: LiquidityId,
        to: Address,
        amount_a_desired: BigUint,
        amount_b_desired: BigUint,
        amount_a_min: BigUint,
        amount_b_min: BigUint,
        token: TokenId,
        fee_a: BigUint,
        fee_b: BigUint,
        nonce: Nonce,
        time_range: TimeRange,
        private_key: &PrivateKey<Engine>,
    ) -> Result<Self, anyhow::Error> {
        let mut tx = Self::new(
            account_id, liquidity_id, to, amount_a_desired, amount_b_desired, amount_a_min,  amount_b_min, token, fee_a, fee_b, nonce, time_range, None,
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
        out.extend_from_slice(&self.to.as_bytes());
        out.extend_from_slice(&pack_token_amount(&self.amount_a_desired));
        out.extend_from_slice(&pack_token_amount(&self.amount_b_desired));
        out.extend_from_slice(&pack_token_amount(&self.amount_a_min));
        out.extend_from_slice(&pack_token_amount(&self.amount_b_min));
        out.extend_from_slice(&pack_fee_amount(&self.fee_a));
        out.extend_from_slice(&pack_fee_amount(&self.fee_b));
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
    /// - add liquidity recipient must not be `Adddress::zero()`.
    /// - zkDpos signature must correspond to the PubKeyHash of the account.
    pub fn check_correctness(&mut self) -> bool {
        let mut valid = self.amount_a_desired <= BigUint::from(u128::max_value())
            && self.fee_a <= BigUint::from(u128::max_value())
            && is_token_amount_packable(&self.amount_b_desired)
            && is_fee_amount_packable(&self.fee_b)
            && self.account_id <= max_account_id()
            && self.to != Address::zero()
            && self
                .time_range
                .map(|r| r.check_correctness())
                .unwrap_or(true);
        if valid {
            let signer = self.verify_signature();
            valid = valid && signer.is_some();
            self.cached_signer = VerifiedSignatureCache::Cached(signer);
        };
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
        format!(
            "AddLiquidity {liquidity_id} {amount_a_desired} {amount_b_desired} {amount_a_min} {amount_b_min}\n\
            Nonce: {nonce}\n\
            Fee: {fee_a} {fee_b}\n\
            Account Id: {account_id}",
            liquidity_id = token_symbol,
            amount_a_desired = format_units(&self.amount_a_desired, decimals),
            amount_b_desired = format_units(&self.amount_b_desired, decimals),
            amount_a_min = format_units(&self.amount_a_min, decimals),
            amount_b_min = format_units(&self.amount_b_min, decimals),
            nonce = *self.nonce,
            fee_a = format_units(&self.fee_a, decimals),
            fee_b = format_units(&self.fee_b, decimals),
            account_id = *self.account_id,
        )
    }

    /// Gets message that should be signed by Alaya keys of the account for 2-Factor authentication.
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
            "AddLiquidity {liquidity_id} {amount_a_desired} {amount_b_desired} {amount_a_min} {amount_b_min}\n\
            Nonce: {nonce}\n\
            Fee: {fee_a} {fee_b}\n\
            Account Id: {account_id}",
            liquidity_id = token_symbol,
            amount_a_desired = format_units(&self.amount_a_desired, decimals),
            amount_b_desired = format_units(&self.amount_b_desired, decimals),
            amount_a_min = format_units(&self.amount_a_min, decimals),
            amount_b_min = format_units(&self.amount_b_min, decimals),
            nonce = *self.nonce,
            fee_a = format_units(&self.fee_a, decimals),
            fee_b = format_units(&self.fee_b, decimals),
            account_id = *self.account_id,
        )
    }
}

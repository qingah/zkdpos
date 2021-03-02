// External uses
use anyhow::ensure;
use itertools::Itertools;
// Workspace uses
use zkdpos_basic_types::Address;
// Local uses
use super::atp_signature::TxAtpSignature;
use crate::{Token, ZkDposTx};

/// Encapsulates transactions batch signature data. Should only be created via `new()`
/// as long as errors are possible.
#[derive(Debug, Clone)]
pub struct AtpBatchSignData {
    pub signatures: Vec<TxAtpSignature>,
    pub message: Vec<u8>,
}

impl AtpBatchSignData {
    /// Construct the message user is expected to sign for the given batch and pack
    /// it along with signatures. Since there can be multiple senders in a single batch,
    /// separate them with
    ///
    /// `From: {address}`
    pub fn new(
        txs: Vec<(ZkDposTx, Token, Address)>,
        signatures: Vec<TxAtpSignature>,
    ) -> anyhow::Result<AtpBatchSignData> {
        ensure!(!txs.is_empty(), "Transaction batch cannot be empty");

        let message = AtpBatchSignData::get_batch_sign_message(txs);

        Ok(AtpBatchSignData {
            signatures,
            message,
        })
    }

    /// Construct the message user is expected to sign for the given batch.
    pub fn get_batch_sign_message(txs: Vec<(ZkDposTx, Token, Address)>) -> Vec<u8> {
        let grouped = txs.into_iter().group_by(|tx| tx.2);
        let mut iter = grouped.into_iter().peekable();
        // The message is empty if there're no transactions.
        let first = match iter.next() {
            Some(group) => group,
            None => return Vec::new(),
        };
        // Check whether there're mutiple addresses in the batch, concatenate their
        // transaction messages with `From: {address}` separator.
        // Otherwise, process the whole group at once.
        match iter.peek() {
            Some(_) => {
                let head = AtpBatchSignData::group_message(first.1, Some(first.0));
                let tail = itertools::join(
                    iter.map(|(address, group)| {
                        AtpBatchSignData::group_message(group, Some(address))
                    }),
                    "\n\n",
                );
                format!("{}\n\n{}", head, tail)
            }
            None => AtpBatchSignData::group_message(first.1, None),
        }
        .into_bytes()
    }

    fn group_message<I>(iter: I, address: Option<Address>) -> String
    where
        I: IntoIterator<Item = (ZkDposTx, Token, Address)>,
    {
        let mut iter = iter.into_iter().peekable();
        // The group is not empty.
        let nonce = iter.peek().unwrap().0.nonce();
        let message = itertools::join(
            iter.filter_map(|(tx, token, _)| tx.get_alaya_sign_message_part(token))
                .filter(|part| !part.is_empty()),
            "\n",
        );
        let body = format!(
            "{message}\n\
            Nonce: {nonce}",
            message = message,
            nonce = nonce
        );
        match address {
            Some(address) => format!(
                "From: 0x{address}\n\
                {body}",
                address = hex::encode(address),
                body = body
            ),
            None => body,
        }
    }

    /// Returns an old-format message that should be signed by Alaya account key.
    /// Needed for backwards compatibility.
    pub fn get_old_alaya_batch_message<'a, I>(txs: I) -> Vec<u8>
    where
        I: Iterator<Item = &'a ZkDposTx>,
    {
        tiny_keccak::keccak256(
            txs.flat_map(ZkDposTx::get_bytes)
                .collect::<Vec<u8>>()
                .as_slice(),
        )
        .to_vec()
    }
}

use super::{
    tx::{TxAtpSignature, TxHash},
    SignedZkDposTx,
};

/// A collection of transactions that must be executed together.
/// All the transactions in the batch must be included into the same block,
/// and either succeed or fail all together.
#[derive(Debug, Clone)]
pub struct SignedTxsBatch {
    pub txs: Vec<SignedZkDposTx>,
    pub batch_id: i64,
    pub atp_signatures: Vec<TxAtpSignature>,
}

/// A wrapper around possible atomic block elements: it can be either
/// a single transaction, or the transactions batch.
#[derive(Debug, Clone)]
pub enum SignedTxVariant {
    Tx(SignedZkDposTx),
    Batch(SignedTxsBatch),
}

impl From<SignedZkDposTx> for SignedTxVariant {
    fn from(tx: SignedZkDposTx) -> Self {
        Self::Tx(tx)
    }
}

impl SignedTxVariant {
    pub fn batch(
        txs: Vec<SignedZkDposTx>,
        batch_id: i64,
        atp_signatures: Vec<TxAtpSignature>,
    ) -> Self {
        Self::Batch(SignedTxsBatch {
            txs,
            batch_id,
            atp_signatures,
        })
    }

    pub fn hashes(&self) -> Vec<TxHash> {
        match self {
            Self::Tx(tx) => vec![tx.hash()],
            Self::Batch(batch) => batch.txs.iter().map(|tx| tx.hash()).collect(),
        }
    }

    pub fn get_transactions(&self) -> Vec<SignedZkDposTx> {
        match self {
            Self::Tx(tx) => vec![tx.clone()],
            Self::Batch(batch) => batch.txs.clone(),
        }
    }
}

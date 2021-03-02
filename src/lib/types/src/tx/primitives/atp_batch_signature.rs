use crate::tx::TxAtpSignature;
use serde::{Deserialize, Serialize};

/// Representation of the signatures secured by L1 fot batch.
/// Used for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum AtpBatchSignatures {
    /// Old version of the batch signature, represents a maximum of one signature for one batch.
    Single(TxAtpSignature),
    /// New version of the batch signature, represents multiple signatures for one batch.
    Multi(Vec<TxAtpSignature>),
}

impl AtpBatchSignatures {
    pub fn api_arg_to_vec(api_argument: Option<AtpBatchSignatures>) -> Vec<TxAtpSignature> {
        match api_argument {
            // If the signature is one, then just wrap it around the vector
            Some(AtpBatchSignatures::Single(single_signature)) => {
                vec![single_signature]
            }
            Some(AtpBatchSignatures::Multi(signatures)) => signatures,
            None => Vec::new(),
        }
    }
}

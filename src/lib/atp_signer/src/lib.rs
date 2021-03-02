#[macro_use]
extern crate serde_derive;

use async_trait::async_trait;
use error::SignerError;
use zkdpos_types::tx::TxAtpSignature;
use zkdpos_types::Address;

pub use json_rpc_signer::JsonRpcSigner;
pub use pk_signer::PrivateKeySigner;
pub use raw_alaya_tx::RawTransaction;

pub mod error;
pub mod json_rpc_signer;
pub mod pk_signer;
pub mod raw_alaya_tx;

#[async_trait]
pub trait AlayaSigner: Send + Sync + Clone {
    async fn sign_message(&self, message: &[u8]) -> Result<TxAtpSignature, SignerError>;
    async fn sign_transaction(&self, raw_tx: RawTransaction) -> Result<Vec<u8>, SignerError>;
    async fn get_address(&self) -> Result<Address, SignerError>;
}

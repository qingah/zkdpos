// Built-in imports
use std::{fmt, sync::Mutex};
// External uses
use num::BigUint;
// Workspace uses
use zkdpos_basic_types::H256;
use zkdpos_crypto::rand::{thread_rng, Rng};
use zkdpos_crypto::{priv_key_from_fs, PrivateKey};
use zkdpos_types::tx::{
    ChangePubKey, ChangePubKeyECDSAData, ChangePubKeyAtpAuthData, PackedAtpSignature, TimeRange,
    TxSignature,
};
use zkdpos_types::{
    AccountId, Address, Close, ForcedExit, Nonce, PubKeyHash, TokenId, Transfer, Withdraw,
};

/// Structure used to sign ZKDpos transactions, keeps tracks of its nonce internally
pub struct ZkDposAccount {
    pub private_key: PrivateKey,
    pub pubkey_hash: PubKeyHash,
    pub address: Address,
    pub atp_private_key: H256,
    account_id: Mutex<Option<AccountId>>,
    nonce: Mutex<Nonce>,
}

impl Clone for ZkDposAccount {
    fn clone(&self) -> Self {
        Self {
            private_key: priv_key_from_fs(self.private_key.0),
            pubkey_hash: self.pubkey_hash,
            address: self.address,
            atp_private_key: self.atp_private_key,
            account_id: Mutex::new(*self.account_id.lock().unwrap()),
            nonce: Mutex::new(*self.nonce.lock().unwrap()),
        }
    }
}

impl fmt::Debug for ZkDposAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // It is OK to disclose the private key contents for a testkit account.
        let mut pk_contents = Vec::new();
        self.private_key
            .write(&mut pk_contents)
            .expect("Failed writing the private key contents");

        f.debug_struct("ZkDposAccount")
            .field("private_key", &pk_contents)
            .field("pubkey_hash", &self.pubkey_hash)
            .field("address", &self.address)
            .field("atp_private_key", &self.atp_private_key)
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl ZkDposAccount {
    /// Note: probably not secure, use for testing.
    pub fn rand() -> Self {
        let rng = &mut thread_rng();

        let pk = priv_key_from_fs(rng.gen());
        let (atp_pk, atp_address) = {
            let atp_pk = rng.gen::<[u8; 32]>().into();
            let atp_address;
            loop {
                if let Ok(address) = PackedAtpSignature::address_from_private_key(&atp_pk) {
                    atp_address = address;
                    break;
                }
            }
            (atp_pk, atp_address)
        };
        Self::new(pk, Nonce(0), atp_address, atp_pk)
    }

    pub fn new(
        private_key: PrivateKey,
        nonce: Nonce,
        address: Address,
        atp_private_key: H256,
    ) -> Self {
        let pubkey_hash = PubKeyHash::from_privkey(&private_key);
        assert_eq!(
            address,
            PackedAtpSignature::address_from_private_key(&atp_private_key)
                .expect("private key is incorrect"),
            "address should correspond to private key"
        );
        Self {
            account_id: Mutex::new(None),
            address,
            private_key,
            pubkey_hash,
            atp_private_key,
            nonce: Mutex::new(nonce),
        }
    }

    pub fn nonce(&self) -> Nonce {
        let n = self.nonce.lock().unwrap();
        *n
    }

    pub fn set_nonce(&self, new_nonce: Nonce) {
        *self.nonce.lock().unwrap() = new_nonce;
    }

    pub fn set_account_id(&self, account_id: Option<AccountId>) {
        *self.account_id.lock().unwrap() = account_id;
    }

    pub fn get_account_id(&self) -> Option<AccountId> {
        *self.account_id.lock().unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_transfer(
        &self,
        token_id: TokenId,
        token_symbol: &str,
        amount: BigUint,
        fee: BigUint,
        to: &Address,
        nonce: Option<Nonce>,
        increment_nonce: bool,
        time_range: TimeRange,
    ) -> (Transfer, PackedAtpSignature) {
        let mut stored_nonce = self.nonce.lock().unwrap();
        let transfer = Transfer::new_signed(
            self.account_id
                .lock()
                .unwrap()
                .expect("can't sign tx without account id"),
            self.address,
            *to,
            token_id,
            amount,
            fee,
            nonce.unwrap_or_else(|| *stored_nonce),
            time_range,
            &self.private_key,
        )
        .expect("Failed to sign transfer");

        if increment_nonce {
            **stored_nonce += 1;
        }

        let message = transfer.get_alaya_sign_message(token_symbol, 18);
        let atp_signature = PackedAtpSignature::sign(&self.atp_private_key, &message.as_bytes())
            .expect("Signing the transfer unexpectedly failed");
        (transfer, atp_signature)
    }

    pub fn sign_forced_exit(
        &self,
        token_id: TokenId,
        fee: BigUint,
        target: &Address,
        nonce: Option<Nonce>,
        increment_nonce: bool,
        time_range: TimeRange,
    ) -> ForcedExit {
        let mut stored_nonce = self.nonce.lock().unwrap();
        let forced_exit = ForcedExit::new_signed(
            self.account_id
                .lock()
                .unwrap()
                .expect("can't sign tx without account id"),
            *target,
            token_id,
            fee,
            nonce.unwrap_or_else(|| *stored_nonce),
            time_range,
            &self.private_key,
        )
        .expect("Failed to sign forced exit");

        if increment_nonce {
            **stored_nonce += 1;
        }

        forced_exit
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_withdraw(
        &self,
        token_id: TokenId,
        token_symbol: &str,
        amount: BigUint,
        fee: BigUint,
        atp_address: &Address,
        nonce: Option<Nonce>,
        increment_nonce: bool,
        time_range: TimeRange,
    ) -> (Withdraw, PackedAtpSignature) {
        let mut stored_nonce = self.nonce.lock().unwrap();
        let withdraw = Withdraw::new_signed(
            self.account_id
                .lock()
                .unwrap()
                .expect("can't sign tx without account id"),
            self.address,
            *atp_address,
            token_id,
            amount,
            fee,
            nonce.unwrap_or_else(|| *stored_nonce),
            time_range,
            &self.private_key,
        )
        .expect("Failed to sign withdraw");

        if increment_nonce {
            **stored_nonce += 1;
        }

        let message = withdraw.get_alaya_sign_message(token_symbol, 18);
        let atp_signature = PackedAtpSignature::sign(&self.atp_private_key, &message.as_bytes())
            .expect("Signing the withdraw unexpectedly failed");
        (withdraw, atp_signature)
    }

    pub fn sign_close(&self, nonce: Option<Nonce>, increment_nonce: bool) -> Close {
        let mut stored_nonce = self.nonce.lock().unwrap();
        let mut close = Close {
            account: self.address,
            nonce: nonce.unwrap_or_else(|| *stored_nonce),
            signature: TxSignature::default(),
            time_range: Default::default(),
        };
        close.signature = TxSignature::sign_musig(&self.private_key, &close.get_bytes());

        if increment_nonce {
            **stored_nonce += 1;
        }
        close
    }

    pub fn sign_change_pubkey_tx(
        &self,
        nonce: Option<Nonce>,
        increment_nonce: bool,
        fee_token: TokenId,
        fee: BigUint,
        auth_onchain: bool,
        time_range: TimeRange,
    ) -> ChangePubKey {
        let account_id = self
            .account_id
            .lock()
            .unwrap()
            .expect("can't sign tx withoud account id");
        let mut stored_nonce = self.nonce.lock().unwrap();
        let nonce = nonce.unwrap_or_else(|| *stored_nonce);

        let mut change_pubkey = ChangePubKey::new_signed(
            account_id,
            self.address,
            self.pubkey_hash,
            fee_token,
            fee,
            nonce,
            time_range,
            None,
            &self.private_key,
        )
        .expect("Can't sign ChangePubKey operation");
        change_pubkey.atp_auth_data = if auth_onchain {
            Some(ChangePubKeyAtpAuthData::Onchain)
        } else {
            let sign_bytes = change_pubkey
                .get_atp_signed_data()
                .expect("Failed to construct change pubkey signed message.");
            let atp_signature = PackedAtpSignature::sign(&self.atp_private_key, &sign_bytes)
                .expect("Signature should succeed");
            Some(ChangePubKeyAtpAuthData::ECDSA(ChangePubKeyECDSAData {
                atp_signature,
                batch_hash: H256::zero(),
            }))
        };

        assert!(
            change_pubkey.is_atp_auth_data_valid(),
            "atp auth data is incorrect"
        );

        if increment_nonce {
            **stored_nonce += 1;
        }

        change_pubkey
    }
}

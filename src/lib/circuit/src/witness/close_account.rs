// External deps
use zkdpos_crypto::franklin_crypto::{
    bellman::pairing::{
        bn256::{Bn256, Fr},
        ff::{Field, PrimeField},
    },
    rescue::RescueEngine,
};
// Workspace deps
use zkdpos_crypto::{
    circuit::{
        account::CircuitAccountTree,
        utils::{append_be_fixed_width, le_bit_vector_into_field_element},
    },
    params::{
        account_tree_depth, ACCOUNT_ID_BIT_WIDTH, CHUNK_BIT_WIDTH, NEW_PUBKEY_HASH_WIDTH,
        NONCE_BIT_WIDTH, TX_TYPE_BIT_WIDTH,
    },
};
use zkdpos_types::operations::CloseOp;
// Local deps
use crate::{
    operation::{Operation, OperationArguments, OperationBranch, OperationBranchWitness},
    utils::resize_grow_only,
    witness::{
        utils::{apply_leaf_operation, get_audits, SigDataInput},
        Witness,
    },
};

pub struct CloseAccountData {
    pub account_address: u32,
}
pub struct CloseAccountWitness<E: RescueEngine> {
    pub before: OperationBranch<E>,
    pub after: OperationBranch<E>,
    pub args: OperationArguments<E>,
    pub before_root: Option<E::Fr>,
    pub after_root: Option<E::Fr>,
    pub tx_type: Option<E::Fr>,
}

impl Witness for CloseAccountWitness<Bn256> {
    type OperationType = CloseOp;
    type CalculateOpsInput = SigDataInput;

    fn apply_tx(tree: &mut CircuitAccountTree, close_account: &CloseOp) -> Self {
        let close_acoount_data = CloseAccountData {
            account_address: *close_account.account_id,
        };
        Self::apply_data(tree, &close_acoount_data)
    }

    fn get_pubdata(&self) -> Vec<bool> {
        let mut pubdata_bits = vec![];
        append_be_fixed_width(&mut pubdata_bits, &self.tx_type.unwrap(), TX_TYPE_BIT_WIDTH);

        append_be_fixed_width(
            &mut pubdata_bits,
            &self.before.address.unwrap(),
            ACCOUNT_ID_BIT_WIDTH,
        );

        resize_grow_only(&mut pubdata_bits, CloseOp::CHUNKS * CHUNK_BIT_WIDTH, false);
        pubdata_bits
    }

    fn get_offset_commitment_data(&self) -> Vec<bool> {
        vec![false; CloseOp::CHUNKS * 8]
    }

    fn calculate_operations(&self, input: SigDataInput) -> Vec<Operation<Bn256>> {
        let pubdata_chunks: Vec<_> = self
            .get_pubdata()
            .chunks(CHUNK_BIT_WIDTH)
            .map(|x| le_bit_vector_into_field_element(&x.to_vec()))
            .collect();
        let operation_zero = Operation {
            new_root: self.after_root,
            tx_type: self.tx_type,
            chunk: Some(Fr::from_str("0").unwrap()),
            pubdata_chunk: Some(pubdata_chunks[0]),
            first_sig_msg: Some(input.first_sig_msg),
            second_sig_msg: Some(input.second_sig_msg),
            third_sig_msg: Some(input.third_sig_msg),
            signature_data: input.signature.clone(),
            signer_pub_key_packed: input.signer_pub_key_packed.to_vec(),
            args: self.args.clone(),
            lhs: self.before.clone(),
            rhs: self.before.clone(),
        };

        let operations: Vec<Operation<_>> = vec![operation_zero];
        operations
    }
}

impl<E: RescueEngine> CloseAccountWitness<E> {
    pub fn get_sig_bits(&self) -> Vec<bool> {
        let mut sig_bits = vec![];
        append_be_fixed_width(
            &mut sig_bits,
            &Fr::from_str("4").unwrap(), //Corresponding tx_type
            TX_TYPE_BIT_WIDTH,
        );
        append_be_fixed_width(
            &mut sig_bits,
            &self.before.witness.account_witness.pub_key_hash.unwrap(),
            NEW_PUBKEY_HASH_WIDTH,
        );

        append_be_fixed_width(
            &mut sig_bits,
            &self.before.witness.account_witness.nonce.unwrap(),
            NONCE_BIT_WIDTH,
        );
        sig_bits
    }
}

impl CloseAccountWitness<Bn256> {
    fn apply_data(tree: &mut CircuitAccountTree, close_account: &CloseAccountData) -> Self {
        //preparing data and base witness
        let before_root = tree.root_hash();
        vlog::debug!("Initial root = {}", before_root);
        let (audit_path_before, audit_balance_path_before) =
            get_audits(tree, close_account.account_address, 0);

        let capacity = tree.capacity();
        assert_eq!(capacity, 1 << account_tree_depth());
        let account_address_fe = Fr::from_str(&close_account.account_address.to_string()).unwrap();

        //calculate a and b
        let a = Fr::zero();
        let b = Fr::zero();

        //applying close_account
        let (account_witness_before, account_witness_after, balance_before, balance_after) =
            apply_leaf_operation(
                tree,
                close_account.account_address,
                0,
                |acc| {
                    acc.pub_key_hash = Fr::zero();
                    acc.nonce = Fr::zero();
                },
                |_| {},
            );

        let after_root = tree.root_hash();
        vlog::debug!("After root = {}", after_root);
        let (audit_path_after, audit_balance_path_after) =
            get_audits(tree, close_account.account_address, 0);

        CloseAccountWitness {
            before: OperationBranch {
                address: Some(account_address_fe),
                token: Some(Fr::zero()),
                witness: OperationBranchWitness {
                    account_witness: account_witness_before,
                    account_path: audit_path_before,
                    balance_value: Some(balance_before),
                    balance_subtree_path: audit_balance_path_before,
                },
            },
            after: OperationBranch {
                address: Some(account_address_fe),
                token: Some(Fr::zero()),
                witness: OperationBranchWitness {
                    account_witness: account_witness_after,
                    account_path: audit_path_after,
                    balance_value: Some(balance_after),
                    balance_subtree_path: audit_balance_path_after,
                },
            },
            args: OperationArguments {
                atp_address: Some(Fr::zero()),
                amount_packed: Some(Fr::zero()),
                full_amount: Some(Fr::zero()),
                pub_nonce: Some(Fr::zero()),
                fee: Some(Fr::zero()),
                a: Some(a),
                b: Some(b),
                new_pub_key_hash: Some(Fr::zero()),
                valid_from: Some(Fr::zero()),
                valid_until: Some(Fr::from_str(&u32::MAX.to_string()).unwrap()),
            },
            before_root: Some(before_root),
            after_root: Some(after_root),
            tx_type: Some(Fr::from_str("4").unwrap()),
        }
    }
}

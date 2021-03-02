use crate::tests::{AccountState::*, PlasmaTestBuilder};
use num::{BigUint, Zero};
use web3::types::H160;
use zkdpos_types::priority_ops::{Deposit, FullExit};
use zkdpos_types::{account::AccountUpdate, AccountId, Nonce, TokenId, ZkDposPriorityOp};

/// Check Deposit to existing account
#[test]
fn deposit_to_existing() {
    let token = TokenId(0);
    let amount = BigUint::from(100u32);
    let mut tb = PlasmaTestBuilder::new();
    let (account_id, account, _) = tb.add_account(Locked);

    let deposit = Deposit {
        from: account.address,
        to: account.address,
        amount,
        token,
    };

    tb.test_priority_op_success(
        ZkDposPriorityOp::Deposit(deposit),
        &[(
            account_id,
            AccountUpdate::UpdateBalance {
                old_nonce: account.nonce,
                new_nonce: account.nonce,
                balance_update: (token, BigUint::zero(), BigUint::from(100u32)),
            },
        )],
    )
}

/// Check Deposit to new account
#[test]
fn deposit_to_new() {
    let token = TokenId(0);
    let amount = BigUint::from(100u32);
    let mut tb = PlasmaTestBuilder::new();
    let address = H160::random();
    let account_id = tb.state.get_free_account_id();

    let deposit = Deposit {
        from: address,
        to: address,
        amount,
        token,
    };

    tb.test_priority_op_success(
        ZkDposPriorityOp::Deposit(deposit),
        &[
            (
                account_id,
                AccountUpdate::Create {
                    address,
                    nonce: Nonce(0),
                },
            ),
            (
                account_id,
                AccountUpdate::UpdateBalance {
                    old_nonce: Nonce(0),
                    new_nonce: Nonce(0),
                    balance_update: (token, BigUint::zero(), BigUint::from(100u32)),
                },
            ),
        ],
    )
}

/// Check failure of FullExit operation for non-existent account
#[test]
fn full_exit_non_existent() {
    let token = TokenId(0);
    let atp_address = H160::random();
    let mut tb = PlasmaTestBuilder::new();

    let full_exit = FullExit {
        token,
        atp_address,
        account_id: AccountId(145),
    };

    tb.test_priority_op_success(ZkDposPriorityOp::FullExit(full_exit), &[])
}

/// Check successfull FullExit
#[test]
fn full_exit_success() {
    let token = TokenId(0);
    let amount = BigUint::from(145u32);
    let mut tb = PlasmaTestBuilder::new();
    let (account_id, account, _) = tb.add_account(Locked);
    tb.set_balance(account_id, token, amount.clone());

    let full_exit = FullExit {
        token,
        atp_address: account.address,
        account_id,
    };

    tb.test_priority_op_success(
        ZkDposPriorityOp::FullExit(full_exit),
        &[(
            account_id,
            AccountUpdate::UpdateBalance {
                old_nonce: account.nonce,
                new_nonce: account.nonce,
                balance_update: (token, amount, BigUint::zero()),
            },
        )],
    )
}

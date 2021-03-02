# zkDpos types. Essential types for the zkDpos network

`zkdpos_types` is a crate containing essential zkDpos network types, such as transactions, operations and blockchain
primitives.

zkDpos operations are split into the following categories:

- **transactions**: operations of zkDpos network existing purely in the L2. Currently includes `Transfer`, `Withdraw`,
  `ChangePubKey` and `ForcedExit`. All the transactions form an enum named `ZkDposTx`.
- **priority operations**: operations of zkDpos network which are triggered by invoking the zkDpos smart contract method
  in L1. These operations are discovered by the zkDpos server and included into the block just like L2 transactions.
  Currently includes `Deposit` and `FullExit`. All the priority operations form an enum named `ZkDposPriorityOp`.
- **operations**: a superset of `ZkDposTx` and `ZkDposPriorityOp`. All the operations are included into an enum named
  `ZkDposOp`. This enum contains all the items that can be included into the block, together with meta-information about
  each transaction. Main difference of operation from transaction/priority operation is that it can form public data
  required for the committing the block on the L1.

## License

`zkdpos_types` is a part of zkDpos stack, which is distributed under the terms of the MIT license.

See [LICENSE-MIT](../../LICENSE-MIT) for details.

// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

enum TxType {
    CreateAccount,
    ManageCredential,
    ManageCredentialPassword,
    AddWallet,
    AddWalletPassword,
    RemoveWallet,
    RemoveWalletPassword
}

enum CredentialAction {
    Add,
    Remove
}
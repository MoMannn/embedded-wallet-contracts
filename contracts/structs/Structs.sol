// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

import {IAccount} from "../interfaces/IAccount.sol";
import {CosePublicKey,AuthenticatorResponse} from "../lib/WebAuthN.sol";
import {CredentialAction} from "../enums/Enums.sol";
import {WalletType} from "../AccountFactory.sol";

struct UserCredential {
    uint256[2] pubkey;
    bytes credentialId;
    bytes32 username;
}

struct User {
    bytes32 username;
    bytes32 password;
    IAccount[5] accounts; // 0=EVM, 1=SUBSTRATE, 2=BITCOIN, 3=TBD, 4=TBD, 5=TBD
}

struct GaslessData {
    bytes funcData;
    uint8 txType;
}

struct ActionCred {
    bytes32 credentialIdHashed;
    AuthenticatorResponse resp;
    bytes data;
}

struct ActionPass {
    bytes32 hashedUsername;
    bytes32 digest;
    bytes data;
}

struct Credential {
    bytes credentialId;
    CosePublicKey pubkey;
    CredentialAction action;
}

struct NewAccount {
    bytes32 hashedUsername;
    bytes credentialId;
    CosePublicKey pubkey;
    bytes32 optionalPassword;
    WalletData wallet;
}

struct WalletData {
    WalletType walletType;
    bytes32 keypairSecret; // if 0x000.. then generate new
}

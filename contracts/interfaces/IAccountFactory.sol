// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

import {WalletType} from "./../AccountFactory.sol";

interface IAccountFactory {
    function clone (
        address starterOwner, 
        WalletType walletType,
        bytes32 keypairSecret
    ) external returns (address acct);
}
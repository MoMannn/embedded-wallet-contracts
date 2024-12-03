// SPDX-License-Identifier: CC-PDDC

pragma solidity ^0.8.0;

import {Account,AccountFactory,WalletType} from "../Account.sol";

contract TestAccount {
    AccountFactory private factory;
    event CloneCreated(address addr);
    constructor () {
        factory = new AccountFactory();
    }
    function testClone()
        public
    {
        Account acct = factory.clone(msg.sender, WalletType.EVM, bytes32(0), "Test wallet");
        emit CloneCreated(address(acct));
    }
}

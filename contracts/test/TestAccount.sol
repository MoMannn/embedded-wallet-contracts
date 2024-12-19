// SPDX-License-Identifier: CC-PDDC

pragma solidity ^0.8.0;

import {AccountEVM} from "../AccountEVM.sol";
import {AccountFactory,WalletType} from "../AccountFactory.sol";

contract TestAccount {
    AccountFactory private factory;
    event CloneCreated(address addr);
    constructor () {
        factory = new AccountFactory();
    }
    function testClone()
        public
    {
        AccountEVM acct = AccountEVM(
            factory.clone(msg.sender, WalletType.EVM, bytes32(0), "Test wallet")
        );
        emit CloneCreated(address(acct));
    }
}

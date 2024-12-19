// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

import {CloneFactory} from "./lib/CloneFactory.sol";
import {AccountEVM} from "./AccountEVM.sol";

enum WalletType {
    EVM,
    SUBSTRATE,
    BITCOIN
}

contract AccountFactory is CloneFactory {
    AccountEVM private accountEVM;

    constructor () {
        accountEVM = new AccountEVM();
    }

    function clone (
        address starterOwner,
        WalletType walletType,
        bytes32 keypairSecret,
        string memory title
    )
        public
        returns (address)
    {
        if (walletType == WalletType.EVM) {
            AccountEVM acct = AccountEVM(createClone(address(accountEVM)));
            acct.init(
                starterOwner,
                keypairSecret,
                title
            );
            return address(acct);
        } else {
            revert("Action not supported!");
        }
    }
}

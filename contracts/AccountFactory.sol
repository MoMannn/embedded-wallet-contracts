// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {CloneFactory} from "./lib/CloneFactory.sol";
import {AccountEVM} from "./AccountEVM.sol";
import {AccountSubstrate} from "./AccountSubstrate.sol";

enum WalletType {
    EVM,
    SUBSTRATE,
    BITCOIN
}

contract AccountFactory is CloneFactory,
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable
{
    AccountEVM private accountEVM;
    AccountSubstrate private accountSubstrate;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor()  {
        _disableInitializers();
    }

    // Initializer instead of constructor
    function initialize() public payable initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();

        accountEVM = new AccountEVM();
        accountSubstrate = new AccountSubstrate();
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function clone (
        address starterOwner,
        WalletType walletType,
        bytes32 keypairSecret
    )
        public
        returns (address)
    {
        if (walletType == WalletType.EVM) {
            AccountEVM acct = AccountEVM(createClone(address(accountEVM)));
            acct.init(
                starterOwner,
                keypairSecret
            );
            return address(acct);

        } else  if (walletType == WalletType.SUBSTRATE) {
            AccountSubstrate acct = AccountSubstrate(createClone(address(accountSubstrate)));
            acct.init(
                starterOwner,
                keypairSecret
            );
            return address(acct);
            
        } else {
            revert("Action not supported!");
        }
    }
}

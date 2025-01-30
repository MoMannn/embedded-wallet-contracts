// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

abstract contract Account {
    bool internal _initialized;

    mapping(address => bool) internal _controllers;

    bytes32[] internal wallets;

    mapping(bytes32 => bytes32) internal walletSecret;

    constructor () {
        _initialized = true;
    }

    function isController (address who)
        public view
        returns (bool)
    {
        return _controllers[who];
    }

    function init (
        address initialController, 
        bytes32 keypairSecret
    )
        public virtual
    {
        require( ! _initialized, "AlreadyInitialized" );

        _controllers[initialController] = true;

        _createWallet(keypairSecret);

        _initialized = true;
    }

    modifier onlyByController ()
    {
        require( _controllers[msg.sender] == true, "OnlyByController" );

        _;
    }

    modifier onlyActiveWallet (uint256 walletId)
    {
        require(walletId < wallets.length, "Invalid wallet id");
        require(wallets[walletId] != bytes32(0), "Wallet removed");

        _;
    }

    function modifyController(address who, bool status)
        public
        onlyByController
    {
        _controllers[who] = status;
    }

    function getWalletList ()
        public virtual view 
        onlyByController
        returns (bytes32[] memory) 
    {
        return wallets;
    }

    function walletAddress (uint256 walletId)
        public virtual view 
        onlyByController
        onlyActiveWallet(walletId)
        returns (bytes32) 
    {
        return wallets[walletId];
    }

    function exportPrivateKey (uint256 walletId)
        public virtual view
        onlyByController
        onlyActiveWallet(walletId)
        returns (bytes32)
    {
        return walletSecret[wallets[walletId]];
    }

    function removeWallet (
        uint256 walletId
    )
        external virtual
        onlyByController
        onlyActiveWallet(walletId)
    {
        bytes32 publicKey = wallets[walletId];

        // Remove privateKey / secretKey
        walletSecret[publicKey] = bytes32(0);
        
        // Remove publicKey from list
        wallets[walletId] = bytes32(0);

        _afterRemoveWallet(publicKey);
    }

    function _afterRemoveWallet(bytes32 publicKey) internal virtual {}

    function transfer (address in_target, uint256 amount)
        public virtual
        onlyByController
    {
        return payable(in_target).transfer(amount);
    }

    function call (address in_contract, bytes calldata in_data)
        public virtual
        onlyByController
        returns (bytes memory out_data)
    {
        bool success;
        (success, out_data) = in_contract.call(in_data);
        assembly {
            switch success
            case 0 { revert(add(out_data,32),mload(out_data)) }
        }
    }

    function staticcall (address in_contract, bytes calldata in_data)
        public virtual view
        onlyByController
        returns (bytes memory out_data)
    {
        bool success;
        (success, out_data) = in_contract.staticcall(in_data);
        assembly {
            switch success
            case 0 { revert(add(out_data,32),mload(out_data)) }
        }
    }

    function createWallet (
        bytes32 keypairSecret
    )
        external
        onlyByController
        returns (address) 
    {
        return _createWallet(keypairSecret);
    }

    /**
      * PRIVATE FUNCTIONS 
      */
    function _createWallet (
        bytes32 keypairSecret
    ) internal virtual returns (address);
}

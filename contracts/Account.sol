// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

/**
 * @dev Account contract serves as a skeleton and contains all parameters and functions
 * that each chain account should have. Each chain type (EVM, Substrate, Bitcoin, etc...),
 * should have its own contract extending this one.
 */
abstract contract Account {
    bool internal _initialized;

    mapping(address => bool) internal _controllers;

    bytes32[] internal wallets;

    mapping(bytes32 => bytes32) internal walletSecret;

    event WalletCreated(bytes32 indexed publicAddress);

    constructor () {
        _initialized = true;
    }

    /**
     * @dev Checks if an address is a controller
     *
     * @param who address to check
     */
    function isController (address who)
        public view
        returns (bool)
    {
        return _controllers[who];
    }

    /**
     * @dev Initializes the account
     *
     * @param initialController initial controller
     * @param keypairSecret private/secret key if importing an existing address (otherwise bytes32(0) to create new)
     */
    function init (
        address initialController, 
        bytes32 keypairSecret
    )
        public virtual
    {
        require( ! _initialized, "AlreadyInitialized" );

        _controllers[initialController] = true;

        bytes32 publicAddress = _createWallet(keypairSecret);
        emit WalletCreated(publicAddress);

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

    /**
     * @dev Modifies a controller
     *
     * @param who address
     * @param status true/false if whitelisted or not
     */
    function modifyController(address who, bool status)
        public
        onlyByController
    {
        require(who != address(0), "Invalid address");
        _controllers[who] = status;
    }

    /**
     * @dev Get wallet list linked to account contract
     */
    function getWalletList ()
        public virtual view 
        onlyByController
        returns (bytes32[] memory) 
    {
        return wallets;
    }

    /**
     * @dev Get wallet address
     *
     * @param walletId index in wallets list
     */
    function walletAddress (uint256 walletId)
        public virtual view 
        onlyByController
        onlyActiveWallet(walletId)
        returns (bytes32) 
    {
        return wallets[walletId];
    }

    /**
     * @dev Exports private/secret key
     *
     * @param walletId index in wallets list
     */
    function exportPrivateKey (uint256 walletId)
        public virtual view
        onlyByController
        onlyActiveWallet(walletId)
        returns (bytes32)
    {
        return walletSecret[wallets[walletId]];
    }

    /**
     * @dev Remove wallet (all params are set to 0x0)
     *
     * @param walletId index in wallets list
     */
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

    /**
     * @dev After remove wallet hook
     *
     * @param publicKey public key of address being removed
     */
    function _afterRemoveWallet(bytes32 publicKey) internal virtual {}

    /**
     * @dev Transfer function in case any ETH gets stuck in account contract
     *
     * @param in_target receipient
     * @param amount amount to be sent
     */
    function transfer (address in_target, uint256 amount)
        public virtual
        onlyByController
    {
        return payable(in_target).transfer(amount);
    }

    /**
     * @dev Low level call to be performed
     *
     * @param in_contract target contract
     * @param in_data target data
     */
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

    /**
     * @dev Low level staticall to be performed
     *
     * @param in_contract target contract
     * @param in_data target data
     */
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

    /**
     * @dev Create wallet
     *
     * @param keypairSecret private/secret key if importing an existing address (otherwise bytes32(0) to create new)
     */
    function createWallet (
        bytes32 keypairSecret
    )
        external
        onlyByController
        returns (bytes32 publicAddress) 
    {
        publicAddress = _createWallet(keypairSecret);
        emit WalletCreated(publicAddress);
    }

    /**
      * @dev PRIVATE FUNCTIONS - to be integrated in account contract dedicated to specific chain
      */
    function _createWallet (
        bytes32 keypairSecret
    ) internal virtual returns (bytes32);
}

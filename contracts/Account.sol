// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

import {SignatureRSV, EthereumUtils} from "@oasisprotocol/sapphire-contracts/contracts/EthereumUtils.sol";
import {EIP155Signer} from "@oasisprotocol/sapphire-contracts/contracts/EIP155Signer.sol";
import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";
import {CloneFactory} from "./lib/CloneFactory.sol";

enum WalletType {
    EVM,
    SUBSTRATE,
    BITCOIN
}

struct Wallet {
    WalletType walletType;
    address keypairAddress;
    string title;
}

contract AccountFactory is CloneFactory {
    Account private account;

    constructor () {
        account = new Account();
    }

    function clone (
        address starterOwner,
        WalletType walletType,
        bytes32 keypairSecret,
        string memory title
    )
        public
        returns (Account acct)
    {
        acct = Account(createClone(address(account)));
        acct.init(
            starterOwner,
            walletType,
            keypairSecret,
            title
        );
    }
}

contract Account {
    bool private _initialized;

    mapping(address => bool) private _controllers;

    Wallet[] private wallets;

    mapping(WalletType => mapping(address => bytes32)) private walletSecret;

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
        address starterOwner, 
        WalletType walletType,
        bytes32 keypairSecret,
        string memory title
    )
        public
    {
        require( ! _initialized, "AlreadyInitialized" );

        _controllers[starterOwner] = true;

        _createWallet(walletType, keypairSecret, title);

        _initialized = true;
    }

    modifier onlyByController ()
    {
        require( _controllers[msg.sender] == true, "OnlyByController" );

        _;
    }

    function modifyController(address who, bool status)
        public
        onlyByController
    {
        _controllers[who] = status;
    }

    function signEIP155 (uint256 walletId, EIP155Signer.EthTx calldata txToSign)
        public view
        onlyByController
        returns (bytes memory)
    {
        require(walletId < wallets.length, "Invalid wallet id");
        Wallet memory wal = wallets[walletId];

        return EIP155Signer.sign(
            wal.keypairAddress, 
            walletSecret[wal.walletType][wal.keypairAddress], 
            txToSign
        );
    }

    function sign (uint256 walletId, bytes32 digest)
        public view
        onlyByController
        returns (SignatureRSV memory)
    {
        require(walletId < wallets.length, "Invalid wallet id");
        Wallet memory wal = wallets[walletId];

        return EthereumUtils.sign(
            wal.keypairAddress, 
            walletSecret[wal.walletType][wal.keypairAddress], 
            digest
        );
    }

    function getWalletList ()
        public view 
        onlyByController
        returns (Wallet[] memory) 
    {
        return wallets;
    }

    function walletAddress (uint256 walletId)
        public view 
        onlyByController
        returns (address) 
    {
        require(walletId < wallets.length, "Invalid wallet id");
        return wallets[walletId].keypairAddress;
    }

    function exportPrivateKey (uint256 walletId)
        public view
        onlyByController
        returns (bytes32)
    {
        Wallet memory wal = wallets[walletId];
        return walletSecret[wal.walletType][wal.keypairAddress];
    }

    function transfer (address in_target, uint256 amount)
        public
        onlyByController
    {
        return payable(in_target).transfer(amount);
    }

    function call (address in_contract, bytes calldata in_data)
        public
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
        public view
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
        WalletType walletType,
        bytes32 keypairSecret,
        string memory title
    )
        external
        onlyByController
        returns (address) 
    {
        return _createWallet(walletType, keypairSecret, title);
    }

    function updateTitle (
        uint256 walletId,
        string memory title
    )
        external
        onlyByController
    {
        require(walletId < wallets.length, "Invalid wallet id");
        require(bytes(title).length > 0, "Title cannot be empty");
        wallets[walletId].title = title;
    }

    /**
      * PRIVATE FUNCTIONS 
      */
    function _createWallet (
        WalletType walletType,
        bytes32 keypairSecret,
        string memory title
    )
        private
        returns (address) 
    {
        require(wallets.length < 100, "Max 100 wallets per account");

        address keypairAddress;

        if (keypairSecret == bytes32(0)) {
            (keypairAddress, keypairSecret) = EthereumUtils.generateKeypair();

        } else {
            // Generate publicKey from privateKey
            bytes memory keypairSecretB = abi.encodePacked(keypairSecret);

            (bytes memory pk, ) = Sapphire.generateSigningKeyPair(
                Sapphire.SigningAlg.Secp256k1PrehashedKeccak256,
                keypairSecretB
            );

            keypairAddress = EthereumUtils.k256PubkeyToEthereumAddress(pk);
        }

        require(
            walletSecret[walletType][keypairAddress] == bytes32(0), 
            "Wallet already imported"
        );

        wallets.push(
            Wallet(
                walletType,
                keypairAddress,
                title
            )
        );

        walletSecret[walletType][keypairAddress] = keypairSecret;

        if (walletType == WalletType.EVM) {
            _controllers[keypairAddress] = true;
        }

        return keypairAddress;
    }
}

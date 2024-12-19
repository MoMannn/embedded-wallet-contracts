// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

import {SignatureRSV, EthereumUtils} from "@oasisprotocol/sapphire-contracts/contracts/EthereumUtils.sol";
import {EIP155Signer} from "@oasisprotocol/sapphire-contracts/contracts/EIP155Signer.sol";
import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";
import {Account, Wallet} from "./Account.sol";

contract AccountEVM is Account {

    function signEIP155 (uint256 walletId, EIP155Signer.EthTx calldata txToSign)
        public view
        onlyByController
        returns (bytes memory)
    {
        require(walletId < wallets.length, "Invalid wallet id");
        Wallet memory wal = wallets[walletId];

        return EIP155Signer.sign(
            wal.keypairAddress, 
            walletSecret[wal.keypairAddress], 
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
            walletSecret[wal.keypairAddress], 
            digest
        );
    }

    /**
      * PRIVATE FUNCTIONS 
      */
    function _createWallet (
        bytes32 keypairSecret,
        string memory title
    )
        internal override
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
            walletSecret[keypairAddress] == bytes32(0), 
            "Wallet already imported"
        );

        wallets.push(
            Wallet(
                keypairAddress,
                title
            )
        );

        walletSecret[keypairAddress] = keypairSecret;

        _controllers[keypairAddress] = true;

        return keypairAddress;
    }
}

// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

import {EIP155Signer} from "@oasisprotocol/sapphire-contracts/contracts/EIP155Signer.sol";
import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";
import {Account} from "./Account.sol";

contract AccountSubstrate is Account {

    function sign (uint256 walletId, bytes32 digest)
        public view
        onlyByController
        onlyActiveWallet(walletId)
        returns (bytes memory)
    {

        bytes memory signature = Sapphire.sign(
            Sapphire.SigningAlg.Sr25519,
            abi.encodePacked(walletSecret[wallets[walletId]]),
            abi.encodePacked(digest),
            ""
        );

        // rsv = splitDERSignature(signature);
        // recoverV(pubkeyAddr, digest, rsv);

        return signature;
    }

    /**
      * PRIVATE FUNCTIONS 
      */
    function _createWallet (
        bytes32 keypairSecret
    )
        internal override
        returns (bytes32) 
    {
        require(wallets.length < 100, "Max 100 wallets per account");

        bytes32 keypairAddress;

        if (keypairSecret == bytes32(0)) {
            bytes memory randSeed = Sapphire.randomBytes(32, "");

            (bytes memory pk, ) = Sapphire.generateSigningKeyPair(
                Sapphire.SigningAlg.Sr25519,
                randSeed
            );

            keypairAddress = bytes32(pk);
            keypairSecret = bytes32(randSeed);

        } else {
            // Generate publicKey from privateKey
            bytes memory keypairSecretB = abi.encodePacked(keypairSecret);

            (bytes memory pk, ) = Sapphire.generateSigningKeyPair(
                Sapphire.SigningAlg.Sr25519,
                keypairSecretB
            );

            keypairAddress = bytes32(pk);
        }

        require(
            walletSecret[keypairAddress] == bytes32(0), 
            "Wallet already imported"
        );

        wallets.push(keypairAddress);

        walletSecret[keypairAddress] = keypairSecret;

        return keypairAddress;
    }

}

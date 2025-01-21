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
            bytes32ToAddress(wal.keypairAddress), 
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
            bytes32ToAddress(wal.keypairAddress), 
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
            walletSecret[addressToBytes32(keypairAddress)] == bytes32(0), 
            "Wallet already imported"
        );

        wallets.push(
            Wallet(
                addressToBytes32(keypairAddress),
                title
            )
        );

        walletSecret[addressToBytes32(keypairAddress)] = keypairSecret;

        _controllers[keypairAddress] = true;

        return keypairAddress;
    }

    /**
     * @dev Converts an address to bytes32.
     * @param _addr The address to convert.
     * @return The bytes32 representation of the address.
     */
    function addressToBytes32(address _addr) public pure returns (bytes32) {
        return bytes32(uint256(uint160(_addr)));
    }

    /**
     * @dev Converts bytes32 to an address.
     * @param _b The bytes32 value to convert.
     * @return The address representation of bytes32.
     */
    function bytes32ToAddress(bytes32 _b) public pure returns (address) {
        return address(uint160(uint256(_b)));
    }

}

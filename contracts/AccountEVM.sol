// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

import {SignatureRSV, EthereumUtils} from "@oasisprotocol/sapphire-contracts/contracts/EthereumUtils.sol";
import {EIP155Signer} from "@oasisprotocol/sapphire-contracts/contracts/EIP155Signer.sol";
import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";
import {Account} from "./Account.sol";

contract AccountEVM is Account {

    /**
     * @dev Sign EIP155 transaction
     *
     * @param walletId wallet used to generate signature
     * @param txToSign transaction data
     */
    function signEIP155 (uint256 walletId, EIP155Signer.EthTx calldata txToSign)
        public view
        onlyByController
        onlyActiveWallet(walletId)
        returns (bytes memory)
    {

        return EIP155Signer.sign(
            bytes32ToAddress(wallets[walletId]), 
            walletSecret[wallets[walletId]], 
            txToSign
        );
    }

    /**
     * @dev Sign bytes32 digest
     *
     * @param walletId wallet used to generate signature
     * @param digest data to sign
     */
    function sign (uint256 walletId, bytes32 digest)
        public view
        onlyByController
        onlyActiveWallet(walletId)
        returns (SignatureRSV memory)
    {

        return EthereumUtils.sign(
            bytes32ToAddress(wallets[walletId]), 
            walletSecret[wallets[walletId]], 
            digest
        );
    }

    /**
     * @dev Create wallet
     *
     * @param keypairSecret private/secret key if importing an existing address (otherwise bytes32(0) to create new)
     */
    function _createWallet (
        bytes32 keypairSecret
    )
        internal override
        returns (bytes32) 
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

        bytes32 keypairAddressB32 = addressToBytes32(keypairAddress);

        require(
            walletSecret[keypairAddressB32] == bytes32(0), 
            "Wallet already imported"
        );

        wallets.push(keypairAddressB32);

        walletSecret[keypairAddressB32] = keypairSecret;

        _controllers[keypairAddress] = true;

        return keypairAddressB32;
    }


    function _afterRemoveWallet(bytes32 publicKey) internal override {
        // remove from authorized controllers
        _controllers[bytes32ToAddress(publicKey)] = false;
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

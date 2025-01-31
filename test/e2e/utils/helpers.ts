const { secp256r1 } = require('@noble/curves/p256');
const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");

const curve_utils = require('@noble/curves/abstract/utils');

export function hashedUsername (salt, username) {
    return pbkdf2Sync(username, salt, 100_000, 32, 'sha256');
}

export function generateNewKeypair() {
    const privateKey = secp256r1.utils.randomPrivateKey();
    const pubKey = secp256r1.getPublicKey(privateKey, false);
    const pubKeyString = "0x" + curve_utils.bytesToHex(pubKey);
    const credentialId = ethers.AbiCoder.defaultAbiCoder().encode([ "string" ], [ pubKeyString ]);

    const coordsString = pubKeyString.slice(4, pubKeyString.length); // removes 0x04
    const decoded_x = BigInt('0x' + coordsString.slice(0, 64)); // x is the first half
    const decoded_y = BigInt('0x' + coordsString.slice(64, coordsString.length)); // y is the second half

    return {
        credentialId,
        privateKey,
        decoded_x,
        decoded_y,
    }
}
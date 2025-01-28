const { ethers } = require("hardhat");
const { Keyring } = require("@polkadot/api");

const { sr25519PairFromSeed } = require('@polkadot/util-crypto');
const { hexToU8a, u8aToHex } = require('@polkadot/util');

describe("Substrate", function() {

  beforeEach(async () => {
    
  });

  it("Generate substrate keypair", async function() {

    // // Create a keyring instance
    // const keyring = new Keyring({ type: 'sr25519' });

    // // Some mnemonic phrase
    // const PHRASE = 'entire material egg meadow latin bargain dutch coral blood melt acoustic thought';

    // // Add an account, straight mnemonic
    // const newPair = keyring.addFromUri(PHRASE);

    // console.log(newPair);

    const secretKeyHex =
      "0xf896018d6ce114bc835963066128da863461842225b5e525342095a56dfad86e19a15552afae4c40c956adc4af79a9fb7d08b091ad6102c2cecffe48fe22ab30";
    const secretKey = hexToU8a(secretKeyHex);

    // Extract the first 32 bytes (the seed)
    const seed = secretKey.slice(0, 32);
    // const seed = "0x69efaf88fa06b7d79589912854812bf4c75231469bad8a21f607a2224997f5b8";
    const keypair = sr25519PairFromSeed(seed);

    console.log("Seed (32 bytes):", u8aToHex(seed));
    console.log("Public Key (32 bytes):", u8aToHex(keypair.publicKey));
    console.log("Secret Key (64 bytes):", u8aToHex(keypair.secretKey));

    /*
    substrate_pk: 0x8eebd3a86e6fff47e1c18b573d64ed2db202012815b271a2f98c69bfb3805374
    substrate_pk_bytes: 0x8eebd3a86e6fff47e1c18b573d64ed2db202012815b271a2f98c69bfb3805374
    ----------------------------
    substrate_sk: 0xf896018d6ce114bc835963066128da863461842225b5e525342095a56dfad86e
    substrate_sk_bytes: 0xf896018d6ce114bc835963066128da863461842225b5e525342095a56dfad86e19a15552afae4c40c956adc4af79a9fb7d08b091ad6102c2cecffe48fe22ab308eebd3a86e6fff47e1c18b573d64ed2db202012815b271a2f98c69bfb3805374
    */
    
  });

  
});
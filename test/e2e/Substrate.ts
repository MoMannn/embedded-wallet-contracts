const { expect } = require("chai");
const { ethers } = require("hardhat");
const { Keyring } = require("@polkadot/api");

const { sr25519PairFromSeed } = require('@polkadot/util-crypto');
const { u8aToHex } = require('@polkadot/util');

const { 
  SAPPHIRE_LOCALNET, 
  GAS_LIMIT,
  ACCOUNT_ABI,
  WALLET_TYPE_EVM,
  WALLET_TYPE_SUBSTRATE
} = require('./utils/constants');

const { hashedUsername, generateNewKeypair } = require('./utils/helpers');

describe("Substrate", function() {
  let WA, SALT, HELPER, owner, account1, account2, signer, gaspayingAddress;

  const SIMPLE_PASSWORD = "0x0000000000000000000000000000000000000000000000000000000000000001";
  const WRONG_PASSWORD  = "0x0000000000000000000000000000000000000000000000000000009999999999";

  const RANDOM_STRING  = "0x000000000000000000000000000000000000000000000000000000000000DEAD";

  const BYTES32_ZERO = "0x0000000000000000000000000000000000000000000000000000000000000000";

  const WALLET_IDX_0 = 0;
  const WALLET_IDX_1 = 1;

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  beforeEach(async () => {
    [ owner, account1, account2, signer ] = await ethers.getSigners();
    
    const helpFactory = await hre.ethers.getContractFactory("TestHelper");
    HELPER = await helpFactory.deploy();
    await HELPER.waitForDeployment();

    const curveFactory = await hre.ethers.getContractFactory("SECP256R1Precompile");
    const curveLibrary = await curveFactory.deploy();
    await curveLibrary.waitForDeployment();

    const accountFactoryFactory = await hre.ethers.getContractFactory("AccountFactory");
    const accountFactoryProxyFactory = await hre.ethers.getContractFactory("AccountFactoryProxy");
    const accountFactoryImpl = await accountFactoryFactory.deploy();
    await accountFactoryImpl.waitForDeployment();

    const AFProxy = await accountFactoryProxyFactory.deploy(
      await accountFactoryImpl.getAddress(),
      accountFactoryFactory.interface.encodeFunctionData('initialize', []),
    );
    await AFProxy.waitForDeployment();

    const contractFactory = await ethers.getContractFactory("AccountManager", {libraries: {SECP256R1Precompile: await curveLibrary.getAddress()}});
    const proxyFactory = await ethers.getContractFactory('AccountManagerProxy');
  
    const impl = await contractFactory.deploy();
    await impl.waitForDeployment();
    const WAProxy = await proxyFactory.deploy(
      await impl.getAddress(),
      contractFactory.interface.encodeFunctionData('initialize', [await AFProxy.getAddress(), signer.address]),
    );
    await WAProxy.waitForDeployment();

    WA = await ethers.getContractAt("AccountManager", await WAProxy.getAddress(), owner);

    gaspayingAddress = await WA.gaspayingAddress();
    await owner.sendTransaction({
      to: gaspayingAddress,
      value: ethers.parseEther("1.0"), // Sends exactly 1.0 ether to gaspaying address
    });

    SALT = ethers.toBeArray(await WA.salt());
  });

  it("Export PK of new account", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    expect(await WA.userExists(username)).to.equal(true);

    const iface = new ethers.Interface(ACCOUNT_ABI);
    const in_data = iface.encodeFunctionData('exportPrivateKey', [WALLET_IDX_0]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_SUBSTRATE, in_digest, in_data
    );

    const [exportedPrivateKey] = iface.decodeFunctionResult('exportPrivateKey', resp).toArray();

    const unlockedWallet = sr25519PairFromSeed(exportedPrivateKey);
    expect(accountData.publicKey).to.equal(u8aToHex(unlockedWallet.publicKey));
  });

  it("Import PK", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    expect(await WA.userExists(username)).to.equal(true);

    // generate substrate key with ethers
    const newWalletPK = ethers.Wallet.createRandom().privateKey;
    const newWallet = sr25519PairFromSeed(newWalletPK);
    
    const data = {
      walletType: WALLET_TYPE_SUBSTRATE,
      keypairSecret: newWalletPK
    };

    const encoded_data = abiCoder.encode(
      [ "tuple(uint256 walletType, bytes32 keypairSecret)" ], 
      [ data ]
    );

    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    let tx = await WA.addWalletPassword(
      {
        hashedUsername: username,
        digest,
        data: encoded_data
      }
    );
    await tx.wait();

    // Check if wallet correctly imported
    const accountWallets = await getAccountWallets(username);

    expect(accountWallets[0]).to.equal(accountData.publicKey);
    expect(accountWallets[1]).to.equal(u8aToHex(newWallet.publicKey));

    // Try to export, imported wallet
    const iface = new ethers.Interface(ACCOUNT_ABI);
    const in_data = iface.encodeFunctionData('exportPrivateKey', [WALLET_IDX_1]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_SUBSTRATE, in_digest, in_data
    );

    const [exportedPrivateKey] = iface.decodeFunctionResult('exportPrivateKey', resp).toArray();

    expect(exportedPrivateKey).to.equal(newWalletPK);
  });

  async function createAccount(username, password) {
    const keyPair = generateNewKeypair();

    let registerData = {
      hashedUsername: username,
      credentialId: keyPair.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair.decoded_x,
        y: keyPair.decoded_y,
      },
      optionalPassword: password,
      wallet: {
        walletType: WALLET_TYPE_SUBSTRATE,
        keypairSecret: BYTES32_ZERO // create new wallet
      }
    };

    const tx = await WA.createAccount(registerData);
    await tx.wait();

    const iface = new ethers.Interface(ACCOUNT_ABI);
    const in_data = iface.encodeFunctionData('walletAddress', [WALLET_IDX_0]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_SUBSTRATE, in_digest, in_data
    );

    let [publicKey] = iface.decodeFunctionResult('walletAddress', resp).toArray();

    return {
      ...registerData,
      publicKey,
      credentials: [
        keyPair
      ]
    }
  }

  async function getAccountWallets(username) {
    const iface = new ethers.Interface(ACCOUNT_ABI);
    const in_data = iface.encodeFunctionData('getWalletList', []);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_SUBSTRATE, in_digest, in_data
    );

    let [accountWallets] = iface.decodeFunctionResult('getWalletList', resp).toArray();

    return accountWallets;
  }
  
});
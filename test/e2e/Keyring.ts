import { extendEnvironment } from "hardhat/config";

const { expect } = require("chai");
const { ethers } = require("hardhat");
// const { u8aToU8a } = require('@polkadot/util-crypto');
const { u8aToHex, sr25519PairFromU8a, u8aToU8a } = require('@polkadot/util');

const {
  construct,
  decode,
  deriveAddress,
  getRegistry,
  methods,
  PolkadotSS58Format,
  createMetadata,
  createSignedTx,
  createSigningPayload
} = require('@substrate/txwrapper-polkadot');
const { EXTRINSIC_VERSION } = require('@polkadot/types/extrinsic/v4/Extrinsic');

describe("Keyring", function() {
  let owner, account1, account2, signer;
 
  beforeEach(async () => {
    [ owner, account1, account2, signer ] = await ethers.getSigners();
  });

  it("Keyring sign", async function() {

    // Import the API, Keyring and some utility functions
    const { ApiPromise, WsProvider, GenericExtrinsicV4, TypeRegistry } = require('@polkadot/api');
    const { Keyring } = require('@polkadot/keyring');

    const BOB = '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty';

    // Initialise the provider to connect to the local node
    // const provider = new WsProvider('wss://polkadot-asset-hub-rpc.polkadot.io');
    const provider = new WsProvider('wss://asset-hub-westend-rpc.dwellir.com');

    // Create the API and wait until ready
    const api = await ApiPromise.create({ provider });

    // Retrieve the chain & node information via rpc calls
    const [chain, nodeName, nodeVersion] = await Promise.all([
      api.rpc.system.chain(),
      api.rpc.system.name(),
      api.rpc.system.version()
    ]);

    console.log(`You are connected to chain ${chain} using ${nodeName} v${nodeVersion}`);
    console.log(`------------------------------------------------------------`);

    // Construct the keyring after the API (crypto has an async init)
    const keyring = new Keyring({ type: 'sr25519' });

    // Add Alice to our keyring with a hard-derivation path (empty phrase, so uses dev)
    // const alice = keyring.addFromUri('//Alice');
    // const alice = keyring.addFromMnemonic('canoe dizzy orphan hill shrug alien frequent core casual vapor energy fashion');
    const alice = keyring.addFromUri('0x4cea7f38eef57a59916a68b5cdbd20077a3c4a161a6c47cef8a2996c9067c7a9');

    // Create a extrinsic, transferring 12345 units to Bob
    const transfer = api.tx.balances.transferAllowDeath(BOB, 12345);
    // const transfer = api.tx.balances.transfer(BOB, 12345);

    // Retrieve the encoded calldata of the transaction
    // const encodedCalldata = transfer.method.toHex();
    // const encodedCalldata2 = transfer.toHex();
    // console.log(`Encoded calldata: ${encodedCalldata}`);
    // console.log(`Encoded calldata: ${encodedCalldata2}`);

    // console.log(transfer.version);
    // process.exit();

    // Get nonce
    let { nonce: non } = await api.query.system.account(alice.address);
    console.log('Nonce : '+non);

    // Get transaction details
    const info = await transfer.paymentInfo(alice);
    console.log('Estimated fees:', info.partialFee.toHuman());

    // Get transaction hex
    // const unsigned = transfer.toHex();
    // console.log('Unsigned transaction:', unsigned);

    // Sign the transaction
    // const signed = transfer.sign(alice);
    // const signed = await transfer.signAsync(alice);

    // const signedExtrinsic = signed.toJSON();
    // console.log(signedExtrinsic);


    // const tx = await api.rpc.author.submitExtrinsic(signedExtrinsic);

    // Submit the transaction
    // const txHash = await signed.send();
    // const signedExtrinsic = u8aToHex(signed);
    // const signedExtrinsic = signed.toJSON();

    // const tx = await api.rpc.author.submitExtrinsic(signedExtrinsic);

    // console.log(tx);

    // Create a payload
    const payload = api.createType('ExtrinsicPayload',{
        method: transfer.toHex(),
        nonce: non.toHex(),
        eraPeriod: 64,
        specVersion: api.runtimeVersion.specVersion,
        genesisHash: api.genesisHash,
        blockHash: api.genesisHash,
        tip: 0,
    }, { version: transfer.version });
    // console.log(payload);

    /*
    const txU8a = tx.toU8a();

    const signature = pair.sign(txU8a)
    const sigHex = u8aToHex(signature);
    */

    const signature = alice.sign(payload.toU8a(true), { withType: true });

    const signHex = u8aToHex(signature);
    // console.log(signHex);

    transfer.addSignature(alice.address, signHex, payload.toU8a(true));

    const hash = await transfer.send();
    console.log(hash);

    // const signature = alice.sign(transfer.toHex());
    // console.log(u8aToHex(signature));

    // console.log(Object.getOwnPropertyNames(transfer));

    // const { createSigningPayload } = require('@substrate/txwrapper-polkadot');

    // const signingPayload = createSigningPayload(transfer, { /*registry*/ });

    // const payload = api.createType('SignerPayload', {
    //   method: transfer,
    //   nonce: 0,
    //   genesisHash: api.genesisHash,
    //   blockHash: api.genesisHash,
    //   runtimeVersion: api.runtimeVersion,
    //   version: api.extrinsicVersion,
    // });

    // const raw = payload.toRaw();

    // const signature = alice.sign(raw.data);

    // const registry = new TypeRegistry();

    // const extrinsic = new GenericExtrinsicV4(
    //   transfer.registry,
    //   transfer
    //   // tx['balances']['transferAllowDeath'](keyring.bob.publicKey, 6969n)
    // )

    // console.log(extrinsic.toHex());
    // const signature = alice.sign(transfer.toHex());

    // const signedExtrinsic = u8aToHex(signature);

    // const tx = await api.rpc.author.submitExtrinsic(signedExtrinsic);
    process.exit();

    // const signature = alice.sign(transfer.toJSON())

    // console.log(signature);
    // console.log(u8aToHex(signature));
    // // console.log(transfer.toJSON());

    // const signed = await transfer.signAsync(alice);
    // const signedExtrinsic = signed.toJSON();
    // console.log(signedExtrinsic);


    // const tx = await api.rpc.author.submitExtrinsic(signedExtrinsic);

    // console.log(tx);

    // Sign and send the transaction using our account
    // const hash = await transfer.signAndSend(alice);

    // console.log('Transfer sent with hash', hash.toHex());
    
  });

  it("Sign v2", async function() {

    // Import the API, Keyring and some utility functions
    const { ApiPromise, WsProvider, GenericExtrinsicV4, TypeRegistry } = require('@polkadot/api');
    const { Keyring } = require('@polkadot/keyring');

    const BOB = '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty';

    // Initialise the provider to connect to the local node
    // const provider = new WsProvider('wss://polkadot-asset-hub-rpc.polkadot.io');
    const provider = new WsProvider('wss://asset-hub-westend-rpc.dwellir.com');

    // Create the API and wait until ready
    const api = await ApiPromise.create({ provider });

    // Retrieve the chain & node information via rpc calls
    const [chain, nodeName, nodeVersion] = await Promise.all([
      api.rpc.system.chain(),
      api.rpc.system.name(),
      api.rpc.system.version()
    ]);

    console.log(`You are connected to chain ${chain} using ${nodeName} v${nodeVersion}`);
    console.log(`------------------------------------------------------------`);

    // Construct the keyring after the API (crypto has an async init)
    const keyring = new Keyring({ type: 'sr25519' });

    // Add Alice to our keyring with a hard-derivation path (empty phrase, so uses dev)
    // const alice = keyring.addFromUri('//Alice');
    // const alice = keyring.addFromMnemonic('canoe dizzy orphan hill shrug alien frequent core casual vapor energy fashion');
    const alice = keyring.addFromUri('0x4cea7f38eef57a59916a68b5cdbd20077a3c4a161a6c47cef8a2996c9067c7a9');

    // Create a extrinsic, transferring 12345 units to Bob
    // const transfer = api.tx.balances.transferAllowDeath(BOB, 12345);

    const { specVersion, transactionVersion, specName } = await api.rpc.state.getRuntimeVersion();

    const { block } = await api.rpc.chain.getBlock();
    const blockHash = await api.rpc.chain.getBlockHash();
    const genesisHash = await (api.rpc.chain.getBlockHash())[0];
    const metadataRpc = await api.rpc.state.getMetadata();
    // const index = await httpRequest({ ...params, method: 'system_accountNextIndex', params: [pair.address] });
    const index = await api.rpc.system.accountNextIndex(alice.address);
    // let { nonce: non } = await api.query.system.account(alice.address);

    // console.log(block);
    // console.log(blockHash);
    // console.log(genesisHash);
    // console.log(metadataRpc);
    // console.log(index);

    // console.log(chain);
    // console.log(nodeName);

    const registry = api.registry;

    // const registry = getRegistry({
    //     chainName: 'Westend',
    //     specName: 'westend',
    //     specVersion: specVersion,
    //     metadataRpc: metadataRpc
    // });

    // Create a payload
    // const payload = api.createType('ExtrinsicPayload',{
    //     method: transfer.toHex(),
    //     nonce: index,
    //     eraPeriod: 64,
    //     specVersion: api.runtimeVersion.specVersion,
    //     genesisHash: api.genesisHash,
    //     blockHash: api.genesisHash,
    //     tip: 0,
    // }, { version: transfer.version });

    // const payloadRaw = payload.toU8a(true);
    // const payloadHex = u8aToHex(payloadRaw);

    // console.log(payload.toHex(true));

    // 0x0a00008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48e5c085031c000000ae840f001000000067f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c93241e5fa65b1e1ccafdd4442bea4ccc3de2de33f758b2f4071ca31c200db9f7f00

    // const unsigned = methods.balances.transferAllowDeath(
    //     {
    //         dest: BOB,
    //         value: 12345,
    //     },
    //     {
    //         address: alice.address,
    //         blockHash,
    //         blockNumber: registry
    //             .createType('BlockNumber', block.header.number)
    //             .toNumber(),
    //         eraPeriod: 64,
    //         genesisHash,
    //         metadataRpc,
    //         nonce: index,
    //         specVersion,
    //         tip: 0,
    //         transactionVersion,
    //     },
    //     { metadataRpc, registry }
    // );

    const unsigned = methods.balances.transferKeepAlive(
      {
        value: '12345',
        dest: { id: BOB }, // Bob
      },
      {
        address: alice.address,
        blockHash,
        blockNumber: registry
          .createType('BlockNumber', block.header.number)
          .toNumber(),
        eraPeriod: 64,
        genesisHash,
        metadataRpc,
        nonce: index, 
        specVersion,
        tip: 0,
        transactionVersion,
      },
      {
        metadataRpc,
        registry,
      },
    );

    const signingPayload = construct.signingPayload(unsigned, { registry });

    console.log(signingPayload);
    process.exit();

    // const signingPayload = createSigningPayload(unsigned, { registry });

    // const signingPayload = "0x0a00008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48e5c0750314000000ae840f001000000067f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c936b1f0a15b953dbb8b6a19f83091f9242de8eee3c4ed77a40bd53db96c4fb69500";

    // const decodedUnsigned = decode(unsigned, {
    //     metadataRpc: metadataRpc,
    //     registry: registry,
    // });
    // console.log(
    //     `\nDecoded Transaction\n  To: ${(decodedUnsigned.method.args.dest as { id: string })?.id
    //     }\n` + `  Amount: ${decodedUnsigned.method.args.value}`
    // );

    // process.exit();
    
    // On your offline device, sign the payload.
    registry.setMetadata(createMetadata(registry, metadataRpc));

    const exPayload = "0x0a00008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48e5c0b50118000000ae840f001000000067f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c977c7a4f3640f2b9f7c1dabc8d805a1d4dd964ce9f567edbca39f8a794288209b00";

    // const exPayload = registry
    //     .createType('ExtrinsicPayload', signingPayload, {
    //         version: EXTRINSIC_VERSION,
    //     })
    //     // .sign(alice);

    // console.log(exPayload.toHex());

    let signature2 = alice.sign(exPayload, { withType: true });
    signature2 = u8aToHex(signature2);

    // const signature = exPayload.sign(alice)

    console.log("signatures");
    console.log(signature2);
    // console.log(signature.signature);

    // const signedTx = createSignedTx(unsigned, signature, { metadataRpc, registry });
    const signedTx = construct.signedTx(unsigned, signature2, { metadataRpc, registry });

    // console.log(signature);

    // `tx` is ready to be broadcasted.
    // const signedExtrinsic = construct.signedTx(unsigned, signature.signature, { metadataRpc, registry });
    // console.log('tx', signedExtrinsic);

    const signedTx2 = "0x39028400d8a56418ddba88d53b611ea08007e35ec8c9f2bd031a3d3d68511abb5b4b446e01d84b965fbfbd1a8fc1ebf0acae4527596a0484320ad15ab414d1778593f29630565d87605840bc479beb15d268211f3f3a9c392dd8e02ecbe246cbd815c43a85b501180000000a00008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48e5c0";

    const tx = await api.rpc.author.submitExtrinsic(signedTx2);
    
  });

  it.only("Sign v3", async function() {
    const { block } = await rpcToLocalNode('chain_getBlock');
    const blockHash = await rpcToLocalNode('chain_getBlockHash');
    const genesisHash = await rpcToLocalNode('chain_getBlockHash', [0]);
    const metadataRpc = await rpcToLocalNode('state_getMetadata');
    const { specVersion, transactionVersion, specName } = await rpcToLocalNode(
      'state_getRuntimeVersion',
    );

    const registry = getRegistry({
      chainName: 'Westend',
      specName,
      specVersion,
      metadataRpc,
    });

    const BOB = '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty';

    const { Keyring } = require('@polkadot/keyring');
    const { GenericSignerPayload } = require('@polkadot/types');

    // Construct the keyring after the API (crypto has an async init)
    const keyring = new Keyring({ type: 'sr25519' });
    const alice = keyring.addFromUri('0x4cea7f38eef57a59916a68b5cdbd20077a3c4a161a6c47cef8a2996c9067c7a9');

    // const index = await api.rpc.system.accountNextIndex(alice.address);
    const index = await rpcToLocalNode('system_accountNextIndex', [alice.address]);

    const unsigned = methods.balances.transferAllowDeath(
      {
        value: '12345',
        dest: { id: BOB }, // Bob
      },
      {
        address: alice.address,
        blockHash,
        blockNumber: registry
          .createType('BlockNumber', block.header.number)
          .toNumber(),
        eraPeriod: 64,
        genesisHash,
        metadataRpc,
        nonce: index, // Assuming this is Alice's first tx on the chain
        specVersion,
        tip: 0,
        transactionVersion,
      },
      {
        metadataRpc,
        registry,
      },
    );

    // console.log(specVersion);
    // console.log(transactionVersion);
    // process.exit();

    // Decode an unsigned transaction.
    const decodedUnsigned = decode(unsigned, {
      metadataRpc,
      registry,
    });
    console.log(
      `\nDecoded Transaction\n  To: ${
        (decodedUnsigned.method.args.dest as { id: string })?.id
      }\n` + `  Amount: ${JSON.stringify(decodedUnsigned.method.args.value)}`,
    );

    // Construct the signing payload from an unsigned transaction.
    let signingPayloadDebug = construct.signingPayload(unsigned, { registry });
    // console.log(`\nPayload to Sign: ${signingPayload}`);

    // fix payload trim first 2 characters
    // signingPayload = `0x${signingPayload.substring(4,signingPayload.length)}`;
    console.log(`\nPayload to Sign: ${signingPayloadDebug}`);

    // Decode the information from a signing payload.
    const payloadInfo = decode(signingPayloadDebug, {
      metadataRpc,
      registry,
    });
    console.log(
      `\nDecoded Transaction\n  To: ${
        (payloadInfo.method.args.dest as { id: string })?.id
      }\n` + `  Amount: ${JSON.stringify(payloadInfo.method.args.value)}`,
    );

    // Sign a payload. This operation should be performed on an offline device.
    // Important! The registry needs to be updated with latest metadata, so make
    // sure to run `registry.setMetadata(metadata)` before signing.
    registry.setMetadata(createMetadata(registry, metadataRpc));

    let signingPayload = unsigned;
    const payload = new GenericSignerPayload(registry, {
      ...signingPayload,
      runtimeVersion: {
        specVersion: signingPayload.specVersion,
        transactionVersion: signingPayload.transactionVersion,
      },
    }).toPayload();

    // console.log(payload.toPayload());
    // console.log(payload.toU8a(true));
    // console.log('--------------------');
    // console.log(payload.toPayload());
    // process.exit();

    const { signature } = registry
      .createType('ExtrinsicPayload', payload, {
        version: EXTRINSIC_VERSION, // payload.version,
      })
      // .sign(alice);
      .sign(alice);
    console.log(`\nSignature: ${signature}`);

    // Serialize a signed transaction.
    const tx = construct.signedTx(unsigned, signature, {
      metadataRpc,
      registry,
    });
    console.log(`\nTransaction to Submit: ${tx}`);

    // Derive the tx hash of a signed transaction offline.
    const expectedTxHash = construct.txHash(tx);
    console.log(`\nExpected Tx Hash: ${expectedTxHash}`);

    // Send the tx to the node. Again, since `txwrapper` is offline-only, this
    // operation should be handled externally. Here, we just send a JSONRPC
    // request directly to the node.
    const actualTxHash = await rpcToLocalNode('author_submitExtrinsic', [tx]);
    console.log(`Actual Tx Hash: ${actualTxHash}`);
  });

  it("From bytes array", async function() {
    /*
    substrate_pk: 0x8eebd3a86e6fff47e1c18b573d64ed2db202012815b271a2f98c69bfb3805374
    substrate_pk_bytes: 0x8eebd3a86e6fff47e1c18b573d64ed2db202012815b271a2f98c69bfb3805374
    ----------------------------
    substrate_sk: 0xf896018d6ce114bc835963066128da863461842225b5e525342095a56dfad86e
    substrate_sk_bytes: 0xf896018d6ce114bc835963066128da863461842225b5e525342095a56dfad86e19a15552afae4c40c956adc4af79a9fb7d08b091ad6102c2cecffe48fe22ab308eebd3a86e6fff47e1c18b573d64ed2db202012815b271a2f98c69bfb3805374
    */

    const SEC_LEN = 64;
    const PUB_LEN = 32;
    const TOT_LEN = SEC_LEN + PUB_LEN;

    const fullU8a = u8aToU8a(
      "0xf896018d6ce114bc835963066128da863461842225b5e525342095a56dfad86e19a15552afae4c40c956adc4af79a9fb7d08b091ad6102c2cecffe48fe22ab308eebd3a86e6fff47e1c18b573d64ed2db202012815b271a2f98c69bfb3805374"
    );

    if (fullU8a.length !== TOT_LEN) {
      throw new Error(`Expected keypair with ${TOT_LEN} bytes, found ${fullU8a.length}`);
    }

    const res = {
      publicKey: fullU8a.slice(SEC_LEN, TOT_LEN),
      secretKey: fullU8a.slice(0, SEC_LEN)
    };

    console.log(res);

    console.log("Public Key (32 bytes):", u8aToHex(res.publicKey));
    console.log("Secret Key (64 bytes):", u8aToHex(res.secretKey));
  })

  function rpcToLocalNode(
    method: string,
    params: any[] = [],
  ): Promise<any> {
    return fetch('https://asset-hub-westend-rpc.dwellir.com', {
      body: JSON.stringify({
        id: 1,
        jsonrpc: '2.0',
        method,
        params,
      }),
      headers: {
        'Content-Type': 'application/json',
        connection: 'keep-alive',
      },
      method: 'POST',
    })
      .then((response) => response.json())
      .then(({ error, result }) => {
        if (error) {
          throw new Error(
            `${error.code} ${error.message}: ${JSON.stringify(error.data)}`,
          );
        }
  
        return result;
      });
  }
  
});
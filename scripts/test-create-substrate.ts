const hre = require("hardhat");

async function main() {

  const accountManagerAddress = "0xd0C2Fde7F083C8061AB93f860F7BCb99F1eB9379";

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);

  const tx = await contract.createSubstrate();
  await tx.wait();

  const substrate_pk = await contract.substrate_pk();
  const substrate_pk_bytes = await contract.substrate_pk_bytes();
  const substrate_sk = await contract.substrate_sk();
  const substrate_sk_bytes = await contract.substrate_sk_bytes();
  // const substrate_sk_string = await contract.substrate_sk_string();
  console.log(`substrate_pk: ${substrate_pk}`);
  console.log(`substrate_pk_bytes: ${substrate_pk_bytes}`);
  console.log(`----------------------------`);
  console.log(`substrate_sk: ${substrate_sk}`);
  console.log(`substrate_sk_bytes: ${substrate_sk_bytes}`);
  // console.log(`substrate_sk_string: ${substrate_sk_string}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

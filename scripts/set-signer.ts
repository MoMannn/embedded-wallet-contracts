const hre = require("hardhat");

async function main() {
  // DATA to be set
  const accountManagerAddress = "0x2D15A0B4d3d50B227eFa08Ed6a93c23222C995fb";
  const newSigner = "0x5f2B7077a7e5B4fdD97cBb56D9aD02a4f326896d";
  // Data to be set [END]

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);

  const tx = await contract.setSigner(newSigner);

  await tx.wait();

  const signerAddress = await contract.signer();
  console.log(`signer: ${signerAddress}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

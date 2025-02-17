const hre = require("hardhat");

async function main() {
  // DATA to be set
  const accountManagerAddress = "0x2B9A1F2B72602c66e833543D4957c0356EC79f1a";
  const newSigner = "0x03f039b54373591B39d9524A5baA4dAa25A0B4E4";
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

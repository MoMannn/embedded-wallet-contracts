const hre = require("hardhat");

async function main() {
  // DATA to be set
  const accountManagerAddress = "0x510518EBe8266fDF6858d2852ADA3bfE50988DAB";
  // Data to be set [END]

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);

  const gasPayingAddress = await contract.gaspayingAddress();
  console.log(`gasPayingAddress: ${gasPayingAddress}`);

  const signerAddress = await contract.signer();
  console.log(`signer: ${signerAddress}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

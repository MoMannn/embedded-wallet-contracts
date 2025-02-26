import { ethers } from "ethers";
import hre from "hardhat";

async function main() {

  const accountManagerAddress = "0x510518EBe8266fDF6858d2852ADA3bfE50988DAB";

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);

  const hash = "0x6d7f538e2d0d64ebab65f24595cf5e4d4d769f93ea3247dfa182830a755539cb";

  const receipt = await signer.provider.getTransactionReceipt(hash);
  const result = receipt.logs.map((log) => contract.interface.parseLog(log));

  console.log(result);

}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

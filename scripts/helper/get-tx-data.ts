import hre from "hardhat";

async function main() {

    const accountManagerAddress = "0x510518EBe8266fDF6858d2852ADA3bfE50988DAB";
    const accountEVM = "0x66511004f94e7832465fcF3fec59d5467B8dD3bC";

    const signer = (await hre.ethers.getSigners())[0];
    const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);
    const contractAcc = await hre.ethers.getContractAt('AccountEVM', accountEVM, signer);

    const hash = "0x159a7181b83f65d1a2321378f1163322d8f08e2b11e1ac82ccc25c15fbd6d1d7";

    const receipt = await signer.provider.getTransactionReceipt(hash);

    const result = receipt.logs.map((log) => contract.interface.parseLog(log) ?? contractAcc.interface.parseLog(log));

    console.log(result);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

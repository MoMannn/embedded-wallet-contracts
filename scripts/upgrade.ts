const hre = require("hardhat");

async function main() {
  // Get the owner account
  const [deployer] = await hre.ethers.getSigners();

  // DON'T FORGET TO COMMENT OUT sapphire-hardhat IN HARDHAT CONFIG !!!
  // DON'T FORGET TO COMMENT OUT sapphire-hardhat IN HARDHAT CONFIG !!!
  // DON'T FORGET TO COMMENT OUT sapphire-hardhat IN HARDHAT CONFIG !!!

  const accountManagerProxy = "0x50dE236a7ce372E7a09956087Fb4862CA1a887aA";
  const curveLibrary = "0x4c5D338Ed493fA3fDF0813ecA48dd45C6C85C7E2";

  const contractFactory = await hre.ethers.getContractFactory("AccountManager", {libraries: {SECP256R1Precompile: curveLibrary}});
  const impl = await contractFactory.deploy();
  await impl.waitForDeployment();

  const proxyContract = new hre.ethers.Contract(
    accountManagerProxy, 
    ["function upgradeToAndCall(address newImplementation, bytes memory data) external payable"],
    deployer
  );

  const tx = await proxyContract.upgradeToAndCall(await impl.getAddress(), "0x");
  await tx.wait();

  console.log(
    "accountManagerProxy upgraded to: %saddress/%s",
    hre.network.config.explorer,
    accountManagerProxy
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

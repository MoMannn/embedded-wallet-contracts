const hre = require("hardhat");

async function main() {

  // DON'T FORGET TO COMMENT OUT sapphire-hardhat IN HARDHAT CONFIG !!!
  // DON'T FORGET TO COMMENT OUT sapphire-hardhat IN HARDHAT CONFIG !!!
  // DON'T FORGET TO COMMENT OUT sapphire-hardhat IN HARDHAT CONFIG !!!

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

  const contractFactory = await hre.ethers.getContractFactory("AccountManager", {libraries: {SECP256R1Precompile: await curveLibrary.getAddress()}});
  const proxyFactory = await hre.ethers.getContractFactory('AccountManagerProxy');

  const impl = await contractFactory.deploy();
  await impl.waitForDeployment();
  const WAProxy = await proxyFactory.deploy(
    await impl.getAddress(),
    contractFactory.interface.encodeFunctionData(
      'initialize', [
        await AFProxy.getAddress(), // accountFactory
        '0x03f039b54373591B39d9524A5baA4dAa25A0B4E4' // signer
      ]
    ),
    { value: hre.ethers.parseEther('0.3') } // Value to be transfered to gaspaying address
  );
  await WAProxy.waitForDeployment();

  console.log(`CURVE_LIBRARY=${await curveLibrary.getAddress()}`);
  console.log(`ACCOUNT_MANAGER_ADDR=${await WAProxy.getAddress()}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

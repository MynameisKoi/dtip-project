import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import { ethers } from "hardhat";

const deployFunction: DeployFunction = async function (
  hre: HardhatRuntimeEnvironment
) {
  const { getNamedAccounts, deployments } = hre;
  const { deploy, log } = deployments;
  const { deployer, researcher1 } = await getNamedAccounts();

  log("----------------------------------------------------");
  log("Deploying ThreatIntelRegistry...");
  const constructorArgs = [
    "ThreatIntelRegistry", // Name
    "1", // Version
  ];

  const threatIntelRegistry = await deploy("ThreatIntelRegistry", {
    from: deployer,
    args: constructorArgs, // Add constructor arguments here if they exist
    log: true,
  });

  log("ThreatIntelRegistry Deployed at:", threatIntelRegistry.address);
  log("----------------------------------------------------");

  log("Granting RESEARCHER_ROLE to researcher1...");
  const registryContract = await ethers.getContractAt("ThreatIntelRegistry", threatIntelRegistry.address);
  const researcherRole = await registryContract.RESEARCHER_ROLE();

  const grantTx = await registryContract.grantRole(researcherRole, researcher1);
  await grantTx.wait(1);
  log(`RESEARCHER_ROLE granted to: ${researcher1}`);
  log("----------------------------------------------------");
};

export default deployFunction;
deployFunction.tags = ["ThreatIntelRegistry", "all"];
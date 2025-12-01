// scripts/interaction-workflow.ts
import { deployments, ethers, getNamedAccounts } from "hardhat";
import { ThreatIntelRegistry } from "../typechain-types";

async function main() {
  const { deployer, researcher1 } = await getNamedAccounts();
  const researcherSigner = await ethers.getSigner(researcher1);

  console.log("--- Interacting with Deployed ThreatIntelRegistry ---");

  // Get the deployed contract instance
  const threatIntelRegistryDeployment = await deployments.get(
    "ThreatIntelRegistry"
  );
  const threatIntelRegistry = await ethers.getContractAt(
    "ThreatIntelRegistry",
    threatIntelRegistryDeployment.address
  );
  console.log(
    `Contract instance attached at: ${await threatIntelRegistry.getAddress()}`
  );

  // --- Step 1: Off-Chain Signing (Researcher's Action) ---
  console.log(
    "\n--- Step 1: Researcher is preparing and signing a report off-chain ---"
  );

  const reportData = {
    reporter: researcher1,
    iocType: 1, // DomainName
    iocValue: "evil-phish.net",
    severity: 2, // High
    description: "Credential harvesting site",
    timestamp: 0, // Placeholder, not part of signature
    isDeprecated: false, // Placeholder, not part of signature
  };

  // The contract will use the current nonce for the hash
  const currentNonce = await threatIntelRegistry.getNonce(researcher1);
  console.log(
    `Current nonce for researcher ${researcher1} is: ${currentNonce.toString()}`
  );

  // Construct the EIP-712 typed data hash that needs to be signed
  // This must match the logic in the contract's _getReportHash function
  const digest = await threatIntelRegistry.getReportHash(reportData);
  console.log(`EIP-712 Digest to be signed: ${digest}`);

  // Researcher signs the digest with their private key
  const signature = await researcherSigner.signMessage(ethers.getBytes(digest));
  console.log(`Generated Signature: ${signature}`);

  // --- Step 2: On-Chain Verification and Submission (Transaction) ---
  console.log(
    "\n--- Step 2: Submitting the signed report to the blockchain ---"
  );

  const tx = await threatIntelRegistry
    .connect(researcherSigner)
    .submitReportBySignature(reportData, signature);
  console.log(`Transaction sent. Waiting for confirmation... Hash: ${tx.hash}`);
  await tx.wait(1);
  console.log("Transaction confirmed. Report has been submitted.");

  const newNonce = await threatIntelRegistry.getNonce(researcher1);
  console.log(
    `New nonce for researcher ${researcher1} is: ${newNonce.toString()}`
  );

  // --- Step 3: Querying the Registry (Consumer's Action) ---
  console.log(
    "\n--- Step 3: A consumer queries the registry for the submitted report ---"
  );

  // The consumer calculates the report ID to query it
  const reportId = ethers.solidityPackedKeccak256(
    ["uint8", "string"],
    [reportData.iocType, reportData.iocValue]
  );
  console.log(`Calculated Report ID for query: ${reportId}`);

  // Retrieve the report from the contract's public mapping
  const savedReport = await threatIntelRegistry.reports(reportId);

  console.log("\n--- Retrieved Report Details ---");
  console.log(`Reporter: ${savedReport.reporter}`);
  console.log(`IOC Type: ${savedReport.iocType.toString()} (DomainName)`);
  console.log(`IOC Value: ${savedReport.iocValue}`);
  console.log(`Severity: ${savedReport.severity.toString()} (High)`);
  console.log(`Description: ${savedReport.description}`);
  console.log(
    `Timestamp: ${new Date(Number(savedReport.timestamp) * 1000).toUTCString()}`
  );
  console.log(`Is Deprecated: ${savedReport.isDeprecated}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

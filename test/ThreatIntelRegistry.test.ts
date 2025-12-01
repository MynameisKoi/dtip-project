// test/ThreatIntelRegistry.test.ts
import { ethers, deployments, getNamedAccounts } from "hardhat";
import { expect } from "chai";
import { ThreatIntelRegistry } from "../typechain-types";
import { Signer } from "ethers";

describe("ThreatIntelRegistry", function () {
  let threatIntelRegistry: ThreatIntelRegistry;
  let deployer: Signer, researcher1: Signer, unauthorizedUser: Signer;
  let deployerAddress: string,
    researcher1Address: string,
    unauthorizedUserAddress: string;

  beforeEach(async function () {
    await deployments.fixture(["all"]);
    const deployment = await deployments.get("ThreatIntelRegistry");
    threatIntelRegistry = await ethers.getContractAt(
      "ThreatIntelRegistry",
      deployment.address
    );

    const accounts = await ethers.getSigners();
    deployer = accounts[0];
    researcher1 = accounts[1];
    unauthorizedUser = accounts[2];

    deployerAddress = await deployer.getAddress();
    researcher1Address = await researcher1.getAddress();
    unauthorizedUserAddress = await unauthorizedUser.getAddress();

    // Grant researcher role for testing
    const researcherRole = await threatIntelRegistry.RESEARCHER_ROLE();
    await threatIntelRegistry
      .connect(deployer)
      .grantRole(researcherRole, researcher1Address);
  });

  it("Should set the right admin role", async function () {
    const adminRole = await threatIntelRegistry.ADMIN_ROLE();
    expect(await threatIntelRegistry.hasRole(adminRole, deployerAddress)).to.be
      .true;
  });

  it("Should allow a researcher to submit a report with a valid signature", async function () {
    const report = {
      reporter: researcher1Address,
      iocType: 0, // IPAddress
      iocValue: "198.51.100.10",
      severity: 2, // High
      description: "Phishing C2 Server",
      timestamp: 0, // Not used in signature
      isDeprecated: false, // Not used in signature
    };

    const digest = await threatIntelRegistry.getReportHash(report);
    const signature = await researcher1.signMessage(ethers.getBytes(digest));

    await expect(
      threatIntelRegistry
        .connect(researcher1)
        .submitReportBySignature(report, signature)
    ).to.emit(threatIntelRegistry, "ReportSubmitted");

    const reportId = ethers.solidityPackedKeccak256(
      ["uint8", "string"],
      [report.iocType, report.iocValue]
    );
    const savedReport = await threatIntelRegistry.reports(reportId);
    expect(savedReport.reporter).to.equal(researcher1Address);
    expect(savedReport.iocValue).to.equal("198.51.100.10");
  });

  it("Should prevent submission with an invalid signature", async function () {
    const report = {
      reporter: researcher1Address,
      iocType: 0,
      iocValue: "198.51.100.10",
      severity: 2,
      description: "Phishing C2 Server",
      timestamp: 0,
      isDeprecated: false,
    };

    const digest = await threatIntelRegistry.getReportHash(report);
    // Sign with the wrong user (unauthorizedUser)
    const signature = await unauthorizedUser.signMessage(
      ethers.getBytes(digest)
    );

    await expect(
      threatIntelRegistry
        .connect(researcher1)
        .submitReportBySignature(report, signature)
    ).to.be.revertedWith("ThreatIntel: Signer mismatch.");
  });

  it("Should prevent submission from an account without the RESEARCHER_ROLE", async function () {
    const report = {
      reporter: unauthorizedUserAddress,
      iocType: 1,
      iocValue: "malicious-domain.com",
      severity: 1,
      description: "Malware distribution",
      timestamp: 0,
      isDeprecated: false,
    };

    const digest = await threatIntelRegistry.getReportHash(report);
    const signature = await unauthorizedUser.signMessage(
      ethers.getBytes(digest)
    );

    await expect(
      threatIntelRegistry
        .connect(unauthorizedUser)
        .submitReportBySignature(report, signature)
    ).to.be.reverted; // Reverts due to AccessControl
  });

  it("Should prevent a replay attack using the same signature", async function () {
    const report = {
      reporter: researcher1Address,
      iocType: 2, // FileHash
      iocValue: "d41d8cd98f00b204e9800998ecf8427e",
      severity: 3, // Critical
      description: "Ransomware payload",
      timestamp: 0,
      isDeprecated: false,
    };

    const digest = await threatIntelRegistry.getReportHash(report);
    const signature = await researcher1.signMessage(ethers.getBytes(digest));

    // First submission should succeed
    await threatIntelRegistry
      .connect(researcher1)
      .submitReportBySignature(report, signature);

    // Second submission with the same signature should fail because the nonce has increased
    await expect(
      threatIntelRegistry
        .connect(researcher1)
        .submitReportBySignature(report, signature)
    ).to.be.revertedWith("ThreatIntel: Signer mismatch.");
  });

  it("Should prevent duplicate submission overwriting a valid report", async function () {
    // 1. ARRANGE: Submit an initial, valid report
    const initialReport = {
      reporter: researcher1Address,
      iocType: 0, // IPAddress
      iocValue: "203.0.113.42",
      severity: 2, // High
      description: "Initial valid report",
      timestamp: 0,
      isDeprecated: false,
    };

    const initialDigest = await threatIntelRegistry.getReportHash(
      initialReport
    );
    const initialSignature = await researcher1.signMessage(
      ethers.getBytes(initialDigest)
    );

    // This first submission should succeed
    await threatIntelRegistry
      .connect(researcher1)
      .submitReportBySignature(initialReport, initialSignature);

    // 2. ARRANGE: Create a second, duplicate report for the same IoC
    // It has the same iocType and iocValue, but other details are different
    const duplicateReport = {
      reporter: researcher1Address,
      iocType: 0, // Same IPAddress
      iocValue: "203.0.113.42", // Same IP
      severity: 1, // Different severity
      description: "Attempt to overwrite",
      timestamp: 0,
      isDeprecated: true, // Attempt to deprecate
    };

    const duplicateDigest = await threatIntelRegistry.getReportHash(
      duplicateReport
    );
    const duplicateSignature = await researcher1.signMessage(
      ethers.getBytes(duplicateDigest)
    );

    // 3. ACT & ASSERT: Attempt to submit the duplicate report and expect it to revert
    await expect(
      threatIntelRegistry
        .connect(researcher1)
        .submitReportBySignature(duplicateReport, duplicateSignature)
    ).to.be.revertedWith("ThreatIntel: Report already exists.");

    // 4. ASSERT (Optional but Recommended): Verify the original report was not changed
    const reportId = ethers.solidityPackedKeccak256(
      ["uint8", "string"],
      [initialReport.iocType, initialReport.iocValue]
    );
    const savedReport = await threatIntelRegistry.reports(reportId);
    expect(savedReport.isDeprecated).to.be.false;
    expect(savedReport.description).to.equal("Initial valid report");
  });

  it("Should prevent someone not original reporter or an admin from deprecating a report", async function () {
    // 1. ARRANGE: Submit a valid report as researcher1
    const report = {
      reporter: researcher1Address,
      iocType: 1, // DomainName
      iocValue: "unauthorized-deprecate-test.com",
      severity: 1, // Medium
      description: "A report to test deprecation access control",
      timestamp: 0,
      isDeprecated: false,
    };

    const digest = await threatIntelRegistry.getReportHash(report);
    const signature = await researcher1.signMessage(ethers.getBytes(digest));
    await threatIntelRegistry
      .connect(researcher1)
      .submitReportBySignature(report, signature);

    // Calculate the reportId to target for deprecation
    const reportId = ethers.solidityPackedKeccak256(
      ["uint8", "string"],
      [report.iocType, report.iocValue]
    );

    // 2. ACT & ASSERT: Attempt to deprecate the report as an unauthorized user
    // This user is neither the admin (deployer) nor the original reporter (researcher1)
    await expect(
      threatIntelRegistry.connect(unauthorizedUser).deprecateReport(reportId)
    ).to.be.revertedWith("ThreatIntel: Not authorized to deprecate.");
  });

  it("Should allow the original reporter to deprecate their own report", async function () {
    // 1. ARRANGE: Submit a valid report as researcher1
    const report = {
      reporter: researcher1Address,
      iocType: 2, // FileHash
      iocValue: "d41d8cd98f00b204e9800998ecf8427e",
      severity: 3, // Critical
      description: "A report to be deprecated by its owner",
      timestamp: 0,
      isDeprecated: false,
    };

    const digest = await threatIntelRegistry.getReportHash(report);
    const signature = await researcher1.signMessage(ethers.getBytes(digest));
    await threatIntelRegistry
      .connect(researcher1)
      .submitReportBySignature(report, signature);

    // Calculate the reportId to target
    const reportId = ethers.solidityPackedKeccak256(
      ["uint8", "string"],
      [report.iocType, report.iocValue]
    );

    // 2. ACT: Deprecate the report as the original reporter
    const tx = threatIntelRegistry
      .connect(researcher1)
      .deprecateReport(reportId);

    // 3. ASSERT: Check for the event and the state change
    await expect(tx)
      .to.emit(threatIntelRegistry, "ReportDeprecated")
      .withArgs(reportId, researcher1Address);

    const updatedReport = await threatIntelRegistry.reports(reportId);
    expect(updatedReport.isDeprecated).to.be.true;
  });

  it("Should allow an admin to deprecate any report", async function () {
    // 1. ARRANGE: Have a non-admin (researcher1) submit a valid report
    const report = {
      reporter: researcher1Address,
      iocType: 0, // IPAddress
      iocValue: "192.0.2.100",
      severity: 2, // High
      description: "A report to be deprecated by an admin",
      timestamp: 0,
      isDeprecated: false,
    };

    const digest = await threatIntelRegistry.getReportHash(report);
    const signature = await researcher1.signMessage(ethers.getBytes(digest));
    await threatIntelRegistry
      .connect(researcher1)
      .submitReportBySignature(report, signature);

    // Calculate the reportId to target
    const reportId = ethers.solidityPackedKeccak256(
      ["uint8", "string"],
      [report.iocType, report.iocValue]
    );

    // 2. ACT: Deprecate the report as the admin (deployer)
    const tx = threatIntelRegistry.connect(deployer).deprecateReport(reportId);

    // 3. ASSERT: Check for the event and the state change
    await expect(tx)
      .to.emit(threatIntelRegistry, "ReportDeprecated")
      .withArgs(reportId, deployerAddress);

    const updatedReport = await threatIntelRegistry.reports(reportId);
    expect(updatedReport.isDeprecated).to.be.true;
  });

  it("Should prevent deprecating a non-existent report", async function () {
    // 1. ARRANGE: Create a report ID that is guaranteed not to exist.
    // We can do this by hashing some random data.
    const nonExistentReportId = ethers.keccak256(
      ethers.toUtf8Bytes("this-report-does-not-exist")
    );

    // 2. ACT & ASSERT: Attempt to deprecate using the fake ID and expect a revert.
    // The admin (deployer) is used here, as the focus is on the report's existence, not access control.
    await expect(
      threatIntelRegistry.connect(deployer).deprecateReport(nonExistentReportId)
    ).to.be.revertedWith("ThreatIntel: Report does not exist.");
  });

  it("Should prevent deprecating an already deprecated report", async function () {
    // 1. ARRANGE: Submit a report and then deprecate it once.
    const report = {
      reporter: researcher1Address,
      iocType: 1, // DomainName
      iocValue: "already-deprecated-test.com",
      severity: 1,
      description: "A report to test double deprecation",
      timestamp: 0,
      isDeprecated: false,
    };

    const digest = await threatIntelRegistry.getReportHash(report);
    const signature = await researcher1.signMessage(ethers.getBytes(digest));
    await threatIntelRegistry
      .connect(researcher1)
      .submitReportBySignature(report, signature);

    const reportId = ethers.solidityPackedKeccak256(
      ["uint8", "string"],
      [report.iocType, report.iocValue]
    );

    // First deprecation should succeed
    await threatIntelRegistry.connect(deployer).deprecateReport(reportId);

    // 2. ACT & ASSERT: Attempt to deprecate the report a second time and expect a revert.
    await expect(
      threatIntelRegistry.connect(deployer).deprecateReport(reportId)
    ).to.be.revertedWith("ThreatIntel: Report is already deprecated.");
  });

  it("Should prevent non-admins from granting roles", async function () {
    // 1. ARRANGE: Identify the roles and actors.
    const researcherRole = await threatIntelRegistry.RESEARCHER_ROLE();
    const adminRole = await threatIntelRegistry.DEFAULT_ADMIN_ROLE();

    // 2. ACT & ASSERT: Expect the transaction to revert with the specific custom error.
    await expect(
      threatIntelRegistry
        .connect(researcher1)
        .grantRole(researcherRole, unauthorizedUserAddress)
    )
      .to.be.revertedWithCustomError(
        threatIntelRegistry,
        "AccessControlUnauthorizedAccount"
      )
      .withArgs(researcher1Address, adminRole); // Check that the error returns the correct account and role
  });

  it("Should prevent overwriting a deprecated report", async function () {
    // 1. ARRANGE: Submit a report and then immediately deprecate it.
    const report = {
      reporter: researcher1Address,
      iocType: 0, // IPAddress
      iocValue: "203.0.113.55",
      severity: 2,
      description: "Initial report to be deprecated",
      timestamp: 0,
      isDeprecated: false,
    };

    const initialDigest = await threatIntelRegistry.getReportHash(report);
    const initialSignature = await researcher1.signMessage(
      ethers.getBytes(initialDigest)
    );
    await threatIntelRegistry
      .connect(researcher1)
      .submitReportBySignature(report, initialSignature);

    const reportId = ethers.solidityPackedKeccak256(
      ["uint8", "string"],
      [report.iocType, report.iocValue]
    );

    // Deprecate the report as the admin
    await threatIntelRegistry.connect(deployer).deprecateReport(reportId);

    // 2. ACT & ASSERT: Attempt to submit a new report for the same IoC.
    const newReportAttempt = {
      reporter: researcher1Address,
      iocType: 0, // Same IPAddress
      iocValue: "203.0.113.55", // Same IP
      severity: 3, // Different severity
      description: "Attempting to overwrite a deprecated report",
      timestamp: 0,
      isDeprecated: false,
    };

    const newDigest = await threatIntelRegistry.getReportHash(newReportAttempt);
    const newSignature = await researcher1.signMessage(
      ethers.getBytes(newDigest)
    );

    // The transaction should be reverted because a report for this IoC already exists.
    await expect(
      threatIntelRegistry
        .connect(researcher1)
        .submitReportBySignature(newReportAttempt, newSignature)
    ).to.be.revertedWith("ThreatIntel: Cannot update a deprecated report.");
  });
});

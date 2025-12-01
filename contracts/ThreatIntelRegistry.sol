// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title ThreatIntelRegistry
 * @author Principal Blockchain Security Architect
 * @notice A decentralized registry for cybersecurity threat intelligence.
 * Vetted researchers can submit Indicators of Compromise (IOCs) via
 * off-chain signatures, creating an immutable and censorship-resistant ledger.
 */
contract ThreatIntelRegistry is AccessControl, EIP712 {
    // --- Roles ---
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant RESEARCHER_ROLE = keccak256("RESEARCHER_ROLE");

    // --- Enums and Structs ---

    // Defines the type of Indicator of Compromise.
    enum IOCType {
        IPAddress,
        DomainName,
        FileHash,
        WalletAddress
    }

    // Defines the severity level of the reported threat.
    enum Severity {
        Low,
        Medium,
        High,
        Critical
    }

    // Represents a single threat intelligence report.
    struct ThreatReport {
        address reporter; // The address of the researcher who submitted the report.
        IOCType iocType; // The type of the indicator.
        string iocValue; // The value of the indicator (e.g., "192.168.1.100").
        Severity severity; // The assessed severity of the threat.
        string description; // A brief description of the threat.
        uint256 timestamp; // The timestamp of the submission.
        bool isDeprecated; // Flag to mark if the report is no longer considered valid.
    }

    // --- State Variables ---

    // Mapping from a unique report ID (hash of IOC) to the ThreatReport struct.
    mapping(bytes32 => ThreatReport) public reports;

    // Mapping from a researcher's address to their current nonce. Used to prevent signature replay attacks.
    mapping(address => uint256) private _nonces;

    // --- Events ---
    event ReportSubmitted(
        bytes32 indexed reportId,
        address indexed reporter,
        IOCType iocType,
        string iocValue,
        Severity severity
    );

    event ReportDeprecated(
        bytes32 indexed reportId,
        address indexed deprecatedBy
    );

    // --- Constants for EIP-712 ---
    // The EIP-712 type hash for the ThreatReport struct.
    bytes32 private constant THREAT_REPORT_TYPEHASH =
        keccak256(
            "ThreatReport(address reporter,uint8 iocType,string iocValue,uint8 severity,string description,uint256 nonce)"
        );

    // --- Constructor ---

    /**
     * @dev Sets up the contract, EIP-712 domain, and initial roles.
     * The deployer of the contract is granted the ADMIN_ROLE.
     */
    constructor(
        string memory name,
        string memory version
    ) EIP712(name, version) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    // --- Core Functions ---

    /**
     * @notice Submits a threat report using an EIP-712 signature.
     * @dev This function allows a researcher to submit a report without sending a transaction themselves.
     *      A relayer can submit the signed data on their behalf.
     * @param report The ThreatReport data that was signed.
     * @param signature The EIP-712 signature from the researcher.
     */
    function submitReportBySignature(
        ThreatReport calldata report,
        bytes calldata signature
    ) public onlyRole(RESEARCHER_ROLE) {
        // 1. Verify that the caller is the same as the claimed reporter.
        // This prevents a researcher from submitting a report on behalf of another researcher.
        require(
            msg.sender == report.reporter,
            "ThreatIntel: Caller must be the reporter."
        );

        // 2. Compute the EIP-712 digest that the researcher should have signed.
        bytes32 digest = _getReportHash(report);
        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );

        // 3. Recover the signer's address from the digest and signature.
        // Uses OpenZeppelin's ECDSA library to prevent signature malleability.
        address signer = ECDSA.recover(messageHash, signature);
        require(signer != address(0), "ThreatIntel: Invalid signature.");

        // 4. Verify that the recovered signer is the claimed reporter.
        require(signer == report.reporter, "ThreatIntel: Signer mismatch.");

        // 5. Generate the unique report ID from the core IOC data.
        bytes32 reportId = keccak256(
            abi.encodePacked(report.iocType, report.iocValue)
        );

        // Check if a report already exists at this ID
        if (reports[reportId].timestamp != 0) {
            // If it exists AND is deprecated, revert with the specific error
            if (reports[reportId].isDeprecated) {
                revert("ThreatIntel: Cannot update a deprecated report.");
            }
            // Otherwise, it exists and is active, so revert with the general error
            revert("ThreatIntel: Report already exists.");
        }

        // 6. Store the report data on-chain.
        reports[reportId] = ThreatReport({
            reporter: report.reporter,
            iocType: report.iocType,
            iocValue: report.iocValue,
            severity: report.severity,
            description: report.description,
            timestamp: block.timestamp,
            isDeprecated: false
        });

        // 7. Increment the nonce for the reporter to prevent replay attacks.
        _nonces[report.reporter]++;

        emit ReportSubmitted(
            reportId,
            report.reporter,
            report.iocType,
            report.iocValue,
            report.severity
        );
    }

    /**
     * @notice Marks a report as deprecated.
     * @dev Can only be called by the original reporter or an admin.
     *      This preserves the history while indicating the intelligence may be outdated.
     * @param reportId The unique ID of the report to deprecate.
     */
    function deprecateReport(bytes32 reportId) public {
        ThreatReport storage reportToDeprecate = reports[reportId];
        require(
            reportToDeprecate.reporter != address(0),
            "ThreatIntel: Report does not exist."
        );

        // Only the original reporter or an admin can deprecate a report.
        require(
            msg.sender == reportToDeprecate.reporter ||
                hasRole(ADMIN_ROLE, msg.sender),
            "ThreatIntel: Not authorized to deprecate."
        );

        require(
            !reports[reportId].isDeprecated,
            "ThreatIntel: Report is already deprecated."
        );

        reportToDeprecate.isDeprecated = true;
        emit ReportDeprecated(reportId, msg.sender);
    }

    // --- View and Pure Functions ---

    /**
     * @notice Retrieves the current nonce for a given researcher.
     * @param account The address of the researcher.
     * @return The current nonce.
     */
    function getNonce(address account) public view returns (uint256) {
        return _nonces[account];
    }

    /**
     * @notice A public view function to compute the EIP-712 hash for a given report structure.
     * @dev This helps off-chain clients construct the correct hash to sign.
     * @param report The ThreatReport data to hash.
     * @return The EIP-712 digest.
     */
    function getReportHash(
        ThreatReport calldata report
    ) public view returns (bytes32) {
        return _getReportHash(report);
    }

    // --- Internal Functions ---

    /**
     * @dev Internal function to compute the EIP-712 hash for a report.
     * @param report The ThreatReport data to hash.
     * @return The EIP-712 digest.
     */
    function _getReportHash(
        ThreatReport calldata report
    ) internal view returns (bytes32) {
        // Hash the structured data according to the EIP-712 standard.
        bytes32 structHash = keccak256(
            abi.encode(
                THREAT_REPORT_TYPEHASH,
                report.reporter,
                uint8(report.iocType),
                keccak256(bytes(report.iocValue)),
                uint8(report.severity),
                keccak256(bytes(report.description)),
                _nonces[report.reporter] // Use the current nonce
            )
        );

        // Combine the struct hash with the domain separator to create the final digest.
        return _hashTypedDataV4(structHash);
    }
}

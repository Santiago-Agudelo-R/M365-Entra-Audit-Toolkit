# M365-Entra-Audit-Toolkit

Automated PowerShell governance and security auditor for Microsoft 365, Microsoft Entra ID, and Microsoft Intune.

[![PowerShell 5.1 / 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Santiago-Agudelo-R/M365-Entra-Audit-Toolkit?color=success)](https://github.com/Santiago-Agudelo-R/M365-Entra-Audit-Toolkit/releases)

---

## Overview

Maintaining hygiene across cloud and hybrid Microsoft enterprise tenants is critical to preventing unauthorized persistence and minimizing licensing overhead. `M365-Entra-Audit-Toolkit` provides an automated, modular PowerShell auditor designed for systems administrators and security operations teams to evaluate four critical governance domains:

1. **Stale Guest Accounts:** Identifies external vendor and partner accounts with no interactive sign-ins over a configurable threshold (default: 90 days).
2. **Privileged Roles Governance:** Audits permanent assignments to high-risk roles (Global Administrator, Privileged Role Administrator) versus Privileged Identity Management (PIM) eligibility.
3. **License Optimization:** Flags active Microsoft 365 licenses assigned to disabled or long-inactive accounts to eliminate unnecessary recurring costs.
4. **Intune Endpoint Posture:** Extracts non-compliant managed devices and flags workstations with missing encryption baselines (BitLocker).

All extracted timestamps are normalized to ISO 8601 UTC. Outputs are delivered in structured JSON accompanied by a `.sha256` integrity sidecar file, with optional CSV exports.

---

## Architecture

```text
[Microsoft Graph API / Intune] ─── queries ───> [Invoke-M365EntraAudit.ps1]
                                                          │
                                                          ▼
                                             [Evaluation & Triage Engine]
                                                          │
                                     ┌────────────────────┴────────────────────┐
                                     ▼                                         ▼
                        [Hashed JSON Artifact]                     [Segmented CSV Reports]
                        (Metadata + SHA256 Sidecar)                (Guests, Roles, Licenses, Intune)
```

---

## Requirements & Permissions

### Minimum Requirements
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or PowerShell 7+
- Microsoft Graph PowerShell SDK (`Microsoft.Graph.Users`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.DeviceManagement`)

### Required Microsoft Graph Scopes (Live Execution)
- `User.Read.All`
- `Directory.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `AuditLog.Read.All`

---

## Usage

### 1. Offline Demo Mode (Zero Credentials Required)
Evaluate the tool immediately using built-in synthetic enterprise telemetry:
```powershell
.\src\Invoke-M365EntraAudit.ps1 -DemoMode
```

### 2. Full Audit with CSV Exports
```powershell
.\src\Invoke-M365EntraAudit.ps1 -DemoMode -ExportCsv -InactiveDaysThreshold 60 -OutputDirectory "C:\Audits\M365"
```

### 3. Live Tenant Execution
```powershell
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "DeviceManagementManagedDevices.Read.All"
.\src\Invoke-M365EntraAudit.ps1 -ExportCsv
```

---

## Sample JSON Output Structure

```json
{
  "Metadata": {
    "ToolName": "M365-Entra-Audit-Toolkit",
    "ToolVersion": "1.0.0",
    "TimestampUtc": "2026-10-13T23:15:00.1234567Z",
    "InactiveDaysThreshold": 90,
    "ExecutionMode": "DemoMode"
  },
  "Summary": {
    "TotalStaleGuestsFound": 2,
    "TotalPrivilegedAssignments": 3,
    "TotalReclaimableLicenses": 2,
    "TotalNonCompliantEndpoints": 2
  },
  "StaleGuests": [
    {
      "UserPrincipalName": "vendor.contractor_external.com#EXT#@contoso.onmicrosoft.com",
      "DisplayName": "External Vendor Auditor",
      "AccountEnabled": true,
      "DaysInactive": 115,
      "StatusFlag": "StaleGuest"
    }
  ],
  "PrivilegedRoles": [
    {
      "RoleName": "Global Administrator",
      "PrincipalName": "admin_secops@contoso.com",
      "AssignmentType": "Permanent",
      "IsPimEligible": false,
      "MfaRegistered": true,
      "ComplianceRisk": "PermanentGlobalAdminAssignment"
    }
  ]
}
```

---

## Testing

Run unit tests via Pester:
```powershell
Invoke-Pester -Path ./tests
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

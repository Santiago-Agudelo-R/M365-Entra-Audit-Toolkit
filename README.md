# M365-Entra-Audit-Toolkit

Automated PowerShell governance and security auditor for Microsoft 365, Microsoft Entra ID, and Microsoft Intune.

[![PowerShell 5.1 / 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Santiago-Agudelo-R/M365-Entra-Audit-Toolkit?color=success)](https://github.com/Santiago-Agudelo-R/M365-Entra-Audit-Toolkit/releases)

---

## Overview

Maintaining hygiene across cloud and hybrid Microsoft enterprise tenants is critical to preventing unauthorized persistence and minimizing licensing overhead. `M365-Entra-Audit-Toolkit` provides a modular PowerShell auditor designed for systems administrators and security operations teams to evaluate five critical governance domains:

1. **Stale Guest Accounts (`Get-LiveStaleGuest`):** Identifies external vendor and partner accounts with no interactive sign-ins over a configurable threshold (default: 90 days) via `SignInActivity`.
2. **Privileged Roles Governance (`Get-LivePrivilegedRole`):** Audits high-risk directory roles (`Global Administrator`, `Privileged Role Administrator`, `Security Administrator`, `Intune Administrator`), correlating active assignments against Entra ID PIM eligibility schedules (`Get-MgRoleManagementDirectoryRoleEligibilitySchedule`) and MFA registration status (`Get-MgReportAuthenticationMethodUserRegistrationDetail`). If PIM or MFA report permissions are unavailable, fields report `"Unknown"` rather than assuming compliance.
3. **License Optimization (`Get-LiveInactiveLicense`):** Flags active Microsoft 365 licenses assigned to disabled (`AccountEnabled = false`) or long-inactive accounts to eliminate recurring licensing waste.
4. **Intune Endpoint Posture (`Get-LiveEndpointCompliance`):** Extracts non-compliant managed devices (`Get-MgDeviceManagementManagedDevice`), flagging missing BitLocker encryption (`BitLockerNotActive`) on Windows endpoints and `DeviceEncryptionNotActive` on macOS/mobile endpoints.
5. **Conditional Access Posture (`Get-LiveConditionalAccess`):** Evaluates Entra ID Conditional Access policies (`Get-MgIdentityConditionalAccessPolicy`) to identify policies left in `enabledForReportingButNotEnforced` (Report-Only) or `disabled` states.

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
                        (Metadata + SHA256 Sidecar)          (Guests, Roles, Licenses, Intune, CA)
```

---

## Requirements & Permissions

### Minimum Requirements
- Windows, Linux, or macOS running PowerShell 7+ (or Windows PowerShell 5.1)
- Microsoft Graph PowerShell SDK (`Microsoft.Graph.Users`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Identity.Governance`, `Microsoft.Graph.Reports`, `Microsoft.Graph.DeviceManagement`, `Microsoft.Graph.Identity.SignIns`)

### Required Microsoft Graph Scopes (Live Execution)
- `User.Read.All`
- `Directory.Read.All`
- `RoleManagement.Read.Directory` (for PIM schedule evaluation)
- `UserAuthenticationMethod.Read.All` (for MFA registration verification)
- `DeviceManagementManagedDevices.Read.All`
- `Policy.Read.All`
- `AuditLog.Read.All`

---

## Usage

### 1. Offline Demo Mode (Zero Credentials Required)
Evaluate the tool using built-in synthetic enterprise telemetry:
```powershell
.\src\Invoke-M365EntraAudit.ps1 -DemoMode
```

### 2. Full Demo Audit with CSV Exports
```powershell
.\src\Invoke-M365EntraAudit.ps1 -DemoMode -ExportCsv -InactiveDaysThreshold 60 -OutputDirectory "./AuditOutput"
```

### 3. Live Tenant Execution
Live execution requires an active Microsoft Graph session and terminates with an error if unauthenticated:
```powershell
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory", "UserAuthenticationMethod.Read.All", "DeviceManagementManagedDevices.Read.All", "Policy.Read.All", "AuditLog.Read.All"
.\src\Invoke-M365EntraAudit.ps1 -ExportCsv
```

---

## Testing

Run unit tests (including mocked Microsoft Graph live-query tests) via Pester 5:
```powershell
Invoke-Pester -Path ./tests
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

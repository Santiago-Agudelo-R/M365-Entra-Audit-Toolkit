# M365-Entra-Audit-Toolkit

Automated PowerShell governance and security auditor for Microsoft 365, Microsoft Entra ID, and Microsoft Intune.

[![CI](https://github.com/Santiago-Agudelo-R/M365-Entra-Audit-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Santiago-Agudelo-R/M365-Entra-Audit-Toolkit/actions)
[![PowerShell 5.1 / 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Santiago-Agudelo-R/M365-Entra-Audit-Toolkit?color=success)](https://github.com/Santiago-Agudelo-R/M365-Entra-Audit-Toolkit/releases)

---

## Overview

Maintaining hygiene across cloud and hybrid Microsoft enterprise tenants is critical to preventing unauthorized persistence and minimizing licensing overhead. `M365-Entra-Audit-Toolkit` provides a modular PowerShell auditor designed for systems administrators and security operations teams to evaluate six critical governance domains:

1. **Stale Guest Accounts (`Get-LiveStaleGuest`):** Identifies external vendor and partner accounts with no sign-in activity over a configurable threshold (default: 90 days), evaluating `LastSuccessfulSignInDateTime`, `LastSignInDateTime` (interactive), and `LastNonInteractiveSignInDateTime` (token refresh).
2. **Privileged Roles Governance (`Get-LivePrivilegedRole`):** Audits high-risk directory roles (`Global Administrator`, `Privileged Role Administrator`, `Security Administrator`, `Intune Administrator`, `Exchange Administrator`, `Conditional Access Administrator`). Roles are listed from role definitions (`Get-MgRoleManagementDirectoryRoleDefinition`), so a role held only through PIM eligibility is reported even if it has never been activated in the tenant. It combines active role members (`Get-MgDirectoryRoleMember`), **both active and inactive PIM eligibility schedules** (`Get-MgRoleManagementDirectoryRoleEligibilitySchedule`), and PIM assignment expiration schedules (`Get-MgRoleManagementDirectoryRoleAssignmentSchedule` to distinguish `TimeBoundAssigned` vs `Permanent`) alongside live MFA registration status (`Get-MgReportAuthenticationMethodUserRegistrationDetail`).
3. **License Optimization (`Get-LiveInactiveLicense`):** Flags active Microsoft 365 licenses assigned to disabled (`AccountEnabled = false`) or long-inactive accounts (checking both interactive and non-interactive sign-ins, using `CreatedDateTime` as the baseline for accounts that have never signed in so newly created employees are not flagged, and translating `SkuId` GUIDs to friendly SKU names via `Get-MgSubscribedSku`).
4. **Intune Endpoint Posture (`Get-LiveEndpointCompliance`):** Extracts non-compliant managed devices (`Get-MgDeviceManagementManagedDevice`), flagging missing BitLocker encryption (`BitLockerNotActive`) on Windows endpoints and `DeviceEncryptionNotActive` on macOS/mobile endpoints.
5. **Conditional Access Posture (`Get-LiveConditionalAccess`):** Evaluates Entra ID Conditional Access policies (`Get-MgIdentityConditionalAccessPolicy`) to identify policies left in `enabledForReportingButNotEnforced` (Report-Only) or `disabled` states, as well as `All`-user policies lacking break-glass exclusions or carrying excessive direct user exclusions. It also reports tenant-level gaps that per-policy checks miss: no enforced policy requiring MFA for all users, none covering Global Administrators, and no policy blocking legacy authentication (skipped when security defaults are enabled, since they provide both).
6. **OAuth App Consent & Credential Hygiene (`Get-LiveAppConsentAndSecret`):** Reviews every service principal, including third-party multi-tenant apps, for high-risk **application permissions** on Microsoft Graph and Exchange Online (`Get-MgServicePrincipalAppRoleAssignedTo`; these act without a signed-in user and are the target of illicit-consent attacks), high-risk **delegated** permissions granted tenant-wide or by individual users (`Get-MgOauth2PermissionGrant`), and the credentials of app registrations owned by the tenant: all credentials expired, the next active credential expiring soon, or expired credentials left in place. Each app is labeled `ThisTenant` or `ThirdParty`.

All extracted timestamps are normalized to ISO 8601 UTC. Outputs are delivered in structured JSON accompanied by a `.sha256` integrity sidecar file, with optional CSV exports protected against CSV/Excel formula injection (`CWE-1236`).

---

## Requirements & Permissions

### Minimum Requirements
- Windows, Linux, or macOS running PowerShell 7+ (or Windows PowerShell 5.1)
- Microsoft Graph PowerShell SDK (`Microsoft.Graph.Users`, `Microsoft.Graph.Applications`, `Microsoft.Graph.Identity.DirectoryManagement`, `Microsoft.Graph.Identity.Governance`, `Microsoft.Graph.Reports`, `Microsoft.Graph.DeviceManagement`, `Microsoft.Graph.Identity.SignIns`)

### Required Microsoft Graph Scopes (Live Execution)
- `User.Read.All`
- `Directory.Read.All`
- `Application.Read.All`
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
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "Application.Read.All", "RoleManagement.Read.Directory", "UserAuthenticationMethod.Read.All", "DeviceManagementManagedDevices.Read.All", "Policy.Read.All", "AuditLog.Read.All"
.\src\Invoke-M365EntraAudit.ps1 -ExportCsv
```

---

## Sample Output (`M365Audit_<timestamp>.json`)

Real output of `.\src\Invoke-M365EntraAudit.ps1 -DemoMode`:

```json
{
  "Metadata": {
    "ToolName": "M365-Entra-Audit-Toolkit",
    "ToolVersion": "1.2.2",
    "TimestampUtc": "2026-11-21T20:30:00.0000000Z",
    "InactiveDaysThreshold": 90,
    "ExecutionMode": "DemoMode"
  },
  "Summary": {
    "TotalStaleGuestsFound": 2,
    "TotalPrivilegedAssignments": 3,
    "TotalReclaimableLicenses": 2,
    "TotalNonCompliantEndpoints": 2,
    "TotalAtRiskCaPolicies": 2,
    "TotalHighRiskAppsFound": 2
  }
}
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

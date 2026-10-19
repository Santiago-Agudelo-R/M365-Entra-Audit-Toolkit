# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-10-18

### Fixed
- **Privileged Role MFA & PIM Verification (`Get-LivePrivilegedRole`):** Replaced hardcoded `AssignmentType = "Permanent"`, `IsPimEligible = $false`, and `MfaRegistered = $true` values with live queries against `Get-MgReportAuthenticationMethodUserRegistrationDetail`, `Get-MgRoleManagementDirectoryRoleEligibilitySchedule`, and `Get-MgRoleManagementDirectoryRoleAssignmentSchedule`. When PIM or MFA report endpoints are inaccessible, fields now return `"Unknown"` instead of fabricating compliant values.
- **Fail-Closed Live Execution:** Running `Invoke-M365EntraAudit.ps1` without `-DemoMode` when no Microsoft Graph session is active now throws a terminating error instead of silently falling back to synthetic `contoso.com` demo telemetry.
- **OS-Aware Encryption Flagging (`Get-LiveEndpointCompliance`):** `BitLockerNotActive` is now reported strictly for Windows endpoints (`OperatingSystem -match '^Windows'`), while unencrypted macOS/mobile devices report `DeviceEncryptionNotActive`.
- **PSScriptAnalyzer Singular Noun Compliance:** Renamed internal cmdlets (`Get-LiveStaleGuest`, `Get-LivePrivilegedRole`, `Get-LiveInactiveLicense`) to adhere to PowerShell singular-noun conventions (`PSUseSingularNouns`).

### Added
- Unit tests in `tests/Invoke-M365EntraAudit.Tests.ps1` verifying fail-closed behavior on unauthenticated live runs and mocking Microsoft Graph cmdlets for `Get-LivePrivilegedRole` and `Get-LiveEndpointCompliance`.

## [1.1.0] - 2026-10-18

### Added
- Live Microsoft Graph query implementations and Conditional Access policy posture auditing (`ConditionalAccess` section).

## [1.0.0] - 2026-10-13

### Added
- Initial release of `Invoke-M365EntraAudit.ps1`.

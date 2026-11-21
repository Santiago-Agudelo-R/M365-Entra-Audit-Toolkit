# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-11-21

### Fixed
- **Privileged roles:** Roles are enumerated from role definitions instead of `Get-MgDirectoryRole`. A `directoryRole` object only exists once a role has been activated in the tenant, so a role held only through PIM eligibility was previously invisible.
- **App consent:** The audit only looked at delegated permissions (`OAuth2PermissionGrant`) on app registrations owned by the tenant. It now also checks application permissions granted on Microsoft Graph and Exchange Online, covers third-party multi-tenant apps, and separates tenant-wide from user consent.
- **App consent:** Credential findings are based on active credentials. An app with one expired secret and one valid secret is reported as `ExpiredCredentialNotRemoved` instead of `ExpiredClientSecret`; `AllCredentialsExpired` is reported only when nothing valid remains.
- **App consent:** Fixed a null reference when an app had only one kind of delegated consent.

### Changed
- `AppRegistrations` rows now include `Publisher`, `ApplicationPermissions`, `TenantWideDelegatedPermissions` and `UserConsentedPermissions`; DemoMode data uses the same shape as live output.

## [1.2.0] - 2026-11-21

### Fixed
- **PIM Eligible & Time-Bound Role Modeling (`Get-LivePrivilegedRole` — `Q1`):** Added inactive PIM-eligible principals from `Get-MgRoleManagementDirectoryRoleEligibilitySchedule` directly into the role evaluation map (reporting `Eligible (Active)` vs `Eligible (Inactive)`), and inspected `EndDateTime` / `ScheduleInfo.Expiration` on `Get-MgRoleManagementDirectoryRoleAssignmentSchedule` so time-bound assigned roles are classified as `TimeBoundAssigned` rather than `Permanent`.
- **Non-Interactive Sign-In Activity & Newly Provisioned Licensed Users (`Get-LiveInactiveLicense` / `Get-LiveStaleGuest` — `Q2`, `Q3`):** Added `Get-MostRecentSignInDateUtc` evaluating `LastSuccessfulSignInDateTime`, `LastSignInDateTime`, and `LastNonInteractiveSignInDateTime`. Users who have never signed in now use `CreatedDateTime` as their inactivity baseline instead of `$ThresholdDays + 1`.
- **SKU Friendly Name Resolution & Conditional Access Scope/Exclusions (`Q4`):** Added `Resolve-FriendlySkuName` via `Get-MgSubscribedSku` so live mode outputs human-readable license names (`Microsoft 365 E5`, `Microsoft Entra ID P2`), and expanded `Get-LiveConditionalAccess` to audit `IncludeUsersScope`, break-glass exclusions, and excessive direct user exclusions.
- **CSV Formula Injection Mitigation (`Protect-CsvValue` — `S3`):** Sanitized string fields starting with `=`, `+`, `-`, `@`, `\t`, or `\r` prior to `Export-Csv` (`CWE-1236`).

### Added
- **OAuth App Consent & Service Principal Credential Hygiene (`Get-LiveAppConsentAndSecret`):** Audits application registrations (`Get-MgApplication`), service principals (`Get-MgServicePrincipal`), and tenant-wide OAuth2 permission grants (`Get-MgOauth2PermissionGrant`) for high-risk permissions and expired or expiring client secrets.

## [1.1.2] - 2026-11-09

### Fixed
- **Privileged role risk evaluation:** Comparing a verified MFA value (`$true`) with `"Unknown"` was coerced to `$true` by PowerShell, so admins with confirmed MFA were flagged `UnverifiedPimAndMfaPosture` when PIM data was unavailable.
- **Group principals:** Role assignments to role-assignable groups are now reported as `PrincipalType = "Group"` instead of `"User"`.

## [1.1.1] - 2026-10-18

### Fixed
- Live queries for MFA registration and PIM schedules, fail-closed unauthenticated execution, and OS-aware BitLocker flagging.

## [1.1.0] - 2026-10-18

### Added
- Live Microsoft Graph query implementations and Conditional Access policy posture auditing.

## [1.0.0] - 2026-10-13

### Added
- Initial release of `Invoke-M365EntraAudit.ps1`.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-13

### Added
- Initial release of `Invoke-M365EntraAudit.ps1`.
- Inactive and stale guest account discovery based on configurable inactivity thresholds.
- Permanent vs PIM-eligible privileged role assignment auditing.
- Inactive licensed user discovery for Microsoft 365 licensing cost optimization.
- Intune managed device compliance posture and BitLocker encryption checks.
- Offline `-DemoMode` parameter for zero-friction evaluation in testing environments.
- Optional CSV export for compliance reporting alongside primary SHA256-hashed JSON artifacts.
- Automated Pester unit test suite.

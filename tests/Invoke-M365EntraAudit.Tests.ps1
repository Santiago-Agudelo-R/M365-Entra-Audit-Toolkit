#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\src\Invoke-M365EntraAudit.ps1'
}

Describe 'Invoke-M365EntraAudit' {

    Context 'DemoMode execution' {
        BeforeAll {
            $script:OutDir = Join-Path -Path $TestDrive -ChildPath 'audit_out'
            $script:Result = & $script:ScriptPath -OutputDirectory $script:OutDir -DemoMode -ExportCsv
            $script:RawJson = Get-Content -LiteralPath $script:Result.ArtifactPath -Raw
            $script:Report = $script:RawJson | ConvertFrom-Json
        }

        It 'returns a completed status object with v1.1.0 metadata' {
            $script:Result.Status | Should -Be 'Completed'
            $script:Report.Metadata.ToolVersion | Should -Be '1.1.0'
        }

        It 'creates the primary JSON artifact and SHA256 sidecar file' {
            Test-Path -LiteralPath $script:Result.ArtifactPath | Should -BeTrue
            Test-Path -LiteralPath $script:Result.HashFile | Should -BeTrue
        }

        It 'contains all expected top-level sections in JSON' {
            $script:Report.PSObject.Properties.Name |
                Should -Be @('Metadata', 'Summary', 'StaleGuests', 'PrivilegedRoles', 'InactiveLicenses', 'EndpointCompliance', 'ConditionalAccess')
        }

        It 'audits stale guest accounts correctly' {
            $script:Result.StaleGuestCount | Should -BeGreaterThan 0
            $script:Report.StaleGuests[0].StatusFlag | Should -Be 'StaleGuest'
        }

        It 'identifies non-compliant endpoints and BitLocker status' {
            $script:Result.NonCompliantDeviceCount | Should -BeGreaterThan 0
            $nonCompliant = $script:Report.EndpointCompliance | Where-Object { $_.DeviceName -eq 'WKSTN-FIN-01' }
            $nonCompliant.IsEncrypted | Should -BeFalse
        }

        It 'audits Conditional Access posture for disabled or report-only policies' {
            $script:Result.AtRiskCaPolicyCount | Should -Be 2
            $reportOnly = $script:Report.ConditionalAccess | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }
            $reportOnly.PostureRisk | Should -Be 'PolicyInReportOnlyMode'
        }

        It 'verifies sidecar SHA256 integrity hash matches the artifact' {
            $computed = (Get-FileHash -LiteralPath $script:Result.ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
            (Get-Content -LiteralPath $script:Result.HashFile -Raw) | Should -Match "^$computed\s"
        }

        It 'exports all 5 CSV files when -ExportCsv is specified' {
            Get-ChildItem -Path $script:OutDir -Filter "*.csv" | Measure-Object | Select-Object -ExpandProperty Count | Should -Be 5
        }
    }
}

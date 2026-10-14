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

        It 'returns a completed status object' {
            $script:Result.Status | Should -Be 'Completed'
        }

        It 'creates the primary JSON artifact and SHA256 sidecar file' {
            Test-Path -LiteralPath $script:Result.ArtifactPath | Should -BeTrue
            Test-Path -LiteralPath $script:Result.HashFile | Should -BeTrue
        }

        It 'contains all expected top-level sections in JSON' {
            $script:Report.PSObject.Properties.Name |
                Should -Be @('Metadata', 'Summary', 'StaleGuests', 'PrivilegedRoles', 'InactiveLicenses', 'EndpointCompliance')
        }

        It 'audits stale guest accounts correctly' {
            $script:Result.StaleGuestCount | Should -BeGreaterThan 0
            $script:Report.StaleGuests[0].StatusFlag | Should -Be 'StaleGuest'
        }

        It 'identifies non-compliant endpoints' {
            $script:Result.NonCompliantDeviceCount | Should -BeGreaterThan 0
        }

        It 'verifies sidecar SHA256 integrity hash matches the artifact' {
            $computed = (Get-FileHash -LiteralPath $script:Result.ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
            (Get-Content -LiteralPath $script:Result.HashFile -Raw) | Should -Match "^$computed\s"
        }

        It 'exports CSV files when -ExportCsv is specified' {
            Get-ChildItem -Path $script:OutDir -Filter "*.csv" | Measure-Object | Select-Object -ExpandProperty Count | Should -Be 4
        }
    }
}

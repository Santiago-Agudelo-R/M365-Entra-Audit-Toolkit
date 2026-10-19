#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\src\Invoke-M365EntraAudit.ps1'
    . $script:ScriptPath -LoadFunctionsOnly
}

Describe 'Invoke-M365EntraAudit' {

    Context 'DemoMode execution' {
        BeforeAll {
            $script:OutDir = Join-Path -Path $TestDrive -ChildPath 'audit_out'
            $script:Result = & $script:ScriptPath -OutputDirectory $script:OutDir -DemoMode -ExportCsv
            $script:RawJson = Get-Content -LiteralPath $script:Result.ArtifactPath -Raw
            $script:Report = $script:RawJson | ConvertFrom-Json
        }

        It 'returns a completed status object with v1.1.1 metadata' {
            $script:Result.Status | Should -Be 'Completed'
            $script:Report.Metadata.ToolVersion | Should -Be '1.1.1'
        }

        It 'creates the primary JSON artifact and SHA256 sidecar file' {
            Test-Path -LiteralPath $script:Result.ArtifactPath | Should -BeTrue
            Test-Path -LiteralPath $script:Result.HashFile | Should -BeTrue
        }

        It 'contains all expected top-level sections in JSON' {
            $script:Report.PSObject.Properties.Name |
                Should -Be @('Metadata', 'Summary', 'StaleGuests', 'PrivilegedRoles', 'InactiveLicenses', 'EndpointCompliance', 'ConditionalAccess')
        }

        It 'verifies sidecar SHA256 integrity hash matches the artifact' {
            $computed = (Get-FileHash -LiteralPath $script:Result.ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
            (Get-Content -LiteralPath $script:Result.HashFile -Raw) | Should -Match "^$computed\s"
        }

        It 'exports all 5 CSV files when -ExportCsv is specified' {
            Get-ChildItem -Path $script:OutDir -Filter "*.csv" | Measure-Object | Select-Object -ExpandProperty Count | Should -Be 5
        }
    }

    Context 'Live Mode Safety Gate (Unauthenticated Execution)' {
        It 'throws a terminating error instead of silently falling back to DemoMode when no Graph session exists' {
            function Get-MgContext { return $null }
            $unauthOutDir = Join-Path -Path $TestDrive -ChildPath 'unauth_out'
            { & $script:ScriptPath -OutputDirectory $unauthOutDir } | Should -Throw '*No active Microsoft Graph session detected*'
            Test-Path -LiteralPath $unauthOutDir | Should -BeFalse
        }
    }

    Context 'Live Graph Query Functions (Mocked Microsoft Graph Responses)' {
        It 'Get-LivePrivilegedRole evaluates real MFA registration and PIM eligibility schedules' {
            function Get-MgReportAuthenticationMethodUserRegistrationDetail {
                return @(
                    [PSCustomObject]@{ Id = 'user-1'; UserPrincipalName = 'admin_no_mfa@contoso.com'; IsMfaRegistered = $false },
                    [PSCustomObject]@{ Id = 'user-2'; UserPrincipalName = 'pim_admin@contoso.com'; IsMfaRegistered = $true }
                )
            }
            function Get-MgRoleManagementDirectoryRoleEligibilitySchedule {
                return @(
                    [PSCustomObject]@{ RoleDefinitionId = 'template-ga'; PrincipalId = 'user-2' }
                )
            }
            function Get-MgRoleManagementDirectoryRoleAssignmentSchedule {
                return @(
                    [PSCustomObject]@{ RoleDefinitionId = 'template-ga'; PrincipalId = 'user-1'; AssignmentType = 'Assigned' }
                )
            }
            function Get-MgDirectoryRole {
                return @(
                    [PSCustomObject]@{ Id = 'role-ga'; RoleTemplateId = 'template-ga'; DisplayName = 'Global Administrator' }
                )
            }
            function Get-MgDirectoryRoleMember {
                return @(
                    [PSCustomObject]@{
                        Id                   = 'user-1'
                        AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.user'; 'userPrincipalName' = 'admin_no_mfa@contoso.com' }
                    },
                    [PSCustomObject]@{
                        Id                   = 'user-2'
                        AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.user'; 'userPrincipalName' = 'pim_admin@contoso.com' }
                    }
                )
            }

            $roles = Get-LivePrivilegedRole
            $roles.Count | Should -Be 2

            $permNoMfa = $roles | Where-Object { $_.PrincipalName -eq 'admin_no_mfa@contoso.com' }
            $permNoMfa.AssignmentType | Should -Be 'Permanent'
            $permNoMfa.IsPimEligible | Should -BeFalse
            $permNoMfa.MfaRegistered | Should -BeFalse
            $permNoMfa.ComplianceRisk | Should -Match 'PrivilegedAccountWithoutMfa'

            $pimUser = $roles | Where-Object { $_.PrincipalName -eq 'pim_admin@contoso.com' }
            $pimUser.AssignmentType | Should -Be 'Eligible (PIM)'
            $pimUser.IsPimEligible | Should -BeTrue
            $pimUser.MfaRegistered | Should -BeTrue
            $pimUser.ComplianceRisk | Should -Be 'None'
        }

        It 'Get-LiveEndpointCompliance flags BitLockerNotActive only on Windows devices and DeviceEncryptionNotActive on non-Windows' {
            function Get-MgDeviceManagementManagedDevice {
                return @(
                    [PSCustomObject]@{
                        DeviceName      = 'WIN-LAPTOP-01'
                        OperatingSystem = 'Windows 11 Enterprise'
                        ComplianceState = 'noncompliant'
                        IsEncrypted     = $false
                        LastSyncDateTime = [DateTime]::UtcNow
                        ManagementAgent = 'mdm'
                    },
                    [PSCustomObject]@{
                        DeviceName      = 'MACBOOK-DESIGN-02'
                        OperatingSystem = 'macOS 14.5'
                        ComplianceState = 'noncompliant'
                        IsEncrypted     = $false
                        LastSyncDateTime = [DateTime]::UtcNow
                        ManagementAgent = 'mdm'
                    }
                )
            }

            $endpoints = Get-LiveEndpointCompliance
            $winDev = $endpoints | Where-Object { $_.DeviceName -eq 'WIN-LAPTOP-01' }
            $macDev = $endpoints | Where-Object { $_.DeviceName -eq 'MACBOOK-DESIGN-02' }

            $winDev.NonComplianceReasons | Should -Match 'BitLockerNotActive'
            $macDev.NonComplianceReasons | Should -Not -Match 'BitLockerNotActive'
            $macDev.NonComplianceReasons | Should -Match 'DeviceEncryptionNotActive'
        }
    }
}

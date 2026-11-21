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

        It 'returns a completed status object with valid semantic version metadata' {
            $script:Result.Status | Should -Be 'Completed'
            $script:Report.Metadata.ToolVersion | Should -Match '^\d+\.\d+\.\d+$'
        }

        It 'creates the primary JSON artifact and SHA256 sidecar file' {
            Test-Path -LiteralPath $script:Result.ArtifactPath | Should -BeTrue
            Test-Path -LiteralPath $script:Result.HashFile | Should -BeTrue
        }

        It 'contains all expected top-level sections in JSON' {
            $script:Report.PSObject.Properties.Name |
                Should -Be @('Metadata', 'Summary', 'StaleGuests', 'PrivilegedRoles', 'InactiveLicenses', 'EndpointCompliance', 'ConditionalAccess', 'AppRegistrations')
        }

        It 'verifies sidecar SHA256 integrity hash matches the artifact' {
            $computed = (Get-FileHash -LiteralPath $script:Result.ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
            (Get-Content -LiteralPath $script:Result.HashFile -Raw) | Should -Match "^$computed\s"
        }

        It 'exports all 6 CSV files when -ExportCsv is specified' {
            Get-ChildItem -Path $script:OutDir -Filter "*.csv" | Measure-Object | Select-Object -ExpandProperty Count | Should -Be 6
        }
    }

    Context 'CSV Formula Injection Sanitization (CWE-1236)' {
        It 'prefixes untrusted strings starting with =, +, -, or @ with a single quote while preserving negative numbers' {
            $unsafe = @(
                [PSCustomObject]@{
                    DisplayName     = "=CMD|' /C calc'!A0"
                    PlusPayload     = "+SUM(1,1)"
                    AtPayload       = "@SUM(1,1)"
                    DaysUntilExpiry = -12
                }
            )
            $safe = ConvertTo-SafeCsvRecord -InputObjects $unsafe
            $safe[0].DisplayName | Should -Be "'=CMD|' /C calc'!A0"
            $safe[0].PlusPayload | Should -Be "'+SUM(1,1)"
            $safe[0].AtPayload | Should -Be "'@SUM(1,1)"
            $safe[0].DaysUntilExpiry | Should -Be -12
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
        It 'Get-LivePrivilegedRole includes inactive PIM-eligible principals, distinguishes TimeBoundAssigned vs Permanent, and checks MFA' {
            function Get-MgReportAuthenticationMethodUserRegistrationDetail {
                return @(
                    [PSCustomObject]@{ Id = 'user-perm'; UserPrincipalName = 'admin_no_mfa@contoso.com'; IsMfaRegistered = $false },
                    [PSCustomObject]@{ Id = 'user-pim-active'; UserPrincipalName = 'pim_active@contoso.com'; IsMfaRegistered = $true },
                    [PSCustomObject]@{ Id = 'user-pim-inactive'; UserPrincipalName = 'pim_inactive@contoso.com'; IsMfaRegistered = $true },
                    [PSCustomObject]@{ Id = 'user-timebound'; UserPrincipalName = 'contractor_timebound@contoso.com'; IsMfaRegistered = $true }
                )
            }
            function Get-MgRoleManagementDirectoryRoleEligibilitySchedule {
                return @(
                    [PSCustomObject]@{ RoleDefinitionId = 'template-ga'; PrincipalId = 'user-pim-active' },
                    [PSCustomObject]@{
                        RoleDefinitionId = 'template-ga'
                        PrincipalId      = 'user-pim-inactive'
                        Principal        = [PSCustomObject]@{
                            AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.user'; 'userPrincipalName' = 'pim_inactive@contoso.com' }
                        }
                    }
                )
            }
            function Get-MgRoleManagementDirectoryRoleAssignmentSchedule {
                return @(
                    [PSCustomObject]@{ RoleDefinitionId = 'template-ga'; PrincipalId = 'user-perm'; AssignmentType = 'Assigned'; EndDateTime = $null },
                    [PSCustomObject]@{ RoleDefinitionId = 'template-ga'; PrincipalId = 'user-timebound'; AssignmentType = 'Assigned'; EndDateTime = [DateTime]::UtcNow.AddDays(30) }
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
                        Id                   = 'user-perm'
                        AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.user'; 'userPrincipalName' = 'admin_no_mfa@contoso.com' }
                    },
                    [PSCustomObject]@{
                        Id                   = 'user-pim-active'
                        AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.user'; 'userPrincipalName' = 'pim_active@contoso.com' }
                    },
                    [PSCustomObject]@{
                        Id                   = 'user-timebound'
                        AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.user'; 'userPrincipalName' = 'contractor_timebound@contoso.com' }
                    }
                )
            }

            $roles = Get-LivePrivilegedRole
            $roles.Count | Should -Be 4

            $permNoMfa = $roles | Where-Object { $_.PrincipalName -eq 'admin_no_mfa@contoso.com' }
            $permNoMfa.AssignmentType | Should -Be 'Permanent'
            $permNoMfa.IsPimEligible | Should -BeFalse
            $permNoMfa.MfaRegistered | Should -BeFalse
            $permNoMfa.ComplianceRisk | Should -Match 'PrivilegedAccountWithoutMfa'

            $pimActive = $roles | Where-Object { $_.PrincipalName -eq 'pim_active@contoso.com' }
            $pimActive.AssignmentType | Should -Be 'Eligible (Active)'
            $pimActive.IsPimEligible | Should -BeTrue
            $pimActive.ComplianceRisk | Should -Be 'None'

            $pimInactive = $roles | Where-Object { $_.PrincipalName -eq 'pim_inactive@contoso.com' }
            $pimInactive.AssignmentType | Should -Be 'Eligible (Inactive)'
            $pimInactive.IsPimEligible | Should -BeTrue
            $pimInactive.ComplianceRisk | Should -Be 'None'

            $timeBound = $roles | Where-Object { $_.PrincipalName -eq 'contractor_timebound@contoso.com' }
            $timeBound.AssignmentType | Should -Be 'TimeBoundAssigned'
            $timeBound.IsPimEligible | Should -BeFalse
            $timeBound.ComplianceRisk | Should -Be 'None'
        }

        It 'Get-LiveInactiveLicense respects LastNonInteractiveSignInDateTime, uses CreatedDateTime for new users, and translates SKU names' {
            function Get-MgSubscribedSku {
                return @(
                    [PSCustomObject]@{ SkuId = 'guid-e5'; SkuPartNumber = 'SPE_E5' }
                )
            }
            function Get-MgUser {
                $now = [DateTime]::UtcNow
                return @(
                    # User 1: Brand-new employee created yesterday who has never signed in -> must NOT be flagged
                    [PSCustomObject]@{
                        UserPrincipalName = 'new_hire@contoso.com'
                        DisplayName       = 'New Hire'
                        AccountEnabled    = $true
                        CreatedDateTime   = $now.AddDays(-1)
                        AssignedLicenses  = @([PSCustomObject]@{ SkuId = 'guid-e5' })
                        SignInActivity    = $null
                    },
                    # User 2: Active via non-interactive token 5 days ago (interactive sign-in was 120 days ago) -> must NOT be flagged
                    [PSCustomObject]@{
                        UserPrincipalName = 'token_active@contoso.com'
                        DisplayName       = 'Token Active User'
                        AccountEnabled    = $true
                        CreatedDateTime   = $now.AddDays(-300)
                        AssignedLicenses  = @([PSCustomObject]@{ SkuId = 'guid-e5' })
                        SignInActivity    = [PSCustomObject]@{
                            LastSignInDateTime               = $now.AddDays(-120)
                            LastNonInteractiveSignInDateTime = $now.AddDays(-5)
                        }
                    },
                    # User 3: Truly inactive for 150 days -> must be flagged with friendly SKU name
                    [PSCustomObject]@{
                        UserPrincipalName = 'stale_user@contoso.com'
                        DisplayName       = 'Stale User'
                        AccountEnabled    = $true
                        CreatedDateTime   = $now.AddDays(-400)
                        AssignedLicenses  = @([PSCustomObject]@{ SkuId = 'guid-e5' })
                        SignInActivity    = [PSCustomObject]@{
                            LastSignInDateTime               = $now.AddDays(-150)
                            LastNonInteractiveSignInDateTime = $now.AddDays(-150)
                        }
                    }
                )
            }

            $reclaimable = @(Get-LiveInactiveLicense -ThresholdDays 90)
            $reclaimable.Count | Should -Be 1
            $reclaimable[0].UserPrincipalName | Should -Be 'stale_user@contoso.com'
            $reclaimable[0].AssignedLicenses | Should -Be 'Microsoft 365 E5'
        }

        It 'Get-LiveEndpointCompliance flags BitLockerNotActive only on Windows devices and DeviceEncryptionNotActive on non-Windows' {
            function Get-MgDeviceManagementManagedDevice {
                return @(
                    [PSCustomObject]@{
                        DeviceName       = 'WIN-LAPTOP-01'
                        OperatingSystem  = 'Windows 11 Enterprise'
                        ComplianceState  = 'noncompliant'
                        IsEncrypted      = $false
                        LastSyncDateTime = [DateTime]::UtcNow
                        ManagementAgent  = 'mdm'
                    },
                    [PSCustomObject]@{
                        DeviceName       = 'MACBOOK-DESIGN-02'
                        OperatingSystem  = 'macOS 14.5'
                        ComplianceState  = 'noncompliant'
                        IsEncrypted      = $false
                        LastSyncDateTime = [DateTime]::UtcNow
                        ManagementAgent  = 'mdm'
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

        It 'Get-LiveAppConsentAndSecret resolves ServicePrincipals and flags high-risk OAuth grants and expired client secrets' {
            function Get-MgServicePrincipal {
                return @(
                    [PSCustomObject]@{ AppId = 'app-111'; Id = 'sp-risky-1' },
                    [PSCustomObject]@{ AppId = 'app-222'; Id = 'sp-clean-2' }
                )
            }
            function Get-MgOauth2PermissionGrant {
                return @(
                    [PSCustomObject]@{
                        ClientId    = 'sp-risky-1'
                        ConsentType = 'AllPrincipals'
                        Scope       = 'User.Read Mail.ReadWrite Mail.Send'
                    }
                )
            }
            function Get-MgApplication {
                return @(
                    [PSCustomObject]@{
                        DisplayName         = 'Risky-Mail-App'
                        AppId               = 'app-111'
                        PasswordCredentials = @(
                            [PSCustomObject]@{ EndDateTime = [DateTime]::UtcNow.AddDays(-5) }
                        )
                        KeyCredentials      = @()
                    },
                    [PSCustomObject]@{
                        DisplayName         = 'Clean-Internal-App'
                        AppId               = 'app-222'
                        PasswordCredentials = @(
                            [PSCustomObject]@{ EndDateTime = [DateTime]::UtcNow.AddDays(120) }
                        )
                        KeyCredentials      = @()
                    }
                )
            }

            $apps = Get-LiveAppConsentAndSecret -ExpiryWarningDays 30
            @($apps).Count | Should -Be 1
            $apps[0].AppDisplayName | Should -Be 'Risky-Mail-App'
            $apps[0].GovernanceRisk | Should -Match 'HighRiskOAuthPermissions'
            $apps[0].GovernanceRisk | Should -Match 'ExpiredClientSecret'
        }
    }
}

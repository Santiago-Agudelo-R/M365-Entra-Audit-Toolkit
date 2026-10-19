<#
.SYNOPSIS
    Automated hygiene and governance auditor for Microsoft 365, Entra ID, and Intune.

.DESCRIPTION
    Invoke-M365EntraAudit audits five critical governance domains across cloud and hybrid tenants:
    1. Stale guest accounts (>60/90 days without interactive sign-in).
    2. High-privilege role assignments (Global Administrator, Security Administrator, Intune Administrator),
       evaluating permanent vs PIM-eligible schedules and querying MFA registration status.
    3. Inactive licensed accounts (license optimization and disabled account reclamation).
    4. Intune endpoint compliance posture and missing BitLocker encryption on Windows devices.
    5. Conditional Access policy posture (detecting disabled or report-only policies).

    Live execution requires an authenticated Microsoft Graph session (Connect-MgGraph) and stops
    with an explicit error if no session is active. For offline testing or CI pipelines without
    tenant credentials, pass the -DemoMode switch explicitly.
    All dates are strictly formatted in ISO 8601 UTC.

.PARAMETER OutputDirectory
    Directory to export JSON and CSV audit artifacts. Defaults to "$PSScriptRoot\AuditOutput".

.PARAMETER InactiveDaysThreshold
    Number of days of inactivity to flag accounts as stale. Defaults to 90.

.PARAMETER DemoMode
    Executes an offline synthetic audit using sanitized mock enterprise data.

.PARAMETER ExportCsv
    Exports individual CSV reports for each audited category alongside the primary JSON artifact.

.PARAMETER LoadFunctionsOnly
    Loads internal audit functions into the caller scope without executing the main entrypoint (used by Pester unit tests).

.EXAMPLE
    .\Invoke-M365EntraAudit.ps1 -DemoMode

.EXAMPLE
    Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","RoleManagement.Read.Directory","UserAuthenticationMethod.Read.All","DeviceManagementManagedDevices.Read.All","Policy.Read.All","AuditLog.Read.All"
    .\Invoke-M365EntraAudit.ps1 -OutputDirectory "C:\Audits\M365" -InactiveDaysThreshold 60 -ExportCsv

.NOTES
    Author: Santiago Agudelo
    License: MIT
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = "$PSScriptRoot\AuditOutput",

    [Parameter(Mandatory = $false)]
    [ValidateRange(30, 365)]
    [int]$InactiveDaysThreshold = 90,

    [Parameter(Mandatory = $false)]
    [switch]$DemoMode,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [switch]$LoadFunctionsOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-MockTelemetry {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param ([int]$ThresholdDays)

    $nowUtc = [DateTime]::UtcNow
    $guest1Days = [Math]::Max($ThresholdDays + 25, 115)
    $guest2Days = [Math]::Max($ThresholdDays + 8, 98)

    $staleGuests = @(
        [PSCustomObject]@{
            UserPrincipalName     = "vendor.contractor_external.com#EXT#@contoso.onmicrosoft.com"
            DisplayName           = "External Vendor Auditor"
            AccountEnabled        = $true
            CreatedDateTimeUtc    = $nowUtc.AddDays(-180).ToString("o")
            LastSignInDateTimeUtc = $nowUtc.AddDays(-$guest1Days).ToString("o")
            DaysInactive          = $guest1Days
            StatusFlag            = "StaleGuest"
        },
        [PSCustomObject]@{
            UserPrincipalName     = "partner.support_partner.org#EXT#@contoso.onmicrosoft.com"
            DisplayName           = "Partner Escalation Engineer"
            AccountEnabled        = $true
            CreatedDateTimeUtc    = $nowUtc.AddDays(-210).ToString("o")
            LastSignInDateTimeUtc = $nowUtc.AddDays(-$guest2Days).ToString("o")
            DaysInactive          = $guest2Days
            StatusFlag            = "StaleGuest"
        }
    )

    $privilegedRoles = @(
        [PSCustomObject]@{
            RoleName       = "Global Administrator"
            PrincipalName  = "admin_secops@contoso.com"
            PrincipalType  = "User"
            AssignmentType = "Permanent"
            IsPimEligible  = $false
            MfaRegistered  = $true
            ComplianceRisk = "PermanentGlobalAdminAssignment"
        },
        [PSCustomObject]@{
            RoleName       = "Security Administrator"
            PrincipalName  = "soc_lead@contoso.com"
            PrincipalType  = "User"
            AssignmentType = "Eligible (PIM)"
            IsPimEligible  = $true
            MfaRegistered  = $true
            ComplianceRisk = "None"
        },
        [PSCustomObject]@{
            RoleName       = "Privileged Role Administrator"
            PrincipalName  = "legacy_service_account@contoso.com"
            PrincipalType  = "ServicePrincipal"
            AssignmentType = "Permanent"
            IsPimEligible  = $false
            MfaRegistered  = "N/A (ServicePrincipal)"
            ComplianceRisk = "ServicePrincipalDirectRoleAssignment"
        }
    )

    $inactiveLicenses = @(
        [PSCustomObject]@{
            UserPrincipalName     = "former.employee1@contoso.com"
            DisplayName           = "Former Staff 1"
            AccountEnabled        = $false
            AssignedLicenses      = "Microsoft 365 E5; Microsoft Entra ID P2"
            LastSignInDateTimeUtc = $nowUtc.AddDays(-140).ToString("o")
            DaysInactive          = 140
            CostOptimization      = "DisabledAccountWithActiveLicense"
        },
        [PSCustomObject]@{
            UserPrincipalName     = "temp_project_user@contoso.com"
            DisplayName           = "Temp Project User"
            AccountEnabled        = $true
            AssignedLicenses      = "Microsoft 365 E3"
            LastSignInDateTimeUtc = $nowUtc.AddDays(-105).ToString("o")
            DaysInactive          = 105
            CostOptimization      = "ReclaimableLicense"
        }
    )

    $endpointCompliance = @(
        [PSCustomObject]@{
            DeviceName           = "WKSTN-FIN-01"
            OperatingSystem      = "Windows 11 Enterprise"
            ComplianceState      = "NonCompliant"
            IsEncrypted          = $false
            NonComplianceReasons = "BitLockerNotActive; AntivirusDisabled"
            LastSyncDateTimeUtc  = $nowUtc.AddDays(-2).ToString("o")
            ManagedBy            = "Intune"
        },
        [PSCustomObject]@{
            DeviceName           = "LAPTOP-DEV-09"
            OperatingSystem      = "Windows 11 Enterprise"
            ComplianceState      = "Compliant"
            IsEncrypted          = $true
            NonComplianceReasons = "None"
            LastSyncDateTimeUtc  = $nowUtc.AddHours(-4).ToString("o")
            ManagedBy            = "Intune"
        },
        [PSCustomObject]@{
            DeviceName           = "SRV-APPS-02"
            OperatingSystem      = "Windows Server 2022"
            ComplianceState      = "NonCompliant"
            IsEncrypted          = $true
            NonComplianceReasons = "OutdatedSecurityBaseline"
            LastSyncDateTimeUtc  = $nowUtc.AddDays(-14).ToString("o")
            ManagedBy            = "ConfigurationManager"
        }
    )

    $conditionalAccess = @(
        [PSCustomObject]@{
            PolicyName    = "CA01-Require-MFA-All-Users"
            State         = "enabled"
            GrantControls = "mfa"
            PostureRisk   = "None"
        },
        [PSCustomObject]@{
            PolicyName    = "CA04-Require-Compliant-Device-Finance"
            State         = "enabledForReportingButNotEnforced"
            GrantControls = "compliantDevice"
            PostureRisk   = "PolicyInReportOnlyMode"
        },
        [PSCustomObject]@{
            PolicyName    = "CA07-Block-Legacy-Authentication"
            State         = "disabled"
            GrantControls = "block"
            PostureRisk   = "PolicyDisabled"
        }
    )

    return [PSCustomObject]@{
        StaleGuests        = $staleGuests
        PrivilegedRoles    = $privilegedRoles
        InactiveLicenses   = $inactiveLicenses
        EndpointCompliance = $endpointCompliance
        ConditionalAccess  = $conditionalAccess
    }
}

function Get-LiveStaleGuest {
    [CmdletBinding()]
    [OutputType([object[]])]
    param ([int]$ThresholdDays)

    $results = [System.Collections.Generic.List[PSObject]]::new()
    $nowUtc = [DateTime]::UtcNow

    $guests = Get-MgUser -Filter "userType eq 'Guest'" -Property Id, UserPrincipalName, DisplayName, AccountEnabled, CreatedDateTime, SignInActivity -All -ErrorAction Stop
    foreach ($user in $guests) {
        $lastSignIn = $null
        if ($user.PSObject.Properties['SignInActivity'] -and $user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
            $lastSignIn = ([DateTime]$user.SignInActivity.LastSignInDateTime).ToUniversalTime()
        }

        $createdUtc = if ($user.CreatedDateTime) { ([DateTime]$user.CreatedDateTime).ToUniversalTime() } else { $nowUtc }
        $referenceDate = if ($lastSignIn) { $lastSignIn } else { $createdUtc }
        $daysInactive = [int][Math]::Floor(($nowUtc - $referenceDate).TotalDays)

        if ($daysInactive -ge $ThresholdDays) {
            $results.Add([PSCustomObject]@{
                UserPrincipalName     = $user.UserPrincipalName
                DisplayName           = $user.DisplayName
                AccountEnabled        = [bool]$user.AccountEnabled
                CreatedDateTimeUtc    = $createdUtc.ToString("o")
                LastSignInDateTimeUtc = if ($lastSignIn) { $lastSignIn.ToString("o") } else { "NeverSignedIn" }
                DaysInactive          = $daysInactive
                StatusFlag            = "StaleGuest"
            })
        }
    }

    return , $results.ToArray()
}

function Get-LivePrivilegedRole {
    [CmdletBinding()]
    [OutputType([object[]])]
    param ()

    $results = [System.Collections.Generic.List[PSObject]]::new()
    $targetRoles = @(
        "Global Administrator",
        "Security Administrator",
        "Privileged Role Administrator",
        "Intune Administrator",
        "Exchange Administrator",
        "Conditional Access Administrator"
    )

    # 1. Query real MFA registration telemetry (never assume $true if unavailable)
    $mfaLookup = @{}
    $mfaTelemetryAvailable = $false
    if (Get-Command -Name Get-MgReportAuthenticationMethodUserRegistrationDetail -ErrorAction SilentlyContinue) {
        try {
            $mfaReports = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
            foreach ($entry in $mfaReports) {
                if ($entry.UserPrincipalName) {
                    $mfaLookup[$entry.UserPrincipalName.ToLowerInvariant()] = [bool]$entry.IsMfaRegistered
                }
                if ($entry.Id) {
                    $mfaLookup[$entry.Id.ToLowerInvariant()] = [bool]$entry.IsMfaRegistered
                }
            }
            $mfaTelemetryAvailable = $true
        }
        catch {
            Write-Warning "Unable to query MFA registration details (requires UserAuthenticationMethod.Read.All or AuditLog.Read.All): $_"
        }
    }

    # 2. Query PIM Eligibility and Assignment Schedules when available (Entra ID P2)
    $pimEligibleKeys = @{}
    $pimPermanentKeys = @{}
    $pimTelemetryAvailable = $false

    if ((Get-Command -Name Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ErrorAction SilentlyContinue) -and
        (Get-Command -Name Get-MgRoleManagementDirectoryRoleAssignmentSchedule -ErrorAction SilentlyContinue)) {
        try {
            $eligSchedules = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
            foreach ($s in $eligSchedules) {
                $pimEligibleKeys["$($s.RoleDefinitionId):$($s.PrincipalId)"] = $true
            }

            $assignSchedules = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ErrorAction Stop
            foreach ($a in $assignSchedules) {
                if ($a.AssignmentType -eq 'Assigned' -and (-not $pimEligibleKeys.ContainsKey("$($a.RoleDefinitionId):$($a.PrincipalId)"))) {
                    $pimPermanentKeys["$($a.RoleDefinitionId):$($a.PrincipalId)"] = $true
                }
            }
            $pimTelemetryAvailable = $true
        }
        catch {
            Write-Warning "Unable to query PIM role schedules (requires RoleManagement.Read.Directory and Entra ID P2): $_"
        }
    }

    $roles = Get-MgDirectoryRole -All -ErrorAction Stop | Where-Object { $_.DisplayName -in $targetRoles }
    foreach ($role in $roles) {
        $roleTemplateId = if ($role.PSObject.Properties['RoleTemplateId'] -and $role.RoleTemplateId) { $role.RoleTemplateId } else { $role.Id }
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop

        foreach ($member in $members) {
            $odataType = $member.AdditionalProperties['@odata.type']
            $principalName = if ($member.AdditionalProperties.ContainsKey('userPrincipalName')) {
                [string]$member.AdditionalProperties['userPrincipalName']
            }
            elseif ($member.AdditionalProperties.ContainsKey('displayName')) {
                [string]$member.AdditionalProperties['displayName']
            }
            else {
                [string]$member.Id
            }

            $principalType = switch ($odataType) {
                '#microsoft.graph.servicePrincipal' { "ServicePrincipal" }
                '#microsoft.graph.group'            { "Group" }
                default                             { "User" }
            }
            $scheduleKey = "${roleTemplateId}:$($member.Id)"

            # Determine PIM assignment status without fabricating values
            $assignmentType = "Unknown"
            $isPimEligible = "Unknown"
            if ($pimTelemetryAvailable) {
                if ($pimEligibleKeys.ContainsKey($scheduleKey)) {
                    $assignmentType = "Eligible (PIM)"
                    $isPimEligible = $true
                }
                elseif ($pimPermanentKeys.ContainsKey($scheduleKey)) {
                    $assignmentType = "Permanent"
                    $isPimEligible = $false
                }
                else {
                    $assignmentType = "Permanent"
                    $isPimEligible = $false
                }
            }

            # Determine MFA status without fabricating values
            $mfaStatus = "Unknown"
            if ($principalType -eq "ServicePrincipal") {
                $mfaStatus = "N/A (ServicePrincipal)"
            }
            elseif ($principalType -eq "Group") {
                $mfaStatus = "N/A (Group)"
            }
            elseif ($mfaTelemetryAvailable) {
                $upnKey = $principalName.ToLowerInvariant()
                $idKey = ([string]$member.Id).ToLowerInvariant()
                if ($mfaLookup.ContainsKey($upnKey)) {
                    $mfaStatus = $mfaLookup[$upnKey]
                }
                elseif ($mfaLookup.ContainsKey($idKey)) {
                    $mfaStatus = $mfaLookup[$idKey]
                }
            }

            # Evaluate ComplianceRisk based on verified telemetry
            $riskReasons = [System.Collections.Generic.List[string]]::new()
            if ($principalType -eq "ServicePrincipal") {
                $riskReasons.Add("ServicePrincipalDirectRoleAssignment")
            }
            if ($mfaStatus -is [bool] -and (-not $mfaStatus)) {
                $riskReasons.Add("PrivilegedAccountWithoutMfa")
            }
            if ($assignmentType -eq "Permanent") {
                if ($role.DisplayName -eq "Global Administrator") {
                    $riskReasons.Add("PermanentGlobalAdminAssignment")
                }
                else {
                    $riskReasons.Add("PermanentHighPrivilegeAssignment")
                }
            }
            elseif ($assignmentType -eq "Unknown" -and "Unknown" -eq $mfaStatus) {
                $riskReasons.Add("UnverifiedPimAndMfaPosture")
            }

            $results.Add([PSCustomObject]@{
                RoleName       = $role.DisplayName
                PrincipalName  = $principalName
                PrincipalType  = $principalType
                AssignmentType = $assignmentType
                IsPimEligible  = $isPimEligible
                MfaRegistered  = $mfaStatus
                ComplianceRisk = if ($riskReasons.Count -gt 0) { $riskReasons -join "; " } else { "None" }
            })
        }
    }

    return , $results.ToArray()
}

function Get-LiveInactiveLicense {
    [CmdletBinding()]
    [OutputType([object[]])]
    param ([int]$ThresholdDays)

    $results = [System.Collections.Generic.List[PSObject]]::new()
    $nowUtc = [DateTime]::UtcNow

    $users = Get-MgUser -Filter "userType eq 'Member'" -Property Id, UserPrincipalName, DisplayName, AccountEnabled, AssignedLicenses, SignInActivity -All -ErrorAction Stop
    foreach ($u in $users) {
        $licenseCount = @($u.AssignedLicenses).Count
        if ($licenseCount -eq 0) { continue }

        $lastSignIn = $null
        if ($u.PSObject.Properties['SignInActivity'] -and $u.SignInActivity -and $u.SignInActivity.LastSignInDateTime) {
            $lastSignIn = ([DateTime]$u.SignInActivity.LastSignInDateTime).ToUniversalTime()
        }

        $daysInactive = if ($lastSignIn) { [int][Math]::Floor(($nowUtc - $lastSignIn).TotalDays) } else { $ThresholdDays + 1 }
        $skuList = ($u.AssignedLicenses | ForEach-Object { $_.SkuId }) -join "; "

        if (-not $u.AccountEnabled) {
            $results.Add([PSCustomObject]@{
                UserPrincipalName     = $u.UserPrincipalName
                DisplayName           = $u.DisplayName
                AccountEnabled        = $false
                AssignedLicenses      = $skuList
                LastSignInDateTimeUtc = if ($lastSignIn) { $lastSignIn.ToString("o") } else { "Unknown" }
                DaysInactive          = $daysInactive
                CostOptimization      = "DisabledAccountWithActiveLicense"
            })
        }
        elseif ($daysInactive -ge $ThresholdDays) {
            $results.Add([PSCustomObject]@{
                UserPrincipalName     = $u.UserPrincipalName
                DisplayName           = $u.DisplayName
                AccountEnabled        = $true
                AssignedLicenses      = $skuList
                LastSignInDateTimeUtc = if ($lastSignIn) { $lastSignIn.ToString("o") } else { "Unknown" }
                DaysInactive          = $daysInactive
                CostOptimization      = "ReclaimableLicense"
            })
        }
    }

    return , $results.ToArray()
}

function Get-LiveEndpointCompliance {
    [CmdletBinding()]
    [OutputType([object[]])]
    param ()

    $results = [System.Collections.Generic.List[PSObject]]::new()
    $devices = Get-MgDeviceManagementManagedDevice -All -ErrorAction Stop

    foreach ($dev in $devices) {
        $isEncrypted = [bool]$dev.IsEncrypted
        $osName = [string]$dev.OperatingSystem
        $state = [string]$dev.ComplianceState
        $reasons = [System.Collections.Generic.List[string]]::new()

        if (-not $isEncrypted) {
            if ($osName -match '(?i)^Windows') {
                $reasons.Add("BitLockerNotActive")
            }
            else {
                $reasons.Add("DeviceEncryptionNotActive")
            }
        }
        if ($state -ne "compliant") {
            $reasons.Add("PolicyState:$state")
        }

        $lastSyncUtc = if ($dev.LastSyncDateTime) { ([DateTime]$dev.LastSyncDateTime).ToUniversalTime().ToString("o") } else { $null }

        $results.Add([PSCustomObject]@{
            DeviceName           = $dev.DeviceName
            OperatingSystem      = $osName
            ComplianceState      = if ($state -eq "compliant") { "Compliant" } else { "NonCompliant" }
            IsEncrypted          = $isEncrypted
            NonComplianceReasons = if ($reasons.Count -gt 0) { $reasons -join "; " } else { "None" }
            LastSyncDateTimeUtc  = $lastSyncUtc
            ManagedBy            = [string]$dev.ManagementAgent
        })
    }

    return , $results.ToArray()
}

function Get-LiveConditionalAccess {
    [CmdletBinding()]
    [OutputType([object[]])]
    param ()

    $results = [System.Collections.Generic.List[PSObject]]::new()
    $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

    foreach ($pol in $policies) {
        $controls = if ($pol.GrantControls -and $pol.GrantControls.BuiltInControls) {
            ($pol.GrantControls.BuiltInControls) -join "; "
        }
        else {
            "None"
        }

        $risk = switch ($pol.State) {
            "disabled"                          { "PolicyDisabled" }
            "enabledForReportingButNotEnforced" { "PolicyInReportOnlyMode" }
            default                             { "None" }
        }

        $results.Add([PSCustomObject]@{
            PolicyName    = $pol.DisplayName
            State         = [string]$pol.State
            GrantControls = $controls
            PostureRisk   = $risk
        })
    }

    return , $results.ToArray()
}

if ($LoadFunctionsOnly) {
    return
}

# --- Execution Entry Point ---
$executionTimestampUtc = [DateTime]::UtcNow.ToString("o")

$auditResults = $null
$effectiveMode = "Live"

if ($DemoMode) {
    Write-Verbose "Executing audit in DemoMode with synthetic enterprise data..."
    $effectiveMode = "DemoMode"
    $auditResults = Get-MockTelemetry -ThresholdDays $InactiveDaysThreshold
}
else {
    if (-not (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) -or ($null -eq (Get-MgContext))) {
        throw "No active Microsoft Graph session detected. Authenticate first with Connect-MgGraph, or specify -DemoMode for offline synthetic evaluation."
    }

    Write-Verbose "Querying live Microsoft Graph tenant telemetry..."
    $auditResults = [PSCustomObject]@{
        StaleGuests        = Get-LiveStaleGuest -ThresholdDays $InactiveDaysThreshold
        PrivilegedRoles    = Get-LivePrivilegedRole
        InactiveLicenses   = Get-LiveInactiveLicense -ThresholdDays $InactiveDaysThreshold
        EndpointCompliance = Get-LiveEndpointCompliance
        ConditionalAccess  = Get-LiveConditionalAccess
    }
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
}

$summaryReport = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        ToolName              = "M365-Entra-Audit-Toolkit"
        ToolVersion           = "1.1.1"
        TimestampUtc          = $executionTimestampUtc
        InactiveDaysThreshold = $InactiveDaysThreshold
        ExecutionMode         = $effectiveMode
    }
    Summary = [PSCustomObject]@{
        TotalStaleGuestsFound        = @($auditResults.StaleGuests).Count
        TotalPrivilegedAssignments   = @($auditResults.PrivilegedRoles).Count
        TotalReclaimableLicenses     = @($auditResults.InactiveLicenses).Count
        TotalNonCompliantEndpoints   = @($auditResults.EndpointCompliance | Where-Object { $_.ComplianceState -ne 'Compliant' }).Count
        TotalAtRiskCaPolicies        = @($auditResults.ConditionalAccess | Where-Object { $_.PostureRisk -ne 'None' }).Count
    }
    StaleGuests        = $auditResults.StaleGuests
    PrivilegedRoles    = $auditResults.PrivilegedRoles
    InactiveLicenses   = $auditResults.InactiveLicenses
    EndpointCompliance = $auditResults.EndpointCompliance
    ConditionalAccess  = $auditResults.ConditionalAccess
}

$timestampFileStr = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmss")
$jsonFileName = "M365Audit_${timestampFileStr}.json"
$jsonPath = Join-Path -Path $OutputDirectory -ChildPath $jsonFileName

$jsonBody = $summaryReport | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($jsonPath, $jsonBody, [System.Text.Encoding]::UTF8)

$reportHash = (Get-FileHash -LiteralPath $jsonPath -Algorithm SHA256).Hash.ToLowerInvariant()
$hashFileName = "${jsonFileName}.sha256"
$hashPath = Join-Path -Path $OutputDirectory -ChildPath $hashFileName
[System.IO.File]::WriteAllText($hashPath, "$reportHash  $jsonFileName`n", [System.Text.Encoding]::UTF8)

if ($ExportCsv) {
    $auditResults.StaleGuests | Export-Csv -Path (Join-Path $OutputDirectory "StaleGuests_${timestampFileStr}.csv") -NoTypeInformation -Encoding UTF8
    $auditResults.PrivilegedRoles | Export-Csv -Path (Join-Path $OutputDirectory "PrivilegedRoles_${timestampFileStr}.csv") -NoTypeInformation -Encoding UTF8
    $auditResults.InactiveLicenses | Export-Csv -Path (Join-Path $OutputDirectory "InactiveLicenses_${timestampFileStr}.csv") -NoTypeInformation -Encoding UTF8
    $auditResults.EndpointCompliance | Export-Csv -Path (Join-Path $OutputDirectory "EndpointCompliance_${timestampFileStr}.csv") -NoTypeInformation -Encoding UTF8
    $auditResults.ConditionalAccess | Export-Csv -Path (Join-Path $OutputDirectory "ConditionalAccess_${timestampFileStr}.csv") -NoTypeInformation -Encoding UTF8
}

return [PSCustomObject]@{
    Status                   = "Completed"
    ArtifactPath             = $jsonPath
    HashFile                 = $hashPath
    SHA256                   = $reportHash
    StaleGuestCount          = $summaryReport.Summary.TotalStaleGuestsFound
    PrivilegedRoleCount      = $summaryReport.Summary.TotalPrivilegedAssignments
    ReclaimableLicenseCount  = $summaryReport.Summary.TotalReclaimableLicenses
    NonCompliantDeviceCount  = $summaryReport.Summary.TotalNonCompliantEndpoints
    AtRiskCaPolicyCount      = $summaryReport.Summary.TotalAtRiskCaPolicies
}

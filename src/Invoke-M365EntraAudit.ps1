<#
.SYNOPSIS
    Automated hygiene and governance auditor for Microsoft 365, Entra ID, and Intune.

.DESCRIPTION
    Invoke-M365EntraAudit audits six critical governance domains across cloud and hybrid tenants:
    1. Stale guest accounts (>60/90 days without interactive or non-interactive sign-in).
    2. High-privilege role assignments (Global Administrator, Security Administrator, Intune Administrator),
       evaluating permanent vs time-bound vs PIM-eligible (both active and inactive eligible) schedules
       and querying MFA registration status.
    3. Inactive licensed accounts (evaluating interactive, non-interactive, and lastSuccessfulSignInDateTime,
       using CreatedDateTime as the baseline for accounts that have never signed in, and resolving SKU names).
    4. Intune endpoint compliance posture and missing BitLocker encryption on Windows devices.
    5. Conditional Access policy posture (detecting disabled/report-only policies, scope coverage, and
       excessive or missing break-glass exclusions).
    6. OAuth application registrations and enterprise app permission grants (high-risk scopes and expiring secrets).

    Live execution requires an authenticated Microsoft Graph session (Connect-MgGraph) and stops
    with an explicit error if no session is active. For offline testing or CI pipelines without
    tenant credentials, pass the -DemoMode switch explicitly.
    All dates are strictly formatted in ISO 8601 UTC, and CSV exports sanitize formula-injection prefixes.

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

function Protect-CsvValue {
    <#
        Prevents CSV / Excel formula injection (CWE-1236) when untrusted directory fields
        (such as external guest DisplayName) begin with =, +, -, @, tab, or carriage return.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value -or ($Value -isnot [string])) {
        return $Value
    }

    $str = [string]$Value
    if ($str -match '^[=+\-@\t\r]' -and ($str -notmatch '^-\d+(\.\d+)?$')) {
        return "'$str"
    }
    return $str
}

function ConvertTo-SafeCsvRecord {
    [CmdletBinding()]
    [OutputType([object[]])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$InputObjects
    )

    $safeList = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($obj in $InputObjects) {
        if ($null -eq $obj) { continue }
        $ordered = [ordered]@{}
        foreach ($prop in $obj.PSObject.Properties) {
            $ordered[$prop.Name] = Protect-CsvValue -Value $prop.Value
        }
        $safeList.Add([PSCustomObject]$ordered)
    }
    return , $safeList.ToArray()
}

function Get-MostRecentSignInDateUtc {
    <#
        Evaluates all available Microsoft Graph SignInActivity timestamps:
        - LastSuccessfulSignInDateTime
        - LastSignInDateTime (interactive)
        - LastNonInteractiveSignInDateTime (token refresh / background apps)
        Returns the most recent [DateTime] in UTC, or $null if the user has never signed in.
    #>
    [CmdletBinding()]
    [OutputType([Nullable[DateTime]])]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$User
    )

    if (-not ($User.PSObject.Properties['SignInActivity'] -and $User.SignInActivity)) {
        return $null
    }

    $act = $User.SignInActivity
    $candidates = [System.Collections.Generic.List[DateTime]]::new()

    foreach ($propName in @('LastSuccessfulSignInDateTime', 'LastSignInDateTime', 'LastNonInteractiveSignInDateTime')) {
        if ($act.PSObject.Properties[$propName] -and $act.$propName) {
            $candidates.Add(([DateTime]$act.$propName).ToUniversalTime())
        }
    }

    if ($candidates.Count -eq 0) {
        return $null
    }

    return ($candidates | Sort-Object -Descending | Select-Object -First 1)
}

function Resolve-FriendlySkuName {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SkuIdentifier,

        [Parameter(Mandatory = $false)]
        [hashtable]$TenantSkuMap = @{}
    )

    $friendlyTable = @{
        'SPE_E5'            = 'Microsoft 365 E5'
        'SPE_E3'            = 'Microsoft 365 E3'
        'SPE_F1'            = 'Microsoft 365 F3'
        'ENTERPRISEPREMIUM' = 'Office 365 E5'
        'ENTERPRISEPACK'    = 'Office 365 E3'
        'AAD_PREMIUM_P2'    = 'Microsoft Entra ID P2'
        'AAD_PREMIUM'       = 'Microsoft Entra ID P1'
        'EMSPREMIUM'        = 'Enterprise Mobility + Security E5'
        'EMS'               = 'Enterprise Mobility + Security E3'
        'SPB'               = 'Microsoft 365 Business Premium'
    }

    $partNumber = if ($TenantSkuMap.ContainsKey($SkuIdentifier)) {
        [string]$TenantSkuMap[$SkuIdentifier]
    }
    else {
        $SkuIdentifier
    }

    if ($friendlyTable.ContainsKey($partNumber.ToUpperInvariant())) {
        return $friendlyTable[$partNumber.ToUpperInvariant()]
    }
    return $partNumber
}

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
            AssignmentType = "Eligible (Inactive)"
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
            PolicyName         = "CA01-Require-MFA-All-Users"
            State              = "enabled"
            IncludeUsersScope  = "All"
            ExcludedUsersCount = 2
            GrantControls      = "mfa"
            PostureRisk        = "None"
        },
        [PSCustomObject]@{
            PolicyName         = "CA04-Require-Compliant-Device-Finance"
            State              = "enabledForReportingButNotEnforced"
            IncludeUsersScope  = "Groups"
            ExcludedUsersCount = 0
            GrantControls      = "compliantDevice"
            PostureRisk        = "PolicyInReportOnlyMode"
        },
        [PSCustomObject]@{
            PolicyName         = "CA07-Block-Legacy-Authentication"
            State              = "disabled"
            IncludeUsersScope  = "All"
            ExcludedUsersCount = 0
            GrantControls      = "block"
            PostureRisk        = "PolicyDisabled"
        }
    )

    $appRegistrations = @(
        [PSCustomObject]@{
            AppDisplayName      = "Legacy-Mail-Sync-Connector"
            AppId               = "11111111-2222-3333-4444-555555555555"
            ConsentType         = "AllPrincipals (AdminConsent)"
            GrantedPermissions  = "Mail.ReadWrite; Mail.Send; User.Read.All"
            CredentialExpiryUtc = $nowUtc.AddDays(-12).ToString("o")
            DaysUntilExpiry     = -12
            GovernanceRisk      = "HighRiskOAuthPermissions; ExpiredClientSecret"
        },
        [PSCustomObject]@{
            AppDisplayName      = "HR-Onboarding-Automation"
            AppId               = "66666666-7777-8888-9999-000000000000"
            ConsentType         = "AllPrincipals (AdminConsent)"
            GrantedPermissions  = "Directory.ReadWrite.All"
            CredentialExpiryUtc = $nowUtc.AddDays(14).ToString("o")
            DaysUntilExpiry     = 14
            GovernanceRisk      = "HighRiskOAuthPermissions; CredentialExpiringSoon"
        }
    )

    return [PSCustomObject]@{
        StaleGuests        = $staleGuests
        PrivilegedRoles    = $privilegedRoles
        InactiveLicenses   = $inactiveLicenses
        EndpointCompliance = $endpointCompliance
        ConditionalAccess  = $conditionalAccess
        AppRegistrations   = $appRegistrations
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
        $lastSignIn = Get-MostRecentSignInDateUtc -User $user
        $createdUtc = if ($user.PSObject.Properties['CreatedDateTime'] -and $user.CreatedDateTime) { ([DateTime]$user.CreatedDateTime).ToUniversalTime() } else { $nowUtc }
        $referenceDate = if ($null -ne $lastSignIn) { $lastSignIn } else { $createdUtc }
        $daysInactive = [int][Math]::Floor(($nowUtc - $referenceDate).TotalDays)

        if ($daysInactive -ge $ThresholdDays) {
            $results.Add([PSCustomObject]@{
                UserPrincipalName     = $user.UserPrincipalName
                DisplayName           = $user.DisplayName
                AccountEnabled        = [bool]$user.AccountEnabled
                CreatedDateTimeUtc    = $createdUtc.ToString("o")
                LastSignInDateTimeUtc = if ($null -ne $lastSignIn) { $lastSignIn.ToString("o") } else { "NeverSignedIn" }
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

    # 1. Query real MFA registration telemetry
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

    # 2. Query PIM Eligibility and Assignment Schedules (Entra ID P2)
    $pimEligibleByKey = @{}
    $pimAssignmentByKey = @{}
    $pimTelemetryAvailable = $false

    if ((Get-Command -Name Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ErrorAction SilentlyContinue) -and
        (Get-Command -Name Get-MgRoleManagementDirectoryRoleAssignmentSchedule -ErrorAction SilentlyContinue)) {
        try {
            $eligSchedules = @(Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop)
            foreach ($s in $eligSchedules) {
                $key = "$($s.RoleDefinitionId):$($s.PrincipalId)"
                $pimEligibleByKey[$key] = $s
            }

            $assignSchedules = @(Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ErrorAction Stop)
            foreach ($a in $assignSchedules) {
                $key = "$($a.RoleDefinitionId):$($a.PrincipalId)"
                $pimAssignmentByKey[$key] = $a
            }
            $pimTelemetryAvailable = $true
        }
        catch {
            Write-Warning "Unable to query PIM role schedules (requires RoleManagement.Read.Directory and Entra ID P2): $_"
        }
    }

    $roles = @(Get-MgDirectoryRole -All -ErrorAction Stop | Where-Object { $_.DisplayName -in $targetRoles })
    foreach ($role in $roles) {
        $roleTemplateId = if ($role.PSObject.Properties['RoleTemplateId'] -and $role.RoleTemplateId) { [string]$role.RoleTemplateId } else { [string]$role.Id }
        $activeMembers = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop)

        # Build a combined dictionary of principals for this role: active members + inactive PIM-eligible principals
        $principalsById = [ordered]@{}
        foreach ($m in $activeMembers) {
            $principalsById[[string]$m.Id] = [PSCustomObject]@{
                MemberObject = $m
                IsActiveNow  = $true
            }
        }

        if ($pimTelemetryAvailable) {
            foreach ($eligKey in $pimEligibleByKey.Keys) {
                $eligObj = $pimEligibleByKey[$eligKey]
                if ([string]$eligObj.RoleDefinitionId -eq $roleTemplateId) {
                    $pId = [string]$eligObj.PrincipalId
                    if (-not $principalsById.Contains($pId)) {
                        $synthProps = if ($eligObj.PSObject.Properties['Principal'] -and $eligObj.Principal -and $eligObj.Principal.PSObject.Properties['AdditionalProperties']) {
                            $eligObj.Principal.AdditionalProperties
                        }
                        elseif ($eligObj.PSObject.Properties['PrincipalPrincipalName'] -and $eligObj.PrincipalPrincipalName) {
                            @{ '@odata.type' = '#microsoft.graph.user'; 'userPrincipalName' = [string]$eligObj.PrincipalPrincipalName }
                        }
                        else {
                            @{ '@odata.type' = '#microsoft.graph.user'; 'userPrincipalName' = $pId }
                        }
                        $principalsById[$pId] = [PSCustomObject]@{
                            MemberObject = [PSCustomObject]@{ Id = $pId; AdditionalProperties = $synthProps }
                            IsActiveNow  = $false
                        }
                    }
                }
            }
        }

        foreach ($pId in $principalsById.Keys) {
            $entryInfo = $principalsById[$pId]
            $member = $entryInfo.MemberObject
            $isActiveNow = [bool]$entryInfo.IsActiveNow

            $addProps = if ($member.PSObject.Properties['AdditionalProperties'] -and $member.AdditionalProperties) { $member.AdditionalProperties } else { @{} }
            $odataType = if ($addProps.ContainsKey('@odata.type')) { $addProps['@odata.type'] } else { '#microsoft.graph.user' }

            $principalName = if ($addProps.ContainsKey('userPrincipalName')) {
                [string]$addProps['userPrincipalName']
            }
            elseif ($addProps.ContainsKey('displayName')) {
                [string]$addProps['displayName']
            }
            else {
                [string]$member.Id
            }

            $principalType = switch ($odataType) {
                '#microsoft.graph.servicePrincipal' { "ServicePrincipal" }
                '#microsoft.graph.group'            { "Group" }
                default                             { "User" }
            }

            $scheduleKey = "${roleTemplateId}:${pId}"

            $assignmentType = "Unknown"
            $isPimEligible = "Unknown"
            if ($pimTelemetryAvailable) {
                $isEligible = $pimEligibleByKey.ContainsKey($scheduleKey)
                $assignObj = if ($pimAssignmentByKey.ContainsKey($scheduleKey)) { $pimAssignmentByKey[$scheduleKey] } else { $null }

                $hasEndDate = $false
                if ($null -ne $assignObj) {
                    if ($assignObj.PSObject.Properties['EndDateTime'] -and $null -ne $assignObj.EndDateTime) {
                        $hasEndDate = $true
                    }
                    elseif ($assignObj.PSObject.Properties['ScheduleInfo'] -and $assignObj.ScheduleInfo -and
                            $assignObj.ScheduleInfo.PSObject.Properties['Expiration'] -and $assignObj.ScheduleInfo.Expiration -and
                            $null -ne $assignObj.ScheduleInfo.Expiration.EndDateTime) {
                        $hasEndDate = $true
                    }
                }

                if ($isEligible) {
                    $isPimEligible = $true
                    $assignmentType = if ($isActiveNow) { "Eligible (Active)" } else { "Eligible (Inactive)" }
                }
                elseif ($hasEndDate) {
                    $isPimEligible = $false
                    $assignmentType = "TimeBoundAssigned"
                }
                else {
                    $isPimEligible = $false
                    $assignmentType = "Permanent"
                }
            }

            $mfaStatus = "Unknown"
            if ($principalType -eq "ServicePrincipal") {
                $mfaStatus = "N/A (ServicePrincipal)"
            }
            elseif ($principalType -eq "Group") {
                $mfaStatus = "N/A (Group)"
            }
            elseif ($mfaTelemetryAvailable) {
                $upnKey = $principalName.ToLowerInvariant()
                $idKey = $pId.ToLowerInvariant()
                if ($mfaLookup.ContainsKey($upnKey)) {
                    $mfaStatus = $mfaLookup[$upnKey]
                }
                elseif ($mfaLookup.ContainsKey($idKey)) {
                    $mfaStatus = $mfaLookup[$idKey]
                }
            }

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

    $skuMap = @{}
    if (Get-Command -Name Get-MgSubscribedSku -ErrorAction SilentlyContinue) {
        try {
            $skus = @(Get-MgSubscribedSku -All -ErrorAction Stop)
            foreach ($s in $skus) {
                if ($s.SkuId -and $s.SkuPartNumber) {
                    $skuMap[[string]$s.SkuId] = [string]$s.SkuPartNumber
                }
            }
        }
        catch {
            Write-Verbose "Unable to query SubscribedSkus: $_"
        }
    }

    $users = Get-MgUser -Filter "userType eq 'Member'" -Property Id, UserPrincipalName, DisplayName, AccountEnabled, CreatedDateTime, AssignedLicenses, SignInActivity -All -ErrorAction Stop
    foreach ($u in $users) {
        $licenseCount = @($u.AssignedLicenses).Count
        if ($licenseCount -eq 0) { continue }

        $lastSignIn = Get-MostRecentSignInDateUtc -User $u
        $createdUtc = if ($u.PSObject.Properties['CreatedDateTime'] -and $u.CreatedDateTime) {
            ([DateTime]$u.CreatedDateTime).ToUniversalTime()
        }
        else {
            $nowUtc.AddDays(-($ThresholdDays + 1))
        }

        # Use CreatedDateTime as the baseline when the user has never signed in,
        # preventing newly provisioned employees from being flagged as ReclaimableLicense on day 1.
        $referenceDate = if ($null -ne $lastSignIn) { $lastSignIn } else { $createdUtc }
        $daysInactive = [int][Math]::Floor(($nowUtc - $referenceDate).TotalDays)

        $resolvedSkus = foreach ($lic in @($u.AssignedLicenses)) {
            Resolve-FriendlySkuName -SkuIdentifier ([string]$lic.SkuId) -TenantSkuMap $skuMap
        }
        $skuList = ($resolvedSkus) -join "; "

        if (-not $u.AccountEnabled) {
            $results.Add([PSCustomObject]@{
                UserPrincipalName     = $u.UserPrincipalName
                DisplayName           = $u.DisplayName
                AccountEnabled        = $false
                AssignedLicenses      = $skuList
                LastSignInDateTimeUtc = if ($null -ne $lastSignIn) { $lastSignIn.ToString("o") } else { "NeverSignedIn" }
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
                LastSignInDateTimeUtc = if ($null -ne $lastSignIn) { $lastSignIn.ToString("o") } else { "NeverSignedIn" }
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

        $includeUsers = @()
        $excludeUsers = @()
        $excludeGroups = @()
        if ($pol.PSObject.Properties['Conditions'] -and $pol.Conditions -and
            $pol.Conditions.PSObject.Properties['Users'] -and $pol.Conditions.Users) {
            $uCond = $pol.Conditions.Users
            if ($uCond.PSObject.Properties['IncludeUsers'] -and $uCond.IncludeUsers) {
                $includeUsers = @($uCond.IncludeUsers)
            }
            if ($uCond.PSObject.Properties['ExcludeUsers'] -and $uCond.ExcludeUsers) {
                $excludeUsers = @($uCond.ExcludeUsers)
            }
            if ($uCond.PSObject.Properties['ExcludeGroups'] -and $uCond.ExcludeGroups) {
                $excludeGroups = @($uCond.ExcludeGroups)
            }
        }

        $scopeLabel = if ('All' -in $includeUsers) { 'All' } elseif ($includeUsers.Count -gt 0) { 'SpecificUsers' } else { 'GroupsOrRoles' }
        $excludedCount = $excludeUsers.Count + $excludeGroups.Count

        $risks = [System.Collections.Generic.List[string]]::new()
        switch ($pol.State) {
            "disabled"                          { $risks.Add("PolicyDisabled") }
            "enabledForReportingButNotEnforced" { $risks.Add("PolicyInReportOnlyMode") }
        }

        if ($pol.State -eq "enabled") {
            if ($scopeLabel -eq 'All' -and $excludedCount -eq 0) {
                $risks.Add("NoBreakGlassExclusionConfigured")
            }
            elseif ($excludeUsers.Count -gt 5) {
                $risks.Add("ExcessiveDirectUserExclusions($($excludeUsers.Count))")
            }
        }

        $results.Add([PSCustomObject]@{
            PolicyName         = $pol.DisplayName
            State              = [string]$pol.State
            IncludeUsersScope  = $scopeLabel
            ExcludedUsersCount = $excludedCount
            GrantControls      = $controls
            PostureRisk        = if ($risks.Count -gt 0) { $risks -join "; " } else { "None" }
        })
    }

    return , $results.ToArray()
}

function Get-LiveAppConsentAndSecret {
    [CmdletBinding()]
    [OutputType([object[]])]
    param (
        [Parameter(Mandatory = $false)]
        [int]$ExpiryWarningDays = 30
    )

    $results = [System.Collections.Generic.List[PSObject]]::new()
    $nowUtc = [DateTime]::UtcNow
    $highRiskScopes = @('Mail.ReadWrite', 'Mail.Send', 'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Files.ReadWrite.All', 'full_access_as_app')

    $grantsByClient = @{}
    if (Get-Command -Name Get-MgOauth2PermissionGrant -ErrorAction SilentlyContinue) {
        try {
            $grants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop
            foreach ($g in $grants) {
                $clientId = [string]$g.ClientId
                if (-not $grantsByClient.ContainsKey($clientId)) {
                    $grantsByClient[$clientId] = [System.Collections.Generic.List[PSObject]]::new()
                }
                $grantsByClient[$clientId].Add($g)
            }
        }
        catch {
            Write-Warning "Unable to query OAuth2 permission grants: $_"
        }
    }

    $spIdByAppId = @{}
    if (Get-Command -Name Get-MgServicePrincipal -ErrorAction SilentlyContinue) {
        try {
            $sps = Get-MgServicePrincipal -All -ErrorAction Stop
            foreach ($sp in $sps) {
                if ($sp.AppId -and $sp.Id) {
                    $spIdByAppId[[string]$sp.AppId] = [string]$sp.Id
                }
            }
        }
        catch {
            Write-Warning "Unable to query Service Principals: $_"
        }
    }

    $apps = @(Get-MgApplication -All -ErrorAction Stop)
    foreach ($app in $apps) {
        $risks = [System.Collections.Generic.List[string]]::new()
        $grantedScopes = [System.Collections.Generic.List[string]]::new()
        $consentType = "None"

        $resolvedSpId = if ($spIdByAppId.ContainsKey([string]$app.AppId)) {
            $spIdByAppId[[string]$app.AppId]
        }
        elseif ($app.PSObject.Properties['ServicePrincipalId'] -and $app.ServicePrincipalId) {
            [string]$app.ServicePrincipalId
        }
        else {
            $null
        }

        if ($null -ne $resolvedSpId -and $grantsByClient.ContainsKey($resolvedSpId)) {
            foreach ($grant in $grantsByClient[$resolvedSpId]) {
                if ($grant.ConsentType -eq 'AllPrincipals') {
                    $consentType = "AllPrincipals (AdminConsent)"
                }
                elseif ($consentType -eq "None") {
                    $consentType = [string]$grant.ConsentType
                }

                $scopes = ([string]$grant.Scope -split '\s+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                foreach ($s in $scopes) {
                    if (-not $grantedScopes.Contains($s)) {
                        $grantedScopes.Add($s)
                    }
                    if ($s -in $highRiskScopes -and (-not $risks.Contains("HighRiskOAuthPermissions"))) {
                        $risks.Add("HighRiskOAuthPermissions")
                    }
                }
            }
        }

        $earliestExpiry = $null
        $creds = @()
        if ($app.PSObject.Properties['PasswordCredentials'] -and $app.PasswordCredentials) {
            $creds += @($app.PasswordCredentials)
        }
        if ($app.PSObject.Properties['KeyCredentials'] -and $app.KeyCredentials) {
            $creds += @($app.KeyCredentials)
        }

        foreach ($cred in $creds) {
            if ($cred.EndDateTime) {
                $endUtc = ([DateTime]$cred.EndDateTime).ToUniversalTime()
                if ($null -eq $earliestExpiry -or $endUtc -lt $earliestExpiry) {
                    $earliestExpiry = $endUtc
                }
            }
        }

        $daysUntilExpiry = $null
        if ($null -ne $earliestExpiry) {
            $daysUntilExpiry = [int][Math]::Floor(($earliestExpiry - $nowUtc).TotalDays)
            if ($daysUntilExpiry -lt 0) {
                $risks.Add("ExpiredClientSecret")
            }
            elseif ($daysUntilExpiry -le $ExpiryWarningDays) {
                $risks.Add("CredentialExpiringSoon")
            }
        }

        if ($risks.Count -gt 0) {
            $results.Add([PSCustomObject]@{
                AppDisplayName      = $app.DisplayName
                AppId               = $app.AppId
                ConsentType         = $consentType
                GrantedPermissions  = if ($grantedScopes.Count -gt 0) { $grantedScopes -join "; " } else { "None" }
                CredentialExpiryUtc = if ($null -ne $earliestExpiry) { $earliestExpiry.ToString("o") } else { "NoCredentials" }
                DaysUntilExpiry     = if ($null -ne $daysUntilExpiry) { $daysUntilExpiry } else { "N/A" }
                GovernanceRisk      = $risks -join "; "
            })
        }
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
        AppRegistrations   = Get-LiveAppConsentAndSecret
    }
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
}

$summaryReport = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        ToolName              = "M365-Entra-Audit-Toolkit"
        ToolVersion           = "1.2.0"
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
        TotalHighRiskAppsFound       = @($auditResults.AppRegistrations).Count
    }
    StaleGuests        = $auditResults.StaleGuests
    PrivilegedRoles    = $auditResults.PrivilegedRoles
    InactiveLicenses   = $auditResults.InactiveLicenses
    EndpointCompliance = $auditResults.EndpointCompliance
    ConditionalAccess  = $auditResults.ConditionalAccess
    AppRegistrations   = $auditResults.AppRegistrations
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
    (ConvertTo-SafeCsvRecord -InputObjects @($auditResults.StaleGuests)) | Export-Csv -Path (Join-Path $OutputDirectory "StaleGuests_${timestampFileStr}.csv") -NoTypeInformation -Encoding UTF8
    (ConvertTo-SafeCsvRecord -InputObjects @($auditResults.PrivilegedRoles)) | Export-Csv -Path (Join-Path $OutputDirectory "PrivilegedRoles_${timestampFileStr}.csv") -NoTypeInformation -Encoding UTF8
    (ConvertTo-SafeCsvRecord -InputObjects @($auditResults.InactiveLicenses)) | Export-Csv -Path (Join-Path $OutputDirectory "InactiveLicenses_${timestampFileStr}.csv") -NoTypeInformation -Encoding UTF8
    (ConvertTo-SafeCsvRecord -InputObjects @($auditResults.EndpointCompliance)) | Export-Csv -Path (Join-Path $OutputDirectory "EndpointCompliance_${timestampFileStr}.csv") -NoTypeInformation -Encoding UTF8
    (ConvertTo-SafeCsvRecord -InputObjects @($auditResults.ConditionalAccess)) | Export-Csv -Path (Join-Path $OutputDirectory "ConditionalAccess_${timestampFileStr}.csv") -NoTypeInformation -Encoding UTF8
    (ConvertTo-SafeCsvRecord -InputObjects @($auditResults.AppRegistrations)) | Export-Csv -Path (Join-Path $OutputDirectory "AppRegistrations_${timestampFileStr}.csv") -NoTypeInformation -Encoding UTF8
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
    HighRiskAppCount         = $summaryReport.Summary.TotalHighRiskAppsFound
}

<#
.SYNOPSIS
    Deploys the Azure Automation infrastructure that keeps a security group reconciled
    against current Entra ID users who have a qualifying MFA method registered.

.DESCRIPTION
    Idempotent deploy script. On each run it will:

      1. Create the resource group (if missing) and an Automation Account with a
         system-assigned managed identity (if missing).
      2. Import the Microsoft Graph PowerShell modules required by the runbook into the
         Automation Account's PowerShell 7.2 runtime, waiting for each to finish importing.
      3. Import and publish runbooks/Sync-MfaRegisteredGroup.ps1 as a PowerShell 7.2 runbook.
      4. Create the target security group (unless -TargetGroupId is supplied for an existing
         group).
      5. Grant the managed identity's service principal the minimum Microsoft Graph
         application permissions the runbook needs:
           - User.Read.All                     (enumerate/resolve in-scope users)
           - UserAuthenticationMethod.Read.All (read registered authentication methods)
           - GroupMember.ReadWrite.All         (reconcile target group membership)
      6. Create a recurring schedule and link it to the runbook with its parameters.

    Run this in a session already authenticated to Azure (Connect-AzAccount) with rights to
    create resources and assign roles, and be prepared to interactively consent to the Graph
    application permissions above - none of them are on Microsoft's privileged-permission
    list, so Application Administrator or Cloud Application Administrator should be enough to
    consent (Global Administrator / Privileged Role Administrator also works if that consent
    is unexpectedly denied).

    Deployment settings (subscription, tenant, resource group, automation account, target
    group, cadence, scope filters, qualifying methods) are read from a config file - see
    deploy.config.psd1 next to this script for the field list. Any value can be overridden on
    the command line; explicit parameters always win over the config file.

.PARAMETER ConfigFilePath
    Path to the .psd1 config file. Defaults to deploy.config.psd1 next to this script.

.PARAMETER SubscriptionId
    Azure subscription to deploy into. Overrides the config file's subscriptionId.

.PARAMETER ResourceGroupName
    Resource group for the Automation Account. Created if it does not exist. Overrides the
    config file's resourceGroupName.

.PARAMETER Location
    Azure region for the resource group / Automation Account. Overrides the config file's
    location.

.PARAMETER AutomationAccountName
    Name of the Automation Account. Created if it does not exist. Overrides the config file's
    automationAccountName.

.PARAMETER RunbookFilePath
    Path to the runbook script. Defaults to ..\runbooks\Sync-MfaRegisteredGroup.ps1 relative
    to this script.

.PARAMETER TargetGroupId
    Object ID of an existing target group. If omitted (here and in the config file), a new
    cloud-only security group is created using -TargetGroupDisplayName.

.PARAMETER TargetGroupDisplayName
    Display name for the target group when a new one is created. Overrides the config file's
    targetGroupDisplayName.

.PARAMETER ExcludeGuests
    Passed through to the runbook's -ExcludeGuests parameter on the schedule. Overrides the
    config file's excludeGuests.

.PARAMETER ExcludeDisabledAccounts
    Passed through to the runbook's -ExcludeDisabledAccounts parameter on the schedule.
    Overrides the config file's excludeDisabledAccounts.

.PARAMETER MfaQualifyingMethodTypes
    Passed through to the runbook's -QualifyingMethodTypes parameter on the schedule.
    Overrides the config file's mfaQualifyingMethodTypes. Leave blank/unset to let the
    runbook fall back to its environment variable / built-in default - see
    runbooks/README.md.

.PARAMETER ScheduleStartTime
    First run time for the schedule. Defaults to the next top of hour, at least 10 minutes
    from now. Subsequent runs occur every -CadenceDays days.

.PARAMETER CadenceDays
    Days between scheduled runs. Overrides the config file's cadenceDays (default: 1, daily).

.PARAMETER TenantId
    Tenant ID to connect Microsoft Graph to. Overrides the config file's tenantId; if both are
    blank, defaults to the tenant of the current Az context.

.EXAMPLE
    # Uses every value from deploy.config.psd1
    .\Deploy-MfaRegisteredSyncAutomation.ps1

.EXAMPLE
    # Config file supplies the rest; override just the subscription for a test deploy
    .\Deploy-MfaRegisteredSyncAutomation.ps1 -SubscriptionId '00000000-0000-0000-0000-000000000000'
#>

[CmdletBinding()]
param(
    [string]$ConfigFilePath = (Join-Path $PSScriptRoot 'deploy.config.psd1'),

    [string]$SubscriptionId,
    [string]$TenantId,
    [string]$ResourceGroupName,
    [string]$Location,
    [string]$AutomationAccountName,

    [string]$RunbookFilePath = (Join-Path $PSScriptRoot '..\runbooks\Sync-MfaRegisteredGroup.ps1'),
    [string]$RunbookName = 'Sync-MfaRegisteredGroup',

    [string]$TargetGroupId,
    [string]$TargetGroupDisplayName,

    [Nullable[bool]]$ExcludeGuests,
    [Nullable[bool]]$ExcludeDisabledAccounts,
    [string]$MfaQualifyingMethodTypes,

    [string]$ScheduleName = 'Daily-MfaRegisteredGroupSync',
    [datetime]$ScheduleStartTime = (Get-Date).Date.AddHours([Math]::Ceiling(((Get-Date).AddMinutes(15) - (Get-Date).Date).TotalHours)),
    [Nullable[int]]$CadenceDays
)

$ErrorActionPreference = 'Stop'

$RequiredGraphModules = @(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Identity.SignIns'
    'Microsoft.Graph.Users'
    'Microsoft.Graph.Groups'
)

$RequiredGraphAppRoles = @(
    'User.Read.All'
    'UserAuthenticationMethod.Read.All'
    'GroupMember.ReadWrite.All'
)

$GraphResourceAppId = '00000003-0000-0000-c000-000000000000'

# --- Load config file and resolve effective parameter values ------------

$config = @{}
if (Test-Path $ConfigFilePath) {
    Write-Host "Loading configuration from $ConfigFilePath..."
    $config = Import-PowerShellDataFile -Path $ConfigFilePath
}
else {
    Write-Host "No config file found at $ConfigFilePath; relying entirely on explicit parameters."
}

function Resolve-ConfigValue {
    param($ExplicitValue, $ConfigValue, $Default = $null)
    if ($null -ne $ExplicitValue -and $ExplicitValue -ne '') { return $ExplicitValue }
    if ($null -ne $ConfigValue -and $ConfigValue -ne '') { return $ConfigValue }
    return $Default
}

$SubscriptionId           = Resolve-ConfigValue $SubscriptionId $config.subscriptionId
$TenantId                 = Resolve-ConfigValue $TenantId $config.tenantId
$ResourceGroupName        = Resolve-ConfigValue $ResourceGroupName $config.resourceGroupName
$Location                 = Resolve-ConfigValue $Location $config.location
$AutomationAccountName    = Resolve-ConfigValue $AutomationAccountName $config.automationAccountName
$TargetGroupId            = Resolve-ConfigValue $TargetGroupId $config.targetGroupId
$TargetGroupDisplayName   = Resolve-ConfigValue $TargetGroupDisplayName $config.targetGroupDisplayName 'sg-MFA-Registered-Users'
$MfaQualifyingMethodTypes = Resolve-ConfigValue $MfaQualifyingMethodTypes $config.mfaQualifyingMethodTypes ''

if (-not $PSBoundParameters.ContainsKey('CadenceDays')) {
    $CadenceDays = if ($null -ne $config.cadenceDays) { [int]$config.cadenceDays } else { 1 }
}
if (-not $PSBoundParameters.ContainsKey('ExcludeGuests')) {
    $ExcludeGuests = if ($null -ne $config.excludeGuests) { [bool]$config.excludeGuests } else { $true }
}
if (-not $PSBoundParameters.ContainsKey('ExcludeDisabledAccounts')) {
    $ExcludeDisabledAccounts = if ($null -ne $config.excludeDisabledAccounts) { [bool]$config.excludeDisabledAccounts } else { $true }
}

foreach ($required in @('SubscriptionId', 'ResourceGroupName', 'Location', 'AutomationAccountName')) {
    if ([string]::IsNullOrEmpty((Get-Variable -Name $required -ValueOnly))) {
        throw "Missing required value '$required'. Set it in $ConfigFilePath or pass -$required."
    }
}

Write-Host '=== Resolved configuration ==='
Write-Host "  SubscriptionId            : $SubscriptionId"
Write-Host "  TenantId                  : $(if ($TenantId) { $TenantId } else { '<not set - will default to current Az context tenant>' })"
Write-Host "  ResourceGroupName         : $ResourceGroupName"
Write-Host "  Location                  : $Location"
Write-Host "  AutomationAccountName     : $AutomationAccountName"
Write-Host "  RunbookName               : $RunbookName"
Write-Host "  RunbookFilePath           : $RunbookFilePath"
Write-Host "  TargetGroupId             : $(if ($TargetGroupId) { $TargetGroupId } else { '<not set - a new group will be created>' })"
Write-Host "  TargetGroupDisplayName    : $TargetGroupDisplayName"
Write-Host "  CadenceDays               : $CadenceDays"
Write-Host "  ExcludeGuests             : $ExcludeGuests"
Write-Host "  ExcludeDisabledAccounts   : $ExcludeDisabledAccounts"
Write-Host "  MfaQualifyingMethodTypes  : $(if ($MfaQualifyingMethodTypes) { $MfaQualifyingMethodTypes } else { '<not set - runbook will use its environment variable / built-in default>' })"
Write-Host "  ScheduleName              : $ScheduleName"
Write-Host "  RequiredGraphModules      : $($RequiredGraphModules -join ', ')"
Write-Host '=============================='

function Get-AutomationModuleRecord {
    <#
        PowerShell 7.1/7.2 runbooks execute against a distinct "Runtime Environment"
        resource, not the classic account-wide module store - the two do not sync. The
        classic REST endpoint (modules/{name}) writes to the legacy store only; the
        -RuntimeVersion parameter on these Az.Automation cmdlets is what actually reaches
        the Runtime Environment a PowerShell72-type runbook runs in. Confirmed against this
        account: a module imported via the classic REST API showed provisioningState
        'Succeeded' in the classic store yet was invisible to the runbook and to the
        Runtime Environment's own package list in the portal.
    #>
    param([string]$ModuleName)
    try {
        return Get-AzAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
            -RuntimeVersion '7.2' -Name $ModuleName -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Wait-AutomationModuleImport {
    param([string]$ModuleName, [int]$TimeoutSeconds = 1200)

    $elapsed = 0
    while ($true) {
        $record = Get-AutomationModuleRecord -ModuleName $ModuleName
        $state = if ($record) { $record.ProvisioningState } else { 'Pending (not yet visible)' }
        Write-Host "  ...$ModuleName status: $state ($elapsed s elapsed, larger modules can take several minutes to extract)"

        if ($record) {
            if ($state -eq 'Succeeded') { return }
            if ($state -eq 'Failed') {
                throw "Import of module '$ModuleName' failed. Check the Automation Account's Runtime Environment package errors in the portal."
            }
        }

        if ($elapsed -ge $TimeoutSeconds) {
            throw "Timed out waiting for module '$ModuleName' to finish importing."
        }
        Start-Sleep -Seconds 15
        $elapsed += 15
    }
}

function Install-AutomationGraphModule {
    param([string]$ModuleName)

    $existing = Get-AutomationModuleRecord -ModuleName $ModuleName
    if ($existing -and $existing.ProvisioningState -eq 'Succeeded') {
        Write-Host "Module $ModuleName already imported (version $($existing.Version))."
        return
    }

    $version = (Find-Module -Name $ModuleName -Repository PSGallery -ErrorAction Stop).Version.ToString()
    $contentLink = "https://www.powershellgallery.com/api/v2/package/$ModuleName/$version"

    Write-Host "Importing module $ModuleName version $version into the PowerShell 7.2 Runtime Environment..."
    New-AzAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
        -Name $ModuleName -ContentLinkUri $contentLink -RuntimeVersion '7.2' | Out-Null

    Wait-AutomationModuleImport -ModuleName $ModuleName
    Write-Host "Module $ModuleName imported successfully."
}

function Wait-ManagedIdentityPrincipalId {
    param([int]$TimeoutSeconds = 300)

    $elapsed = 0
    while ($true) {
        $account = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
        if ($account -and $account.Identity -and $account.Identity.PrincipalId -match '.') {
            return $account.Identity.PrincipalId
        }
        if ($elapsed -ge $TimeoutSeconds) {
            throw "Timed out waiting for the Automation Account's system-assigned identity principalId to become available."
        }
        Write-Host "  ...waiting for managed identity principalId to populate ($elapsed s elapsed)..."
        Start-Sleep -Seconds 10
        $elapsed += 10
    }
}

function Import-PinnedGraphModules {
    <#
        Machines commonly end up with multiple installed versions of Microsoft.Graph.*
        modules (e.g. a stale 2.34.0 alongside a current 2.39.0). PowerShell's module
        auto-load can resolve different Graph sub-modules to different versions within the
        same session; once any version of Microsoft.Graph.Authentication's assembly is
        loaded, the CLR refuses to load a second, differently-versioned copy of the
        same-named assembly, which surfaces as "Assembly with same name is already loaded"
        from whichever cmdlet auto-loads second. Force every required module to the same,
        highest common installed version before any of them are used.
    #>
    param([string[]]$ModuleNames)

    $versionSets = foreach ($name in $ModuleNames) {
        $versions = @(Get-Module -ListAvailable -Name $name | Select-Object -ExpandProperty Version -Unique)
        if ($versions.Count -eq 0) {
            throw "Required local module '$name' is not installed. See README.md."
        }
        , $versions
    }

    $commonVersions = $versionSets[0]
    foreach ($set in $versionSets) {
        $commonVersions = @($commonVersions | Where-Object { $set -contains $_ })
    }
    $pinnedVersion = $commonVersions | Sort-Object -Descending | Select-Object -First 1

    if (-not $pinnedVersion) {
        throw "No single installed version is common to: $($ModuleNames -join ', '). Reinstall the Microsoft.Graph PowerShell modules as a matched set, e.g.:`n  Get-InstalledModule Microsoft.Graph.* | Uninstall-Module -Force`n  Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Applications -Scope CurrentUser -Force"
    }

    foreach ($name in $ModuleNames) {
        Get-Module -Name $name | Remove-Module -Force -ErrorAction SilentlyContinue
        try {
            Import-Module -Name $name -RequiredVersion $pinnedVersion -Force -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message -match 'Assembly with same name is already loaded') {
                throw "A different version of a Microsoft.Graph assembly is already loaded in this PowerShell session (from an earlier command or a previous run of this script) and can't be swapped out at runtime - Remove-Module only removes the PowerShell wrapper, not the underlying .NET assembly. Close this terminal/PowerShell window, open a brand new one, and re-run this script there."
            }
            throw
        }
    }

    Write-Host "Pinned local Microsoft.Graph modules to version $pinnedVersion : $($ModuleNames -join ', ')"
}

# --- Azure context -----------------------------------------------------

Write-Host "Setting Azure context to subscription $SubscriptionId..."
$null = Set-AzContext -SubscriptionId $SubscriptionId

if (-not $TenantId) {
    $TenantId = (Get-AzContext).Tenant.Id
}

# --- Resource group -----------------------------------------------------

$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    Write-Host "Creating resource group $ResourceGroupName in $Location..."
    $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
}
else {
    Write-Host "Resource group $ResourceGroupName already exists."
}

# --- Automation account with system-assigned managed identity -----------

$account = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
if (-not $account) {
    Write-Host "Creating Automation Account $AutomationAccountName..."
    $account = New-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -Location $Location -AssignSystemIdentity
}
else {
    Write-Host "Automation Account $AutomationAccountName already exists."
    if (-not $account.Identity -or $account.Identity.PrincipalId -notmatch '.') {
        Write-Host "Enabling system-assigned managed identity..."
        $account = Set-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -AssignSystemIdentity
    }
}

Write-Host "Waiting for the managed identity's principalId to be assigned..."
$miPrincipalId = Wait-ManagedIdentityPrincipalId
Write-Host "Managed identity principal ID: $miPrincipalId"

# --- Import required Graph modules into the PowerShell 7.2 Runtime Environment ----

foreach ($moduleName in $RequiredGraphModules) {
    Install-AutomationGraphModule -ModuleName $moduleName
}

# --- Import and publish the runbook --------------------------------------

Write-Host "Importing runbook $RunbookName from $RunbookFilePath..."
Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
    -Name $RunbookName -Path $RunbookFilePath -Type PowerShell72 -Force | Out-Null

Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $RunbookName | Out-Null
Write-Host "Runbook $RunbookName imported and published."

# --- Connect to Microsoft Graph for group + permission setup ------------

Import-PinnedGraphModules -ModuleNames @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Applications')

Write-Host "Connecting to Microsoft Graph (tenant $TenantId)..."
Connect-MgGraph -TenantId $TenantId -Scopes 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All', 'Group.ReadWrite.All' -NoWelcome

# --- Target group ------------------------------------------------------

if (-not $TargetGroupId) {
    $existingGroup = Get-MgGroup -Filter "displayName eq '$TargetGroupDisplayName'" -ErrorAction SilentlyContinue
    if ($existingGroup) {
        Write-Host "Target group '$TargetGroupDisplayName' already exists ($($existingGroup.Id)); reusing it."
        $TargetGroupId = $existingGroup.Id
    }
    else {
        Write-Host "Creating target group '$TargetGroupDisplayName'..."
        $mailNickname = ($TargetGroupDisplayName -replace '[^a-zA-Z0-9]', '')
        $newGroup = New-MgGroup -DisplayName $TargetGroupDisplayName -MailEnabled:$false -MailNickname $mailNickname `
            -SecurityEnabled:$true -Description 'Group of users who currently have a qualifying MFA method registered. Membership is fully managed by the Sync-MfaRegisteredGroup automation runbook - do not add or remove members manually.'
        $TargetGroupId = $newGroup.Id
    }
}
else {
    Write-Host "Using existing target group $TargetGroupId."
}
Write-Host "Target group ID: $TargetGroupId"

# --- Grant Graph application permissions to the managed identity --------

$miServicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $miPrincipalId
$graphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$GraphResourceAppId'"
$existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $miServicePrincipal.Id -All

foreach ($roleValue in $RequiredGraphAppRoles) {
    $appRole = $graphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $roleValue -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $appRole) {
        throw "Could not find application app role '$roleValue' on the Microsoft Graph service principal."
    }

    $alreadyAssigned = $existingAssignments | Where-Object { $_.AppRoleId -eq $appRole.Id -and $_.ResourceId -eq $graphServicePrincipal.Id }
    if ($alreadyAssigned) {
        Write-Host "Permission $roleValue already granted to the managed identity."
        continue
    }

    Write-Host "Granting $roleValue to the managed identity..."
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $miServicePrincipal.Id -PrincipalId $miServicePrincipal.Id `
        -ResourceId $graphServicePrincipal.Id -AppRoleId $appRole.Id | Out-Null
}

# --- Schedule and link to the runbook ------------------------------------

$schedule = Get-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ScheduleName -ErrorAction SilentlyContinue
if (-not $schedule) {
    Write-Host "Creating schedule $ScheduleName starting $ScheduleStartTime, every $CadenceDays day(s)..."
    $schedule = New-AzAutomationSchedule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
        -Name $ScheduleName -StartTime $ScheduleStartTime -DayInterval $CadenceDays
}
else {
    Write-Host "Schedule $ScheduleName already exists."
}

$linked = Get-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName $RunbookName -ErrorAction SilentlyContinue |
    Where-Object { $_.ScheduleName -eq $ScheduleName }
if (-not $linked) {
    Write-Host "Linking schedule $ScheduleName to runbook $RunbookName..."
    $scheduleParameters = @{
        TargetGroupId           = $TargetGroupId
        ExcludeGuests           = $ExcludeGuests
        ExcludeDisabledAccounts = $ExcludeDisabledAccounts
        WhatIfMode              = $false
    }
    if ($MfaQualifyingMethodTypes) {
        $scheduleParameters['QualifyingMethodTypes'] = $MfaQualifyingMethodTypes
    }
    Register-AzAutomationScheduledRunbook -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName `
        -RunbookName $RunbookName -ScheduleName $ScheduleName -Parameters $scheduleParameters | Out-Null
}
else {
    Write-Host "Schedule $ScheduleName is already linked to runbook $RunbookName."
}

Write-Host ""
Write-Host "Deployment complete."
Write-Host "  Automation Account : $AutomationAccountName (resource group $ResourceGroupName)"
Write-Host "  Managed identity   : $miPrincipalId"
Write-Host "  Runbook            : $RunbookName (PowerShell 7.2)"
Write-Host "  Target group       : $TargetGroupId ($TargetGroupDisplayName)"
Write-Host "  Schedule           : $ScheduleName, every $CadenceDays day(s) starting $ScheduleStartTime"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  - Reference target group $TargetGroupId wherever you need to identify/target users with a qualifying MFA method registered."
Write-Host "  - Consider running the runbook once manually (Start-AzAutomationRunbook, or portal Test pane with WhatIfMode=true) to validate before its first scheduled run."

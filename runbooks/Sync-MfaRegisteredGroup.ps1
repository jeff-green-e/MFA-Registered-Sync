<#
.SYNOPSIS
    Reconciles a security group so its membership exactly matches the set of Entra ID users
    who currently have at least one qualifying MFA authentication method registered.

.DESCRIPTION
    Runs as an Azure Automation PowerShell 7.2 runbook under a system-assigned managed
    identity. On each run it:

      1. Enumerates users in scope (all users by default; guests and/or disabled accounts can
         be excluded from scope via parameters).
      2. Resolves which authentication method types "count" as MFA for this run - see
         "Configuring qualifying methods" below.
      3. For each in-scope user, checks their registered authentication methods for at least
         one qualifying type.
      4. Computes the desired group membership: every in-scope user who has a qualifying
         method. A user whose method lookup fails is left exactly as they are (not added, not
         removed) rather than guessed at - see the fail-safe note below.
      5. Adds/removes members of $TargetGroupId so its membership exactly matches the desired
         set - the group is expected to be dedicated solely to this automation.

    Before step 5 ever touches group membership, three circuit breakers can stop the run
    with no changes applied at all: zero in-scope users resolved, an abnormally high rate of
    per-user authentication-method lookup failures, or a proposed membership swing that's
    large relative to the group's current size. Each exists because a *systemic* failure
    (a missing module/cmdlet, a revoked permission, a Graph outage) fails every user the
    same way it just failed one - and letting that flow through as "nobody/everybody
    qualifies" would silently misconfigure the group instead of just misjudging one person.

    Fail-safe direction for this runbook is "leave unchanged", not "assume compliant" or
    "assume non-compliant": a lookup failure means we genuinely don't know whether the user
    has a qualifying method, so the safest action is to not change their membership status
    at all this run - they'll be re-evaluated on the next one. This differs from a stricter
    fail-closed/fail-open choice because this group has no inherent "safe default" direction
    (unlike, say, a Conditional Access exclusion, where staying excluded avoids a lockout) -
    it's a plain reporting/targeting group of who has MFA registered, so avoiding churn from
    a transient error matters more than guessing.

.PARAMETER TargetGroupId
    Object ID of the dedicated, cloud-only security group that should contain every in-scope
    user with a qualifying MFA method. Membership of this group is fully reconciled by this
    runbook on every run - do not add/remove members manually.

.PARAMETER QualifyingMethodTypes
    Comma-separated list of authentication method keys that qualify as "MFA registered" for
    this run. Explicit parameter value wins over everything else - see "Configuring
    qualifying methods" below. Valid keys: fido2, windowsHelloForBusiness,
    microsoftAuthenticator, softwareOath, hardwareOath, phone, x509Certificate,
    platformCredential, temporaryAccessPass, email, password.

.PARAMETER ExcludeGuests
    When $true (default), users with userType 'Guest' are excluded from scope - a B2B guest's
    authentication methods are registered and enforced in their home tenant, not this one.

.PARAMETER ExcludeDisabledAccounts
    When $true (default), users with accountEnabled = $false are excluded from scope.

.PARAMETER WhatIfMode
    When $true, computes and logs the add/remove plan but makes no changes to group
    membership. Useful for a manual dry-run job.

.PARAMETER MaxAuthLookupFailureRate
    Circuit breaker. If the fraction of in-scope users whose authentication methods couldn't
    be read exceeds this (default 0.2 = 20%), the run stops before touching the group -
    that failure pattern means something's broken (missing module, permission, throttling),
    not that a fifth of users are individually unlucky.

.PARAMETER MaxMembershipChangeRatio
    Circuit breaker. If the target group already has members, a run that would add and/or
    remove more than this fraction of its current size (default 0.3 = 30%, floored at
    -MinMembershipChangeFloor) stops before applying anything. Does not apply when the group
    is currently empty, since populating it from scratch on the first run is expected to
    touch everyone.

.PARAMETER MinMembershipChangeFloor
    Minimum number of changes always allowed through -MaxMembershipChangeRatio regardless of
    how small the current group is (default 5), so routine day-to-day churn on a small group
    isn't blocked by the ratio math.

.NOTES
    Configuring qualifying methods - checked in this order, first one found wins:

      1. -QualifyingMethodTypes parameter (e.g. set on the schedule that triggers this
         runbook). Works reliably in the Azure Automation cloud sandbox.
      2. The $env:MFA_QUALIFYING_METHOD_TYPES environment variable. Azure Automation's cloud
         sandbox does not currently support setting persistent custom environment variables
         for a job, so this only takes effect when the runbook executes somewhere that
         genuinely has that variable set in its process environment - a Hybrid Runbook
         Worker (a host you control, where you can set a machine-level environment variable)
         or a local test run. If you're running purely in the cloud sandbox, use the
         -QualifyingMethodTypes parameter (via the schedule, see deploy.config.psd1's
         mfaQualifyingMethodTypes) instead.
      3. A built-in default (see $DefaultQualifyingMethodKeys below).
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$TargetGroupId,

    [string]$QualifyingMethodTypes,

    [bool]$ExcludeGuests = $true,

    [bool]$ExcludeDisabledAccounts = $true,

    [bool]$WhatIfMode = $false,

    [double]$MaxAuthLookupFailureRate = 0.2,

    [double]$MaxMembershipChangeRatio = 0.3,

    [int]$MinMembershipChangeFloor = 5
)

$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$QualifyingMethodEnvVarName = 'MFA_QUALIFYING_METHOD_TYPES'

$DefaultQualifyingMethodKeys = @(
    'fido2'
    'windowsHelloForBusiness'
    'microsoftAuthenticator'
    'softwareOath'
    'hardwareOath'
    'phone'
    'x509Certificate'
    'platformCredential'
)

$MethodTypeKeyToOdataType = @{
    'fido2'                   = '#microsoft.graph.fido2AuthenticationMethod'
    'windowsHelloForBusiness' = '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
    'microsoftAuthenticator'  = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'
    'softwareOath'            = '#microsoft.graph.softwareOathAuthenticationMethod'
    'hardwareOath'            = '#microsoft.graph.hardwareOathAuthenticationMethod'
    'phone'                   = '#microsoft.graph.phoneAuthenticationMethod'
    'x509Certificate'         = '#microsoft.graph.x509CertificateAuthenticationMethod'
    'platformCredential'      = '#microsoft.graph.platformCredentialAuthenticationMethod'
    'temporaryAccessPass'     = '#microsoft.graph.temporaryAccessPassAuthenticationMethod'
    'email'                   = '#microsoft.graph.emailAuthenticationMethod'
    'password'                = '#microsoft.graph.passwordAuthenticationMethod'
}

$Script:RunbookLogBuffer = [System.Collections.Generic.List[string]]::new()

function Write-RunbookLog {
    <#
        Write-Information has proven unreliable in the portal for PowerShell 7.2 Runtime
        Environment jobs (see runbooks/README.md). Write-Output is the one channel confirmed
        to reliably show up under the job's Output tab - but this function is called from
        inside helper functions that return real data (hashtables, objects), and ANY
        unsuppressed pipeline output inside a PowerShell function becomes part of that
        function's return value. Calling Write-Output here directly previously corrupted a
        helper's hashtable return into a mixed array. So: buffer instead (List<T>.Add()
        returns void - no pipeline output, safe to call from anywhere), and only the
        top-level Main section (via Show-RunbookLog) actually emits the buffer through
        Write-Output, where there's no return value to corrupt.
    #>
    param([string]$Message)
    Write-Information $Message
    $Script:RunbookLogBuffer.Add($Message)
}

function Show-RunbookLog {
    <#
        Flushes buffered Write-RunbookLog messages to Write-Output. Only ever call this from
        the top-level Main section, never from inside a function whose return value matters.
    #>
    foreach ($line in $Script:RunbookLogBuffer) {
        Write-Output "[STEP] $line"
    }
    $Script:RunbookLogBuffer.Clear()
}

function Connect-Automation {
    Write-RunbookLog "Connecting to Microsoft Graph using the automation account's managed identity..."
    Connect-MgGraph -Identity -NoWelcome
    # Select-MgProfile only exists in Graph SDK v1.x; v2+ has no profile concept (v1.0 is
    # the only one). Guard rather than call directly - an unrecognized command isn't
    # suppressed by -ErrorAction and would crash the runbook under $ErrorActionPreference='Stop'.
    if (Get-Command Select-MgProfile -ErrorAction SilentlyContinue) {
        Select-MgProfile -Name 'v1.0' | Out-Null
    }
}

function Resolve-QualifyingMethodTypes {
    <#
        Returns a PSCustomObject { OdataTypes (HashSet[string]); Keys (string[]); Source
        (string) } describing which authentication method types count as "MFA registered"
        for this run. See the .NOTES section at the top of this file for precedence order.
    #>
    param([string]$ParamValue)

    $envValue = [System.Environment]::GetEnvironmentVariable($QualifyingMethodEnvVarName)

    $raw = $null
    $source = $null
    if ($ParamValue) {
        $raw = $ParamValue
        $source = '-QualifyingMethodTypes parameter'
    }
    elseif ($envValue) {
        $raw = $envValue
        $source = "environment variable `$env:$QualifyingMethodEnvVarName"
    }
    else {
        $raw = ($DefaultQualifyingMethodKeys -join ',')
        $source = 'built-in default (no parameter or environment variable set)'
    }

    $tokens = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    $odataTypes = [System.Collections.Generic.HashSet[string]]::new()
    $resolvedKeys = [System.Collections.Generic.List[string]]::new()
    $unknownTokens = [System.Collections.Generic.List[string]]::new()

    foreach ($token in $tokens) {
        $matchedKey = $MethodTypeKeyToOdataType.Keys | Where-Object { $_ -eq $token }
        if (-not $matchedKey) {
            $unknownTokens.Add($token)
            continue
        }
        [void]$odataTypes.Add($MethodTypeKeyToOdataType[$matchedKey])
        $resolvedKeys.Add($matchedKey)
    }

    if ($unknownTokens.Count -gt 0) {
        Write-Warning "Ignoring unrecognized qualifying method key(s): $($unknownTokens -join ', '). Valid keys: $($MethodTypeKeyToOdataType.Keys -join ', ')."
    }

    if ($odataTypes.Count -eq 0) {
        throw "STOP AND INVESTIGATE: no valid qualifying MFA method types resolved from $source (raw value: '$raw'). Valid keys: $($MethodTypeKeyToOdataType.Keys -join ', '). No changes were made."
    }

    return [PSCustomObject]@{
        OdataTypes = $odataTypes
        Keys       = @($resolvedKeys)
        Source     = $source
    }
}

function Get-FriendlyMethodName {
    param([string]$OdataType)
    $map = @{
        '#microsoft.graph.fido2AuthenticationMethod'                    = 'FIDO2 security key / passkey'
        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'  = 'Windows Hello for Business'
        '#microsoft.graph.x509CertificateAuthenticationMethod'          = 'Certificate-based authentication'
        '#microsoft.graph.platformCredentialAuthenticationMethod'       = 'Platform credential'
        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'   = 'Microsoft Authenticator'
        '#microsoft.graph.passwordAuthenticationMethod'                 = 'Password'
        '#microsoft.graph.phoneAuthenticationMethod'                    = 'Phone'
        '#microsoft.graph.softwareOathAuthenticationMethod'             = 'Software OATH token'
        '#microsoft.graph.hardwareOathAuthenticationMethod'             = 'Hardware OATH token'
        '#microsoft.graph.temporaryAccessPassAuthenticationMethod'      = 'Temporary Access Pass'
        '#microsoft.graph.emailAuthenticationMethod'                    = 'Email'
    }
    if ($map.ContainsKey($OdataType)) { return $map[$OdataType] }
    return ($OdataType -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', '')
}

function Get-InScopeUsers {
    <#
        Returns a hashtable of userId -> userPrincipalName for every user in scope, applying
        -ExcludeGuests / -ExcludeDisabledAccounts as server-side $filter clauses so the Graph
        call itself only returns what's needed.
    #>
    param([bool]$ExcludeGuests, [bool]$ExcludeDisabledAccounts)

    $filterClauses = [System.Collections.Generic.List[string]]::new()
    if ($ExcludeGuests) { $filterClauses.Add("userType eq 'Member'") }
    if ($ExcludeDisabledAccounts) { $filterClauses.Add('accountEnabled eq true') }
    $filter = if ($filterClauses.Count -gt 0) { $filterClauses -join ' and ' } else { $null }

    Write-RunbookLog "Enumerating in-scope users (ExcludeGuests=$ExcludeGuests, ExcludeDisabledAccounts=$ExcludeDisabledAccounts)..."
    $params = @{
        All      = $true
        Property = 'id,userPrincipalName'
    }
    if ($filter) { $params['Filter'] = $filter }

    $users = Get-MgUser @params -ErrorAction Stop
    $lookup = @{}
    foreach ($u in $users) { $lookup[$u.Id] = $u.UserPrincipalName }
    Write-RunbookLog "Found $($lookup.Count) in-scope user(s)."
    return $lookup
}

function Test-HasQualifyingMfaMethod {
    <#
        Returns a PSCustomObject { Status; Methods } rather than a bare boolean/null so
        callers can report exactly what a user has registered (or doesn't), not just whether
        they passed - that detail is what makes an ADD or REMOVE investigable.
    #>
    param([string]$UserId, [System.Collections.Generic.HashSet[string]]$QualifyingOdataTypes)

    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $UserId -All -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to read authentication methods for user $UserId : $($_.Exception.Message). Leaving this user's group membership unchanged this run (fail-safe)."
        return [PSCustomObject]@{ Status = $null; Methods = @() }
    }

    $methodNames = [System.Collections.Generic.List[string]]::new()
    $hasQualifying = $false
    foreach ($m in $methods) {
        $odataType = $m.AdditionalProperties['@odata.type']
        $methodNames.Add((Get-FriendlyMethodName -OdataType $odataType))
        if ($QualifyingOdataTypes.Contains($odataType)) {
            $hasQualifying = $true
        }
    }

    return [PSCustomObject]@{ Status = $hasQualifying; Methods = @($methodNames) }
}

# --- Main -------------------------------------------------------------

Write-RunbookLog "=== Starting MFA-registered group sync (TargetGroupId=$TargetGroupId, ExcludeGuests=$ExcludeGuests, ExcludeDisabledAccounts=$ExcludeDisabledAccounts, WhatIfMode=$WhatIfMode) ==="

Connect-Automation

$qualifying = Resolve-QualifyingMethodTypes -ParamValue $QualifyingMethodTypes
Write-RunbookLog "Qualifying MFA method types ($($qualifying.Source)): $($qualifying.Keys -join ', ')"

$upnLookup = Get-InScopeUsers -ExcludeGuests $ExcludeGuests -ExcludeDisabledAccounts $ExcludeDisabledAccounts

if ($upnLookup.Count -eq 0) {
    throw "STOP AND INVESTIGATE: no in-scope users were resolved. A tenant with zero in-scope users is implausible - this almost certainly means user enumeration is broken (permissions, a missing module, a Graph outage, or an overly narrow scope filter), and reconciling against an empty user set would strip the target group entirely. No changes were made."
}

Write-RunbookLog "Reading current membership of target group $TargetGroupId..."
$currentMembers = Get-MgGroupMember -GroupId $TargetGroupId -All -ErrorAction Stop |
    Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.user' }
$currentMemberIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($m in $currentMembers) { [void]$currentMemberIds.Add($m.Id) }
Write-RunbookLog "Target group currently has $($currentMemberIds.Count) member(s)."

Write-RunbookLog "Checking MFA registration status for $($upnLookup.Count) in-scope user(s)..."
$desiredMemberSet = [System.Collections.Generic.HashSet[string]]::new()
$qualifiedCount = 0
$unknownCount = 0
$userAuthDetail = @{}
$checkedCount = 0
$totalToCheck = $upnLookup.Count
$progressInterval = [Math]::Max(1, [Math]::Ceiling($totalToCheck / 10))

foreach ($userId in $upnLookup.Keys) {
    $authResult = Test-HasQualifyingMfaMethod -UserId $userId -QualifyingOdataTypes $qualifying.OdataTypes
    $userAuthDetail[$userId] = $authResult

    if ($authResult.Status -eq $true) {
        $qualifiedCount++
        [void]$desiredMemberSet.Add($userId)
    }
    elseif ($null -eq $authResult.Status) {
        $unknownCount++
        # Fail-safe: leave this user's membership exactly as it is today - neither a
        # confirmed add nor a confirmed remove, since we don't actually know their status.
        if ($currentMemberIds.Contains($userId)) {
            [void]$desiredMemberSet.Add($userId)
        }
    }
    # else: checked successfully, no qualifying method - simply not added to the desired set.

    $checkedCount++
    if ($checkedCount % $progressInterval -eq 0 -or $checkedCount -eq $totalToCheck) {
        Write-RunbookLog "  ...checked $checkedCount of $totalToCheck user(s)."
    }
}

Write-RunbookLog "$qualifiedCount user(s) have a qualifying MFA method; $unknownCount lookup(s) failed (left unchanged)."

$authLookupFailureRate = $unknownCount / $upnLookup.Count
if ($authLookupFailureRate -gt $MaxAuthLookupFailureRate) {
    throw ("STOP AND INVESTIGATE: authentication-method lookup failed for {0} of {1} in-scope user(s) ({2:P0}, threshold {3:P0}). " -f `
        $unknownCount, $upnLookup.Count, $authLookupFailureRate, $MaxAuthLookupFailureRate) +
        "That pattern points to a systemic problem (missing module/cmdlet, a permission change, throttling/outage) rather than isolated per-user errors. No changes were made to the target group - fix the underlying issue and re-run."
}

$toAdd = @($desiredMemberSet | Where-Object { -not $currentMemberIds.Contains($_) })
$toRemove = @($currentMemberIds | Where-Object { -not $desiredMemberSet.Contains($_) })

Write-RunbookLog "Plan: add $($toAdd.Count) user(s), remove $($toRemove.Count) user(s)."
Show-RunbookLog

# Per-user detail for every ADD/REMOVE - all via Write-RunbookLog/Write-Output, per the note
# on that helper.
foreach ($id in $toAdd) {
    $detail = $userAuthDetail[$id]
    $methodsText = if ($detail -and $detail.Methods.Count -gt 0) { ($detail.Methods | Sort-Object -Unique) -join '; ' } else { 'None registered' }

    [PSCustomObject]@{
        Action                = 'ADD'
        UserPrincipalName     = $upnLookup[$id]
        UserId                = $id
        RegisteredAuthMethods = $methodsText
        Reason                = 'Has a qualifying MFA method registered'
    } | Write-Output
}

foreach ($id in $toRemove) {
    $reason = if ($upnLookup.ContainsKey($id)) { 'No longer has a qualifying MFA method registered' } else { 'No longer an in-scope user' }
    [PSCustomObject]@{
        Action            = 'REMOVE'
        UserPrincipalName = if ($upnLookup.ContainsKey($id)) { $upnLookup[$id] } else { $id }
        UserId            = $id
        Reason            = $reason
    } | Write-Output
}

[PSCustomObject]@{
    RunTimeUtc            = (Get-Date).ToUniversalTime().ToString('u')
    Mode                  = if ($WhatIfMode) { 'WhatIf' } else { 'Applied' }
    QualifyingMethodTypes = ($qualifying.Keys -join ', ')
    UsersInScope          = $upnLookup.Count
    Qualified             = $qualifiedCount
    LookupFailures        = $unknownCount
    CurrentGroupSize      = $currentMemberIds.Count
    Added                 = $toAdd.Count
    Removed               = $toRemove.Count
} | Write-Output

if ($currentMemberIds.Count -gt 0) {
    $proposedChangeCount = $toAdd.Count + $toRemove.Count
    $changeCeiling = [Math]::Max($MinMembershipChangeFloor, [Math]::Ceiling($currentMemberIds.Count * $MaxMembershipChangeRatio))
    if ($proposedChangeCount -gt $changeCeiling) {
        throw "STOP AND INVESTIGATE: this run would change $proposedChangeCount member(s) ($($toAdd.Count) add, $($toRemove.Count) remove) against a current target group size of $($currentMemberIds.Count) - above the safety ceiling of $changeCeiling ($($MaxMembershipChangeRatio * 100)% of current size, floor $MinMembershipChangeFloor). A swing this large in one run is more likely a bug than a real shift in MFA registration. No changes were made - review the plan above; if it's genuinely expected, re-run with a higher -MaxMembershipChangeRatio."
    }
}

if ($WhatIfMode) {
    Write-RunbookLog "WhatIfMode is enabled - no changes applied."
    Show-RunbookLog
    return
}

foreach ($id in $toAdd) {
    try {
        New-MgGroupMemberByRef -GroupId $TargetGroupId -BodyParameter @{
            '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$id"
        } -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to add $($upnLookup[$id]) ($id) to the target group: $($_.Exception.Message)"
    }
}

foreach ($id in $toRemove) {
    try {
        Remove-MgGroupMemberByRef -GroupId $TargetGroupId -DirectoryObjectId $id -ErrorAction Stop
    }
    catch {
        $upnForLog = if ($upnLookup.ContainsKey($id)) { $upnLookup[$id] } else { $id }
        Write-Error "Failed to remove $upnForLog ($id) from the target group: $($_.Exception.Message)"
    }
}

Write-RunbookLog "Sync complete."
Show-RunbookLog

# Sync-MfaRegisteredGroup.ps1

Azure Automation runbook (PowerShell 7.2) that reconciles a security group so its membership exactly matches the set of Entra ID users who currently have at least one qualifying MFA authentication method registered.

Runs under the Automation Account's **system-assigned managed identity** — see [../deploy/README.md](../deploy/README.md) for how it's deployed and scheduled.

## What it does, each run

1. **Enumerate in-scope users.** Pulls users via `Get-MgUser -All`. `-ExcludeGuests` (default `$true`) drops `userType eq 'Guest'` accounts — a B2B guest's authentication methods live and are enforced in their home tenant, not this one. `-ExcludeDisabledAccounts` (default `$true`) drops `accountEnabled eq $false` accounts.
2. **Resolve qualifying method types.** See [Configuring qualifying methods](#configuring-qualifying-methods) below.
3. **Check MFA registration status.** For each in-scope user, checks their registered authentication methods for at least one qualifying type.
4. **Compute the desired membership.** Every in-scope user with a qualifying method belongs in the group. A user whose method lookup fails is left exactly as they are — not added, not removed (see [Fail-safe direction](#fail-safe-direction-leave-unchanged) below).
5. **Reconcile the group.** Adds/removes members of `-TargetGroupId` so its membership exactly matches the desired set. **The group must be dedicated solely to this automation** — anything added to it manually will be removed on the next run.

## Configuring qualifying methods

Which authentication method types count as "MFA registered" is configurable, checked in this order — first one found wins:

1. **`-QualifyingMethodTypes` parameter** — a comma-separated list of keys, e.g. `fido2,windowsHelloForBusiness,microsoftAuthenticator`. Set this via the schedule (see `mfaQualifyingMethodTypes` in [deploy.config.psd1](../deploy/deploy.config.psd1)) — this works reliably in the Azure Automation cloud sandbox.
2. **`$env:MFA_QUALIFYING_METHOD_TYPES` environment variable.** Azure Automation's cloud sandbox does not currently support setting a persistent custom environment variable for a job, so this only takes effect where the runbook's process actually has that variable set — a Hybrid Runbook Worker (a host you control) or a local test run. If you're running purely in the cloud sandbox, use the parameter above instead.
3. **Built-in default:** `fido2, windowsHelloForBusiness, microsoftAuthenticator, softwareOath, hardwareOath, phone, x509Certificate, platformCredential`.

Valid keys and the Graph authentication method type each maps to:

| Key | Graph `@odata.type` |
|---|---|
| `fido2` | `fido2AuthenticationMethod` |
| `windowsHelloForBusiness` | `windowsHelloForBusinessAuthenticationMethod` |
| `microsoftAuthenticator` | `microsoftAuthenticatorAuthenticationMethod` |
| `softwareOath` | `softwareOathAuthenticationMethod` |
| `hardwareOath` | `hardwareOathAuthenticationMethod` |
| `phone` | `phoneAuthenticationMethod` |
| `x509Certificate` | `x509CertificateAuthenticationMethod` |
| `platformCredential` | `platformCredentialAuthenticationMethod` |
| `temporaryAccessPass` | `temporaryAccessPassAuthenticationMethod` |
| `email` | `emailAuthenticationMethod` |
| `password` | `passwordAuthenticationMethod` |

`email` and `password` are supported keys but excluded from the built-in default since neither is a second factor on its own. An unrecognized key is ignored with a warning; if every key in the resolved list is unrecognized, the run throws (stop and investigate) rather than silently reconciling against an empty qualifying set.

## Fail-safe direction: leave unchanged

Unlike a Conditional Access exclusion group (where "stay excluded" is the safe default because the alternative is an admin getting locked out), this group has no inherent safe direction — it's a plain reporting/targeting group of who has MFA registered. So when a user's authentication-method lookup fails, the runbook doesn't guess: it leaves that user's group membership exactly as it is this run (still a member if they were one, still not a member if they weren't) and re-evaluates them on the next run. The lookup failure still counts toward the [circuit breaker](#circuit-breakers-stop-and-investigate) below.

## Reading job output

Azure Automation's **Output** tab only shows the `Write-Output`/pipeline stream — plain `Write-Information` narration lands under **All Logs** instead, and in practice has been unreliable even there on PowerShell 7.2 Runtime Environment jobs. So all step-by-step progress goes through a `Write-RunbookLog`/`Show-RunbookLog` helper pair that buffers messages internally (safe to call from any function without corrupting its return value - `Write-Output` inside a function becomes part of that function's return value in PowerShell, which is a real bug this design specifically avoids) and flushes them to `Write-Output`, prefixed `[STEP]`, from the top-level script only. Check the **Output** tab first; a full run looks like:

- `[STEP]` lines for each phase in order: run start, connecting, resolving qualifying method types, enumerating in-scope users, reading the target group's current membership, MFA registration checks (with periodic `checked N of M` progress), and the computed add/remove plan.
- One record per user **added** to the group:
  ```
  Action                : ADD
  UserPrincipalName     : alice@contoso.com
  UserId                : 11111111-1111-1111-1111-111111111111
  RegisteredAuthMethods : FIDO2 security key / passkey; Password
  Reason                : Has a qualifying MFA method registered
  ```
- One record per user **removed** from the group, with `Reason` being either "No longer has a qualifying MFA method registered" or "No longer an in-scope user".
- One summary record per run: the qualifying method types used, and counts of users in scope, qualified, lookup failures, current group size, and added/removed.

## Circuit breakers ("stop and investigate")

Two checks run *before* any group membership change is applied. Each throws (failing the Automation job) rather than silently pushing through a bad reconciliation:

| Check | Trips when | Why |
|---|---|---|
| Zero in-scope users resolved | No users found at all | A tenant with zero in-scope users is implausible — this means user enumeration is broken (permissions, missing module, Graph outage, or an overly narrow scope filter), and reconciling against an empty set would strip the whole target group. |
| Auth-lookup failure rate | `> -MaxAuthLookupFailureRate` (default 20%) of in-scope users fail the method lookup | A systemic failure (missing cmdlet/module, revoked permission, throttling) fails every user the same way — that's a different signal than a few individually unlucky lookups. |
| Membership swing | Proposed add+remove count `> -MaxMembershipChangeRatio` (default 30%, floored at `-MinMembershipChangeFloor`, default 5) of the group's *current* size | A large swing in one run is more likely a bug than a real shift in MFA registration. Skipped when the group is currently empty, since populating it from scratch on the first run is expected to touch everyone. |

The isolated per-user fail-safe (one user's lookup fails → membership left unchanged) still applies below these thresholds and doesn't itself stop a run.

## Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `TargetGroupId` | *(required)* | Object ID of the dedicated target group. |
| `QualifyingMethodTypes` | *(none — falls through to env var / built-in default)* | Comma-separated qualifying method keys. See [Configuring qualifying methods](#configuring-qualifying-methods). |
| `ExcludeGuests` | `$true` | Drop guest accounts from scope. |
| `ExcludeDisabledAccounts` | `$true` | Drop disabled accounts from scope. |
| `WhatIfMode` | `$false` | Compute and log the plan, but apply no changes. Use for a manual dry-run job. |
| `MaxAuthLookupFailureRate` | `0.2` | See circuit breakers above. |
| `MaxMembershipChangeRatio` | `0.3` | See circuit breakers above. |
| `MinMembershipChangeFloor` | `5` | See circuit breakers above. |

## Required Microsoft Graph application permissions

Granted to the managed identity by the deploy script — deliberately narrow:

- `User.Read.All` — enumerate/resolve in-scope users
- `UserAuthenticationMethod.Read.All` — check for qualifying MFA methods
- `GroupMember.ReadWrite.All` — reconcile the target group

## Manual test run

From the portal's Test pane, or:

```powershell
Start-AzAutomationRunbook -ResourceGroupName <rg> -AutomationAccountName <account> `
    -Name Sync-MfaRegisteredGroup -Parameters @{ TargetGroupId = '<group-object-id>'; WhatIfMode = $true }
```

Review the logged plan (who'd be added/removed and why) before trusting a real (non-`WhatIfMode`) run, especially the first one.

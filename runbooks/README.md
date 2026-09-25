# Sync-MfaRegisteredGroup.ps1

Azure Automation runbook (PowerShell 7.2) that reconciles a security group so its membership exactly matches the set of Entra ID users who currently have at least one qualifying MFA authentication method registered.

Runs under the Automation Account's **system-assigned managed identity** — see [../deploy/README.md](../deploy/README.md) for how it's deployed and scheduled.

## What it does, each run

1. **Resolve configuration.** `TargetGroupId`, `ExcludeGuests`, `ExcludeDisabledAccounts` — and, later, `QualifyingMethodTypes` — each resolve from an explicit parameter, then a like-named Automation Variable, then a built-in default. See [Configuring settings](#configuring-settings) below.
2. **Enumerate in-scope users.** Pulls users via `Get-MgUser -All`. `ExcludeGuests` (default `$true`) drops `userType eq 'Guest'` accounts — a B2B guest's authentication methods live and are enforced in their home tenant, not this one. `ExcludeDisabledAccounts` (default `$true`) drops `accountEnabled eq $false` accounts.
3. **Check MFA registration status.** For each in-scope user, checks their registered authentication methods for at least one qualifying type.
4. **Compute the desired membership.** Every in-scope user with a qualifying method belongs in the group. A user whose method lookup fails is left exactly as they are — not added, not removed (see [Fail-safe direction](#fail-safe-direction-leave-unchanged) below).
5. **Reconcile the group.** Adds/removes members of `TargetGroupId` so its membership exactly matches the desired set. **The group must be dedicated solely to this automation** — anything added to it manually will be removed on the next run.

## Configuring settings

`TargetGroupId`, `ExcludeGuests`, `ExcludeDisabledAccounts`, and `QualifyingMethodTypes` each resolve in this order — first one found wins:

1. **The matching explicit parameter** (`-TargetGroupId`, `-ExcludeGuests`, `-ExcludeDisabledAccounts`, `-QualifyingMethodTypes`). Meant for a one-off manual/test run (portal Test pane, `Start-AzAutomationRunbook -Parameters`) — the recurring schedule doesn't set these.
2. **The like-named Automation Variable** on this Automation Account (`TargetGroupId`, `ExcludeGuests`, `ExcludeDisabledAccounts`, `QualifyingMethodTypes`), read via `Get-AutomationVariable`. **This is the supported way to change day-to-day configuration** — the deploy script creates/updates these from [deploy.config.psd1](../deploy/deploy.config.psd1), but they can also be edited directly in the portal (**Automation Account → Variables**) and take effect on the very next run, with no redeploy and no touching the schedule.
3. **`QualifyingMethodTypes` only:** the `$env:MFA_QUALIFYING_METHOD_TYPES` environment variable. Azure Automation's cloud sandbox does not support setting a persistent custom environment variable for a job, so this only takes effect where the runbook's process genuinely has it set — a Hybrid Runbook Worker (a host you control) or a local test run.
4. **A built-in default:** `$true` for `ExcludeGuests`/`ExcludeDisabledAccounts`; `fido2, windowsHelloForBusiness, microsoftAuthenticator, softwareOath, hardwareOath, phone, x509Certificate, platformCredential` for `QualifyingMethodTypes`; and, for `TargetGroupId` only, a thrown error — there's no sensible default target group.

Each resolved value is logged at the start of the run, along with which source it came from.

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
| `TargetGroupId` | *(none — falls through to Automation Variable, then errors)* | Object ID of the dedicated target group. See [Configuring settings](#configuring-settings). |
| `QualifyingMethodTypes` | *(none — falls through to Automation Variable / env var / built-in default)* | Comma-separated qualifying method keys. See [Configuring settings](#configuring-settings). |
| `ExcludeGuests` | *(unset — falls through to Automation Variable, then `$true`)* | Drop guest accounts from scope. |
| `ExcludeDisabledAccounts` | *(unset — falls through to Automation Variable, then `$true`)* | Drop disabled accounts from scope. |
| `WhatIfMode` | `$false` | Compute and log the plan, but apply no changes. Use for a manual dry-run job. Always a parameter, never an Automation Variable - it's meant for a one-off run, not a persistent setting. |
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

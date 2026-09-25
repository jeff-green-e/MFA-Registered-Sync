# Deploy-MfaRegisteredSyncAutomation.ps1

Idempotent deploy script that provisions everything [../runbooks/Sync-MfaRegisteredGroup.ps1](../runbooks/README.md) needs to run on a schedule. Safe to re-run — every step checks current state first and skips what already exists.

See [../README.md](../README.md#prerequisites) before running this for the first time.

## What it does, in order

0. **Preflight** (`Assert-AzAutomationCapability`) — verifies the loaded `Az.Automation` actually supports the PowerShell 7.2 Runtime Environment before anything is created, and warns on an `Az.Accounts` old enough to fail token acquisition. See [Preflight: Az version check](#preflight-az-version-check) below.
1. **Resource group** — create if missing.
2. **Automation Account** — create with a system-assigned managed identity if missing; if it exists without an identity, enable one. Waits for the identity's `principalId` to actually populate before continuing (this is eventually consistent — using it too early fails silently later).
3. **Import Graph modules into the PowerShell 7.2 Runtime Environment** — `Microsoft.Graph.Authentication`, `.Identity.SignIns`, `.Users`, `.Groups`, via `New-`/`Get-AzAutomationModule -RuntimeVersion '7.2'`, pinned to the exact version currently on PowerShell Gallery (`Find-Module`).
4. **Import and publish the runbook** as `-Type PowerShell72`.
5. **Target group** — create a new dedicated security group, or reuse the one named in config/`-TargetGroupId`.
6. **Automation Variables** — create or update `TargetGroupId`, `ExcludeGuests`, `ExcludeDisabledAccounts`, and (if configured) `QualifyingMethodTypes` on the Automation Account. This is the runbook's actual configuration store — see [Configuration lives in Automation Variables](#configuration-lives-in-automation-variables) below.
7. **Grant Graph application permissions** to the managed identity: `User.Read.All`, `UserAuthenticationMethod.Read.All`, `GroupMember.ReadWrite.All`. None of these are on Microsoft's privileged-permission list, so Application Administrator or Cloud Application Administrator should be enough to consent them (Global Administrator / Privileged Role Administrator also works).
8. **Schedule** — create (default: daily) and link it to the runbook if not already linked. The link only ever carries `WhatIfMode = $false` — nothing about it needs updating once created, since every setting that can legitimately change over time lives in the Automation Variables from step 6 instead.

## Configuration lives in Automation Variables

`TargetGroupId`, `ExcludeGuests`, `ExcludeDisabledAccounts`, and `QualifyingMethodTypes` are written to the Automation Account as **Automation Variables**, not schedule parameters. That's deliberate: a scheduled runbook's linked parameters are fixed at link time — `Register-AzAutomationScheduledRunbook` has no update mode, and the portal's schedule pane only lets you *view* them, not edit them. An Automation Variable's value, by contrast, is editable directly in **Automation Account → Variables** in the portal, and the runbook picks up the new value on its very next run — no redeploy, no touching the schedule.

Precedence the runbook uses for each of these (see [../runbooks/README.md](../runbooks/README.md#configuring-settings) for the full detail): an explicit parameter (for a one-off manual/test run) wins first, then the Automation Variable, then a built-in default (`QualifyingMethodTypes` also checks `$env:MFA_QUALIFYING_METHOD_TYPES` between the variable and the default, for Hybrid Worker/local runs).

This script keeps `TargetGroupId`, `ExcludeGuests`, and `ExcludeDisabledAccounts` in sync with `deploy.config.psd1` on every run (`Set-AutomationVariableValue` creates the variable if missing, updates it if not). `QualifyingMethodTypes` is only touched when `mfaQualifyingMethodTypes` is set in config — leave it blank to manage that one variable by hand in the portal instead, without this script overwriting it on the next deploy.

**To change any of these after deployment**, either re-run this script with an updated `deploy.config.psd1`, or edit the variable directly in the portal — both work, and the portal edit is faster if you don't need to touch anything else.

## Configuration (deploy script itself)

Settings are read from [deploy.config.psd1](deploy.config.psd1) next to this script: `subscriptionId`, `tenantId`, `resourceGroupName`, `location`, `automationAccountName`, `targetGroupDisplayName` / `targetGroupId`, `cadenceDays`, `excludeGuests`, `excludeDisabledAccounts`, `mfaQualifyingMethodTypes`. Any explicit `-Parameter` on the command line overrides the config file for that one run; nothing else needs to change.

```powershell
# Uses every value from deploy.config.psd1
.\Deploy-MfaRegisteredSyncAutomation.ps1

# Config file supplies the rest; override just the subscription for a test deploy
.\Deploy-MfaRegisteredSyncAutomation.ps1 -SubscriptionId '00000000-0000-0000-0000-000000000000'
```

Every run starts by printing a resolved-configuration block, so what it's about to target is always visible before anything is touched.

## Preflight: Az version check

The PowerShell 7.1/7.2 Runtime Environment cmdlets this script depends on only exist in `Az.Automation` **1.10.0+**. On 1.9.1 — which is what `Az` 10.0.0 through 11.1.0 ship — `-RuntimeVersion` doesn't exist on any module cmdlet and `Import-AzAutomationRunbook -Type` doesn't accept `PowerShell72` at all. Without a preflight, that surfaces as `A parameter cannot be found that matches parameter name 'RuntimeVersion'` **after** the resource group and Automation Account have already been created, leaving a half-built deployment behind.

`Assert-AzAutomationCapability` runs before `Set-AzContext`, so a failure means nothing was touched. It **detects capabilities rather than comparing version numbers** — checking for the `-RuntimeVersion` parameter and for `PowerShell72` in the `-Type` validation set — which keeps it correct without pinning a version, and which also catches the case a version comparison would miss: a current `Az.Automation` installed on disk while an older copy is already loaded in the session. The error message distinguishes the two, because the fixes differ:

- **Newer version already on disk** → no reinstall needed; close the terminal, open a new one, `Connect-AzAccount`, re-run. PowerShell cannot swap an imported module at runtime.
- **Nothing newer installed** → `Install-Module Az.Automation -Scope CurrentUser -Force`, *then* re-run from a new terminal.

It also emits a **non-fatal warning** when `Az.Accounts` is below 3.0.0. That's the same root cause wearing a different mask: `Az` 10.0.0 ships `Az.Accounts` 2.12.3 alongside `Az.Automation` 1.9.1, and that build fails token acquisition against current Entra with `A task was canceled.` for every tenant — which `Set-AzContext` reports as `Please provide a valid tenant or a valid subscription`. `Get-AzContext` succeeding immediately afterward is a red herring; it reads cached context metadata and proves nothing about token validity. Flagging it up front saves diagnosing the same stale install twice. See [../README.md](../README.md#3-local-machine-the-box-running-the-deploy-script) for the version-to-bundle mapping.

## Two separate "needs Graph" surfaces — don't conflate them

- **Cloud-side**: the modules imported into the Automation Account's Runtime Environment (step 3) are what the *runbook* uses at runtime, in Azure.
- **Local-side**: this deploy script itself calls `Connect-MgGraph`, `Get-`/`New-MgGroup`, and the service-principal/app-role-assignment cmdlets *locally*, in the session running it — for creating the target group and granting permissions. That needs `Microsoft.Graph.Authentication`, `.Groups`, and `.Applications` installed on the machine running this script (see [../README.md](../README.md#prerequisites)). `Import-PinnedGraphModules` (below) handles a common failure mode in that local step.

## Hard-won lessons baked into this script

- **PowerShell 7.1/7.2 runbooks execute against a distinct "Runtime Environment" resource, not the classic account-wide module store — the two do not sync.** A module imported via the classic REST API (`.../automationAccounts/{name}/modules/{name}`) can show `provisioningState: Succeeded` yet be completely invisible to the runbook and to the Runtime Environment's own package list in the portal. Always import via `-RuntimeVersion '7.2'` on `New-`/`Get-AzAutomationModule` (both cmdlets need it — `Get-` without it silently checks the wrong bucket and "never finds" a module that's importing normally).
- **Local machines commonly have multiple installed versions of `Microsoft.Graph.*` modules side by side.** PowerShell's auto-loader can resolve different Graph sub-modules to different versions within the same session, and the CLR then refuses to load a second, differently-versioned copy of the shared `Microsoft.Graph.Authentication` assembly (`Assembly with same name is already loaded`). `Import-PinnedGraphModules` forces every required local module to the newest version they all have in common before `Connect-MgGraph` runs. If it throws "No single installed version is common to...", the machine has genuinely incompatible installs and needs manual cleanup (see [../README.md](../README.md#prerequisites)). **Once a conflicting assembly is already loaded in a session, no amount of `Remove-Module`/`Import-Module -Force` can fix it retroactively** — `Remove-Module` only removes the PowerShell wrapper, not the underlying .NET assembly. If this happens, close the terminal/PowerShell window entirely and re-run in a fresh one.
- **`Select-MgProfile` doesn't exist in Graph SDK v2+** (v1.0 is the only profile now) — the runbook guards the call with `Get-Command ... -ErrorAction SilentlyContinue` rather than calling it directly, since an unrecognized command isn't suppressed by `-ErrorAction` and would otherwise crash the job.
- **`Import-AzAutomationRunbook` takes `-Type PowerShell72`, not a `-RuntimeVersion` parameter** — that parameter exists on the module cmdlets, not the runbook cmdlets.
- **A scheduled runbook's linked parameters can't be edited in place** — not via `Register-AzAutomationScheduledRunbook` (no update mode), and not via the portal (the schedule's parameters pane is read-only after creation). This is exactly why day-to-day configuration lives in Automation Variables instead of schedule parameters — see [Configuration lives in Automation Variables](#configuration-lives-in-automation-variables) above. `Set-AzAutomationVariable`/`New-AzAutomationVariable`, by contrast, update cleanly and are reflected in the portal's Variables pane as an editable value.
- **Azure Automation's cloud sandbox has no supported way to set a persistent custom environment variable for a job.** The "Runtime Environment" feature only configures language/version/packages, not environment variables (as of the current Microsoft Learn docs). The runbook's `$env:MFA_QUALIFYING_METHOD_TYPES` support is genuine — it's honored wherever the runbook's process actually has that variable set (a Hybrid Runbook Worker you control, or a local test run) — but for the cloud sandbox, use the `QualifyingMethodTypes` Automation Variable instead.

## After deploying

- Do a manual test run first — see [../runbooks/README.md](../runbooks/README.md#manual-test-run) — before trusting the first scheduled run.
- Use the target group wherever you need to identify or target users who currently have a qualifying MFA method registered.

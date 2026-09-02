# Deploy-MfaRegisteredSyncAutomation.ps1

Idempotent deploy script that provisions everything [../runbooks/Sync-MfaRegisteredGroup.ps1](../runbooks/README.md) needs to run on a schedule. Safe to re-run — every step checks current state first and skips what already exists.

See [../README.md](../README.md#prerequisites) before running this for the first time.

## What it does, in order

1. **Resource group** — create if missing.
2. **Automation Account** — create with a system-assigned managed identity if missing; if it exists without an identity, enable one. Waits for the identity's `principalId` to actually populate before continuing (this is eventually consistent — using it too early fails silently later).
3. **Import Graph modules into the PowerShell 7.2 Runtime Environment** — `Microsoft.Graph.Authentication`, `.Identity.SignIns`, `.Users`, `.Groups`, via `New-`/`Get-AzAutomationModule -RuntimeVersion '7.2'`, pinned to the exact version currently on PowerShell Gallery (`Find-Module`).
4. **Import and publish the runbook** as `-Type PowerShell72`.
5. **Target group** — create a new dedicated security group, or reuse the one named in config/`-TargetGroupId`.
6. **Grant Graph application permissions** to the managed identity: `User.Read.All`, `UserAuthenticationMethod.Read.All`, `GroupMember.ReadWrite.All`. None of these are on Microsoft's privileged-permission list, so Application Administrator or Cloud Application Administrator should be enough to consent them (Global Administrator / Privileged Role Administrator also works).
7. **Schedule** — create (default: daily) and link it to the runbook with its parameters, including `-QualifyingMethodTypes` if `mfaQualifyingMethodTypes` is set in config.

## Configuration

Settings are read from [deploy.config.psd1](deploy.config.psd1) next to this script: `subscriptionId`, `tenantId`, `resourceGroupName`, `location`, `automationAccountName`, `targetGroupDisplayName` / `targetGroupId`, `cadenceDays`, `excludeGuests`, `excludeDisabledAccounts`, `mfaQualifyingMethodTypes`. Any explicit `-Parameter` on the command line overrides the config file for that one run; nothing else needs to change.

```powershell
# Uses every value from deploy.config.psd1
.\Deploy-MfaRegisteredSyncAutomation.ps1

# Config file supplies the rest; override just the subscription for a test deploy
.\Deploy-MfaRegisteredSyncAutomation.ps1 -SubscriptionId '00000000-0000-0000-0000-000000000000'
```

Every run starts by printing a resolved-configuration block, so what it's about to target is always visible before anything is touched.

## Configuring which methods qualify as MFA

`mfaQualifyingMethodTypes` in `deploy.config.psd1` (or `-MfaQualifyingMethodTypes` on the command line) is passed through to the runbook as its `-QualifyingMethodTypes` schedule parameter — this is the supported way to override the default set of qualifying authentication methods when running in the Azure Automation cloud sandbox. Leave it blank to let the runbook fall back to its `$env:MFA_QUALIFYING_METHOD_TYPES` environment variable (only meaningful on a Hybrid Runbook Worker or local run — the cloud sandbox doesn't support persistent custom environment variables for a job) or its built-in default. See [../runbooks/README.md](../runbooks/README.md#configuring-qualifying-methods) for the full list of valid keys.

## Two separate "needs Graph" surfaces — don't conflate them

- **Cloud-side**: the modules imported into the Automation Account's Runtime Environment (step 3) are what the *runbook* uses at runtime, in Azure.
- **Local-side**: this deploy script itself calls `Connect-MgGraph`, `Get-`/`New-MgGroup`, and the service-principal/app-role-assignment cmdlets *locally*, in the session running it — for creating the target group and granting permissions. That needs `Microsoft.Graph.Authentication`, `.Groups`, and `.Applications` installed on the machine running this script (see [../README.md](../README.md#prerequisites)). `Import-PinnedGraphModules` (below) handles a common failure mode in that local step.

## Hard-won lessons baked into this script

- **PowerShell 7.1/7.2 runbooks execute against a distinct "Runtime Environment" resource, not the classic account-wide module store — the two do not sync.** A module imported via the classic REST API (`.../automationAccounts/{name}/modules/{name}`) can show `provisioningState: Succeeded` yet be completely invisible to the runbook and to the Runtime Environment's own package list in the portal. Always import via `-RuntimeVersion '7.2'` on `New-`/`Get-AzAutomationModule` (both cmdlets need it — `Get-` without it silently checks the wrong bucket and "never finds" a module that's importing normally).
- **Local machines commonly have multiple installed versions of `Microsoft.Graph.*` modules side by side.** PowerShell's auto-loader can resolve different Graph sub-modules to different versions within the same session, and the CLR then refuses to load a second, differently-versioned copy of the shared `Microsoft.Graph.Authentication` assembly (`Assembly with same name is already loaded`). `Import-PinnedGraphModules` forces every required local module to the newest version they all have in common before `Connect-MgGraph` runs. If it throws "No single installed version is common to...", the machine has genuinely incompatible installs and needs manual cleanup (see [../README.md](../README.md#prerequisites)). **Once a conflicting assembly is already loaded in a session, no amount of `Remove-Module`/`Import-Module -Force` can fix it retroactively** — `Remove-Module` only removes the PowerShell wrapper, not the underlying .NET assembly. If this happens, close the terminal/PowerShell window entirely and re-run in a fresh one.
- **`Select-MgProfile` doesn't exist in Graph SDK v2+** (v1.0 is the only profile now) — the runbook guards the call with `Get-Command ... -ErrorAction SilentlyContinue` rather than calling it directly, since an unrecognized command isn't suppressed by `-ErrorAction` and would otherwise crash the job.
- **`Import-AzAutomationRunbook` takes `-Type PowerShell72`, not a `-RuntimeVersion` parameter** — that parameter exists on the module cmdlets, not the runbook cmdlets.
- **Azure Automation's cloud sandbox has no supported way to set a persistent custom environment variable for a job.** The "Runtime Environment" feature only configures language/version/packages, not environment variables (as of the current Microsoft Learn docs). The runbook's `$env:MFA_QUALIFYING_METHOD_TYPES` support is genuine — it's honored wherever the runbook's process actually has that variable set (a Hybrid Runbook Worker you control, or a local test run) — but for the cloud sandbox, use the `-QualifyingMethodTypes` schedule parameter (`mfaQualifyingMethodTypes` in config) instead.

## After deploying

- Do a manual test run first — see [../runbooks/README.md](../runbooks/README.md#manual-test-run) — before trusting the first scheduled run.
- Use the target group wherever you need to identify or target users who currently have a qualifying MFA method registered.

# MFA Registered Sync

Keeps a security group reconciled against the current set of Entra ID users who have at least one qualifying MFA authentication method registered. Which methods qualify is configurable — see [Configuring qualifying methods](runbooks/README.md#configuring-qualifying-methods). Users who register a qualifying method are added to the group; users who no longer have one are removed.

## Repository structure

| Path | Purpose |
|---|---|
| [runbooks/Sync-MfaRegisteredGroup.ps1](runbooks/Sync-MfaRegisteredGroup.ps1) | The Azure Automation runbook that does the reconciliation. See [runbooks/README.md](runbooks/README.md). |
| [deploy/Deploy-MfaRegisteredSyncAutomation.ps1](deploy/Deploy-MfaRegisteredSyncAutomation.ps1) | Idempotent script that provisions the Automation Account, imports the runbook, grants it Graph permissions, and schedules it. See [deploy/README.md](deploy/README.md). |
| [deploy/deploy.config.psd1](deploy/deploy.config.psd1) | Deployment settings (subscription, tenant, resource group, target group, cadence, scope filters, qualifying methods) read by the deploy script. |

## Prerequisites

Before running [deploy/Deploy-MfaRegisteredSyncAutomation.ps1](deploy/Deploy-MfaRegisteredSyncAutomation.ps1), confirm the following. At a glance, the account running the script needs:

- **`Contributor`** on the target subscription (or resource group) — to create the resource group, Automation Account, runbook, and schedule.
- **Application Administrator or Cloud Application Administrator** in Entra ID (Global Administrator / Privileged Role Administrator also works) — to consent the managed identity's Graph application permissions. None of the required permissions are on Microsoft's privileged-permission list.
- **PowerShell 7+** on the machine running the script, with the Az and Microsoft.Graph modules listed below installed.
- The **deployment settings** decided and filled into `deploy.config.psd1` up front (subscription, tenant, resource group, target group, schedule cadence, scope filters, qualifying methods).

Details on each below.

### 1. Azure access

An identity (yours, running the deploy script) with rights on the target subscription to:
- Create/read a resource group
- Create an Automation Account and enable its system-assigned managed identity
- Create/import/publish runbooks and modules, create schedules

`Contributor` on the subscription or target resource group is sufficient.

### 2. Entra ID access

Granting the managed identity its Microsoft Graph **application** permissions requires admin consent. The permissions below are not on Microsoft's privileged-permission list (unlike, say, `RoleManagement.Read.Directory`), so **Application Administrator** or **Cloud Application Administrator** should be enough to consent them — Global Administrator / Privileged Role Administrator also works if that's unexpectedly denied.

Permissions granted to the managed identity:
- `User.Read.All` — enumerate/resolve in-scope users
- `UserAuthenticationMethod.Read.All` — check for qualifying MFA methods
- `GroupMember.ReadWrite.All` — reconcile the target group

### 3. Local machine (the box running the deploy script)

PowerShell 7+ recommended (Windows PowerShell 5.1 also works, the Az/Graph modules support both).

| Module | Minimum version | Why |
|---|---|---|
| `Az.Accounts` | any recent | `Connect-AzAccount`, `Set-AzContext` |
| `Az.Resources` | any recent | resource group creation |
| `Az.Automation` | **1.10.0+** | module import (`New-`/`Get-AzAutomationModule -RuntimeVersion '7.2'`), runbook import/publish (`-Type PowerShell72`), schedule create + link. `-RuntimeVersion` matters: PowerShell 7.1/7.2 runbooks execute against a distinct "Runtime Environment" resource, not the classic account-wide module store - the two don't sync. A module imported without `-RuntimeVersion` can show `provisioningState: Succeeded` yet be invisible to the runbook and to the Runtime Environment's package list in the portal. |
| `Microsoft.Graph.Authentication` | same version as the two rows below | `Connect-MgGraph` |
| `Microsoft.Graph.Groups` | same version as the other two | `New-MgGroup`, group membership |
| `Microsoft.Graph.Applications` | same version as the other two | `Get-MgServicePrincipal`, `New-MgServicePrincipalAppRoleAssignment` |

These `Microsoft.Graph.*` modules are for the deploy script's own **local** calls (creating the target group, granting the managed identity its permissions) — they are separate from the Graph modules the *runbook* uses at runtime, which the deploy script imports into the Automation Account's PowerShell 7.2 Runtime Environment via `Az.Automation` cmdlets and don't need to be installed locally at all. See [deploy/README.md](deploy/README.md#two-separate-needs-graph-surfaces--dont-conflate-them) for the full split.

**Microsoft.Graph modules must all resolve to the same version.** If a machine has more than one version of these installed side by side (common after an `Install-Module` upgrade that didn't remove the old one), PowerShell can auto-load a different version for each module in the same session, and the CLR then refuses to load the second, conflicting copy of the shared `Microsoft.Graph.Authentication` assembly - surfacing as `Get-MgGroup: ... Assembly with same name is already loaded`. The deploy script handles this itself (`Import-PinnedGraphModules` forces all three to the newest version they have in common before connecting), but if it throws "No single installed version is common to...", clean up the duplicates manually:

```powershell
Get-Module -ListAvailable Az.Accounts, Az.Resources, Az.Automation, Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Applications |
    Select-Object Name, Version | Sort-Object Name, Version

Install-Module Az.Accounts, Az.Resources, Az.Automation, Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Applications -Scope CurrentUser -Force
```

### 4. Decide your deployment settings

Before filling in [deploy/deploy.config.psd1](deploy/deploy.config.psd1), decide:

| Key | Decision |
|---|---|
| `subscriptionId` | Azure subscription to deploy into. |
| `tenantId` | Entra tenant ID. Leave blank to use the tenant of the current `Az` context. |
| `resourceGroupName` | Resource group for the Automation Account. Created if it doesn't exist. |
| `location` | Azure region for the resource group / Automation Account. |
| `automationAccountName` | Name of the Automation Account. Created if it doesn't exist. |
| `targetGroupDisplayName` / `targetGroupId` | See below — either let the script create a group, or supply an existing one's object ID. |
| `cadenceDays` | Days between scheduled runbook runs (`1` = daily). |
| `excludeGuests` | Whether guest accounts are excluded from scope (default `$true`). |
| `excludeDisabledAccounts` | Whether disabled accounts are excluded from scope (default `$true`). |
| `mfaQualifyingMethodTypes` | Comma-separated list of authentication method keys that count as "MFA registered". Leave blank for the runbook's default. See [runbooks/README.md](runbooks/README.md#configuring-qualifying-methods). |

**Target group**, specifically:
- Let the deploy script create a new, dedicated security group (default, via `targetGroupDisplayName`), or
- Supply the object ID of an existing group via `targetGroupId`.

Either way, **this group must be dedicated solely to this automation** — the runbook fully reconciles its membership (adds/removes) on every run, so anything added manually will be removed on the next run.

Any of these can also be overridden on the command line as an explicit `-Parameter` at deploy time instead of being set in the config file — see [deploy/README.md](deploy/README.md#configuration).

## Installation

1. **Clone the repo** onto a machine that meets the [local machine prerequisites](#3-local-machine-the-box-running-the-deploy-script) above.

2. **Fill in the config.** Edit [deploy/deploy.config.psd1](deploy/deploy.config.psd1) with the settings you decided in [Prerequisites #4](#4-decide-your-deployment-settings) above.

3. **Authenticate to Azure** in the session you'll run the deploy script from:

   ```powershell
   Connect-AzAccount
   ```

4. **Run the deploy script.** It's idempotent — safe to re-run if a step fails partway through.

   ```powershell
   cd deploy
   .\Deploy-MfaRegisteredSyncAutomation.ps1
   ```

   You'll be prompted to interactively consent to the Microsoft Graph application permissions listed above. See [deploy/README.md](deploy/README.md) for exactly what the script does, in order, and any explicit `-Parameter` overrides available.

5. **Network reachability (runtime, not deploy-time).** The runbook runs in the Automation Account's default cloud sandbox, which reaches `graph.microsoft.com` and `www.powershellgallery.com` (for module install) over the public internet by default — no action needed unless you later move execution to a Hybrid Runbook Worker behind restrictive egress rules, in which case allow those endpoints.

## After deploying

- Do a manual test run first: `Start-AzAutomationRunbook` with `WhatIfMode = $true`, or use the portal's Test pane, and review the job output before trusting the first scheduled run. See [runbooks/README.md](runbooks/README.md#manual-test-run).
- Use the target group wherever you need to identify or target users who currently have a qualifying MFA method registered.

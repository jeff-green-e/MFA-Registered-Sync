@{
    # Azure subscription to deploy into.
    subscriptionId            = ''

    # Entra tenant ID. Leave blank to use the tenant of the current Az context (Connect-AzAccount).
    tenantId                  = ''

    # Resource group for the Automation Account. Created if it does not exist.
    resourceGroupName         = 'rg-MFARegisteredSync-automation'

    # Azure region for the resource group / Automation Account.
    location                  = 'centralus'

    # Name of the Automation Account. Created if it does not exist.
    automationAccountName     = 'aa-mfa-registered-sync'

    # Display name used to create the target group. Ignored if targetGroupId is set.
    targetGroupDisplayName    = 'sg-MFA-Registered-Users'

    # Object ID of an existing target group. Leave blank to create a new one.
    targetGroupId             = ''

    # Days between scheduled runbook runs. 1 = daily.
    cadenceDays               = 1

    # Exclude guest (userType 'Guest') accounts from scope - their MFA methods are registered
    # and enforced in their home tenant, not this one.
    excludeGuests             = $true

    # Exclude accounts with accountEnabled = $false from scope.
    excludeDisabledAccounts   = $true

    # Comma-separated list of authentication method keys that qualify as "MFA registered".
    # Leave blank to use the runbook's built-in default (see runbooks/README.md). Valid keys:
    # fido2, windowsHelloForBusiness, microsoftAuthenticator, softwareOath, hardwareOath,
    # phone, x509Certificate, platformCredential, temporaryAccessPass, email, password.
    #
    # This is passed to the runbook as a schedule parameter, which works reliably in the
    # Azure Automation cloud sandbox. The runbook also honors a genuine
    # $env:MFA_QUALIFYING_METHOD_TYPES environment variable if one is set in its process
    # environment (e.g. on a Hybrid Runbook Worker you control) - but the cloud sandbox does
    # not support setting persistent custom environment variables for a job, so this config
    # value is the supported way to override the default when running there.
    mfaQualifyingMethodTypes  = ''

    # Highest Microsoft.Graph module version the deploy script may import into the Automation
    # Account's PowerShell 7.2 Runtime Environment. Leave blank to use the script's built-in
    # default (2.25.0).
    #
    # This is a runtime compatibility ceiling, not a preference. PowerShell 7.2 runbooks run on
    # .NET 6 (System.Text.Json 6.0.0.0), and Graph SDK 2.26.1+ bundles System.Text.Json 8.0
    # while 2.36.0+ bundles 10.0 - a .NET 10 assembly that cannot load there. Importing 2.36.0+
    # yields a runbook that fails instantly with "Could not load file or assembly
    # 'System.Text.Json, Version=10.0.0.0'" and produces no output at all.
    #
    # Only raise this together with a runtime change: the PowerShell 7.4 runtime (.NET 8) would
    # make the 8.0 band (up to 2.35.1) usable. No Azure Automation runtime hosts .NET 10, so
    # 2.36.0+ is not deployable regardless.
    maxGraphModuleVersion     = ''
}

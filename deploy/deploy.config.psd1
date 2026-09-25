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
}

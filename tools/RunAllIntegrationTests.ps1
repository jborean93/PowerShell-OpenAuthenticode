#Requires -Module Az.Accounts
#Requires -Module Az.KeyVault
#Requires -Module Az.Resources
#Requires -Module Microsoft.Graph.Applications
#Requires -Module Microsoft.Graph.Authentication
#Requires -Module PwshSpectreConsole

using namespace System.IO

<#
.SYNOPSIS
Sets up an environment to run the integration tests with the optional
components not available in CI.

.DESCRIPTION
This script will setup an environment that can be used to test out the
components not normally testable in CI. So far this includes the Azure KeyVault
and Trusted Signing components.

The Key Vault will be created in a new resource group with a random name and
deleted after the script is done. The Key Vault will contain an RSA code
signing certificate and ECDSA code signing certificates for the P-256, P-256K,
P-384, and P-521 curves.

The script will scan for any Trusted Signing accounts and profiles in the
logged on environment and prompt if one should be used for the test. A
Trusted Signing account cannot be created as it requires manual identification
so an existing accounts can be used instead.

THe script will register an app and service principal and grant the required
roles needed to sign with the Key Vault and Trusted Signing accounts. The app
will be cleaned up after the script is done.

Once the environment is set up a new prompt is shown which can run the
integration tests or any manual test desired. Type in exit to exit the prompt
and clean up the resources.

.PARAMETER UseDeviceAuthentication
Use OAuth Device Authentication to authenticate with Azure.

.NOTES
This relies on the initial connection account having the required permissions
to create resource groups, vauls, and service principals.
#>
[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $UseDeviceAuthentication
)

$ErrorActionPreference = 'Stop'

$ScriptId = -join [char[]]((65..90) + (97..122) | Get-Random -Count 5)
Write-Host "Starting Setup with ScriptId: $ScriptId" -ForegroundColor Cyan
$context = Connect-AzAccount -UseDeviceAuthentication:$UseDeviceAuthentication | Select-Object -ExpandProperty Context
if (-not $context) {
    $context = Get-AzContext
}

Function Get-AzTrustedSigningAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $SubscriptionId
    )

    Write-Host "Retrieving Trusted Signing accounts" -ForegroundColor Cyan
    $getUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.CodeSigning/codeSigningAccounts?api-version=2024-02-05-preview"
    $raw = Invoke-AzRestMethod -Uri $getUri -ErrorAction Stop
    if ($raw.StatusCode -eq 200) {
        $raw.Content |
            ConvertFrom-Json |
            Select-Object -ExpandProperty value |
            Select-Object @(
                @{ N = 'Name'; E = { $_.name } }
                @{ N = 'Location'; E = { $_.location } }
                @{ N = 'ResourceId'; E = { $_.id } }
            )
    }
    else {
        $errorContent = $raw.Content | ConvertFrom-Json
        $msg = "Invoke-AzRestMethod failed to GET codeSigningAccounts ($($errorContent.error.code)): $($errorContent.error.message)"
        Write-Error -Message $msg
    }
}

Function Get-AzTrustedSigningAccountProfile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias("ResourceId")]
        [string]
        $AccountId,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]
        $Location
    )

    process {
        $name = Split-Path $AccountId -Leaf

        $getUri = "https://management.azure.com$AccountId/certificateProfiles?api-version=2024-02-05-preview"

        Write-Host "Retrieving Trusted Signing certificate profiles for '$name'" -ForegroundColor Cyan
        $raw = Invoke-AzRestMethod -Uri $getUri -ErrorAction Stop
        if ($raw.StatusCode -eq 200) {
            $raw.Content |
                ConvertFrom-Json |
                Select-Object -ExpandProperty value |
                Select-Object @(
                    @{ N = 'Name'; E = { $_.name } }
                    @{ N = 'AccountName'; E = { $name } }
                    @{ N = 'Location'; E = { $Location } }
                    @{ N = 'ProfileType'; E = { $_.properties.profileType } }
                    @{ N = 'Status'; E = { $_.properties.status } }
                    @{ N = 'CommonName'; E = { $_.properties.commonName } }
                    @{ N = 'Country'; E = { $_.properties.country } }
                    @{ N = 'State'; E = { $_.properties.state } }
                    @{ N = 'City'; E = { $_.properties.city } }
                    @{ N = 'Organization'; E = { $_.properties.organization } }
                    @{ N = 'ResourceId'; E = { $_.id } }
                )
        }
        else {
            $errorContent = $raw.Content | ConvertFrom-Json
            $msg = "Invoke-AzRestMethod failed to get codeSigningAccounts '$name' certificateProfiles ($($errorContent.error.code)): $($errorContent.error.message)"
            Write-Error -Message $msg
            return
        }
    }
}

Function New-AzKeyVaultCertificate {
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $VaultName,

        [Parameter(Mandatory)]
        [string]
        $KeyType,

        [Parameter()]
        [int]
        $KeySize,

        [Parameter()]
        [string]
        $Curve
    )

    $KeyId = "Test$KeyType"
    if ($Curve) {
        $KeyId = "$KeyId$Curve"
    }

    $keyPolicyParams = @{
        IssuerName = 'Self'
        SubjectName = "CN=OpenAuthenticode-$KeyId"
        KeyUsage = @('DigitalSignature')
        Ekus = @("1.3.6.1.5.5.7.3.3") # Code Signing
        ValidityInMonths = 1
        KeyType = $KeyType
        KeyNotExportable = $true
    }
    if ($KeySize) {
        $keyPolicyParams.KeySize = $KeySize
    }
    if ($Curve) {
        $keyPolicyParams.Curve = $Curve
    }

    $keyParams = @{
        Name = "$KeyId-$ScriptId"
        CertificatePolicy = New-AzKeyVaultCertificatePolicy @keyPolicyParams
        VaultName = $keyVault.VaultName
    }
    for ($i = 0; $i -lt 10; $i++) {
        try {
            $null = Add-AzKeyVaultCertificate @keyParams
            break
        }
        catch {
            # The role assignment from above may not have propagated yet, retry if it fails
            if ($i -lt 9 -and $_ -like '*Forbidden*') {
                Write-Host "Failed to create Key '$($keyParams.Name)': $_, retrying in 15 seconds" -ForegroundColor Yellow
                Start-Sleep -Seconds 15
                continue
            }
            throw
        }
    }

    $attempts = 0
    while ($true) {
        try {
            $status = Get-AzKeyVaultCertificateOperation -VaultName $keyVault.VaultName -Name $keyParams.Name
        }
        catch {
            # More RBAC propagation issues, try again.
            $attempts += 1
            if ($attempts -lt 5 -and $_ -like "*Forbidden*") {
                Write-Host "Failed to get Key status '$($keyParams.Name)': $_, retrying in 15 seconds" -ForegroundColor Yellow
                Start-Sleep -Seconds 15
                continue
            }
            throw
        }

        if ($status.Status -ne 'inProgress') {
            break
        }
    }

    $status.Name
}

Function New-AzRoleAndAssignment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter(Mandatory)]
        [string]
        $Description,

        [Parameter(Mandatory)]
        [string]
        $Scope,

        [Parameter()]
        [string]
        $ObjectId,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]
        $Actions = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]
        $DataActions = @()
    )

    $roleInfo = [Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition]@{
        Name = $Name
        Description = $Description
        IsCustom = $true
        Actions = $Actions
        DataActions = $DataActions
        AssignableScopes = @($Scope)
    }
    $roleDef = New-AzRoleDefinition -Role $roleInfo

    Write-Host "Assigning '$ObjectId' to '$($roleDef.Name)'" -ForegroundColor Cyan
    $roleParams = @{
        ObjectId = $ObjectId
        RoleDefinitionId = $roleDef.Id
        Scope = $Scope
    }
    for ($i = 0; $i -lt 10; $i++) {
        try {
            New-AzRoleAssignment @roleParams
            break
        }
        catch {
            # Getting weird conflict and propagation errors, check if it was created, otherwise retry.
            $roleAssignment = Get-AzRoleAssignment | Where-Object RoleDefinitionName -eq $roleParams.RoleDefinitionName
            if ($roleAssignment) {
                $roleAssignment
                break
            }
            elseif ($i -lt 9) {
                Write-Host "RBAC role definition not propagated yet: $_. Retrying in 30 seconds" -ForegroundColor Yellow
                Start-Sleep -Seconds 30
            }
            else {
                throw
            }
        }
    }
}

$originalEnvVars = [Environment]::GetEnvironmentVariables()
$app = $rg = $signingProfileRoleAssignment = $null
try {
    $resourceGroupParams = @{
        Name = "OpenAuthenticode-TestAzure-$ScriptId"
        Location = 'EastUS'
    }
    Write-Host "Creating Azure Resource Group '$($resourceGroupParams.Name)'" -ForegroundColor Cyan
    $rg = New-AzResourceGroup @resourceGroupParams

    $keyVaultParams = @{
        ResourceGroupName = $rg.ResourceGroupName
        VaultName = "TestVault-$ScriptId"
        Location = $rg.Location
        Sku = 'Standard'
        SoftDeleteRetentionInDays = 7
    }
    Write-Host "Creating Azure Key Vault '$($keyVaultParams.VaultName)'" -ForegroundColor Cyan
    $keyVault = New-AzKeyVault @keyVaultParams

    $keyVaultAdminParams = @{
        ObjectId = (Get-AzADUser -SignedIn).Id
        RoleDefinitionName = 'Key Vault Administrator'
        Scope = $keyVault.ResourceId
    }
    Write-Host "Assigning current user '$($keyVaultAdminParams.ObjectId)' as Key Vault Administrator" -ForegroundColor Cyan
    $null = New-AzRoleAssignment @keyVaultAdminParams

    Write-Host "Creating RSA Certificate" -ForegroundColor Cyan
    $rsaKey = New-AzKeyVaultCertificate -VaultName $keyVault.VaultName -KeyType 'RSA' -KeySize 4096

    Write-Host "Creating ECDSA P-256 Certificate" -ForegroundColor Cyan
    $ecdsaP256Key = New-AzKeyVaultCertificate -VaultName $keyVault.VaultName -KeyType 'EC' -Curve 'P-256'

    Write-Host "Creating ECDSA P-256K Certificate" -ForegroundColor Cyan
    $ecdsaP256KKey = New-AzKeyVaultCertificate -VaultName $keyVault.VaultName -KeyType 'EC' -Curve 'P-256K'

    Write-Host "Creating ECDSA P-384 Certificate" -ForegroundColor Cyan
    $ecdsaP384Key = New-AzKeyVaultCertificate -VaultName $keyVault.VaultName -KeyType 'EC' -Curve 'P-384'

    Write-Host "Creating ECDSA P-521 Certificate" -ForegroundColor Cyan
    $ecdsaP521Key = New-AzKeyVaultCertificate -VaultName $keyVault.VaultName -KeyType 'EC' -Curve 'P-521'

    # TrustedSigning doesn't have an official module and public API. Use this for now to
    # find any accounts and profiles to select for the test
    $selectedTrustedSigningProfile = $null
    try {
        $trustedSigningAccounts = Get-AzTrustedSigningAccount -SubscriptionId $context.Subscription.Id -ErrorAction Stop
        $trustedSigningProfiles = @(
            $trustedSigningAccounts |
                Get-AzTrustedSigningAccountProfile -ErrorAction Stop |
                Where-Object Status -eq Active
            )

        if ($trustedSigningProfiles) {
            $choices = @(
                foreach ($profile in $trustedSigningProfiles) {
                    "$($profile.Name) - Account '$($profile.AccountName)' - ProfileType '$($profile.ProfileType)' - CommonName '$($profile.CommonName)'"
                }
                "Skip"
            )
            $profileChoice = Read-SpectreSelection -Message "Select Trusted Signing Account" -Choices $choices -EnableSearch

            if ($profileChoice -ne "Skip") {
                $profileIdx = $choices.IndexOf($profileChoice)
                $selectedTrustedSigningProfile = $trustedSigningProfiles[$profileIdx]
                Write-Host "Selected Trusted Signing Profile '$($selectedTrustedSigningProfile.Name)'" -ForegroundColor Cyan
            }
        }
        else {
            Write-Host "No Trusted Signing profiles found" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Warning "Failed to retrieve list of Trusted Signing accounts: $_. Skipping TrustedSigning tests."
    }

    Write-Host "Connecting to Microsoft Graph" -ForegroundColor Cyan
    $graphToken = (Get-AzAccessToken -ResourceTypeName MSGraph -AsSecureString).Token
    $graphParams = @{
        AccessToken = $graphToken
        NoWelcome = $true
    }
    Connect-MgGraph @graphParams

    Write-Host "Creating Application and Service Principal" -ForegroundColor Cyan
    $app = New-MgApplication -DisplayName "OpenAuthenticode-TestApp"
    $sp = New-MgServicePrincipal -AppId $app.AppId

    Write-Host "Creating Application Password for '$($app.Id)'" -ForegroundColor Cyan
    $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
        DisplayName = "OpenAuthenticode-TestSecret"
        EndDateTime = (Get-Date).AddDays(1)
    }

    Write-Host "Creating Key Vault role definition" -ForegroundColor Cyan
    $keyVaultRoleParams = @{
        Name = "OpenAuthenticode Test KeyVault Signer - $ScriptId"
        Description = "Test role used by OpenAuthenticode to sign scripts using Get-OpenAuthenticodeAzKey provider"
        Scope = $keyVault.ResourceId
        ObjectId = $sp.Id
        DataActions = @(
            "Microsoft.KeyVault/vaults/certificates/read",
            "Microsoft.KeyVault/vaults/keys/sign/action"
        )
    }
    $null = New-AzRoleAndAssignment @keyVaultRoleParams

    if ($selectedTrustedSigningProfile) {
        $trustedRoleParams = @{
            Name = "OpenAuthenticode Test Trusted Signing Signer - $ScriptId"
            Description = "Test role used by OpenAuthenticode to sign scripts using Get-OpenAuthenticodeAzTrustedSigner provider"
            Scope = $selectedTrustedSigningProfile.ResourceId
            ObjectId = $sp.Id
            Actions = @(
                # The documented role 'Trusted Signing Certificate Profile Signer'
                # has these actions but they do not seem to be needed. This may change
                # in the future as this exits preview status so keep them commented in
                # case we need them later.
                # "Microsoft.CodeSigning/*/read"
                # "Microsoft.Authorization/*/read"
                # "Microsoft.Resources/deployments/*"
                # "Microsoft.Resources/subscriptions/resourceGroups/read"
            )
            DataActions = @(
                "Microsoft.CodeSigning/certificateProfiles/Sign/action"
            )
        }
        $signingProfileRoleAssignment = New-AzRoleAndAssignment @trustedRoleParams

        $env:AZURE_TRUSTED_SIGNER_ACCOUNT = $selectedTrustedSigningProfile.AccountName
        $env:AZURE_TRUSTED_SIGNER_PROFILE = $selectedTrustedSigningProfile.Name
        $env:AZURE_TRUSTED_SIGNER_ENDPOINT = $selectedTrustedSigningProfile.Location
    }

    $env:AZURE_TENANT_ID = $context.Tenant.Id
    $env:AZURE_CLIENT_ID = $app.AppId
    $env:AZURE_CLIENT_SECRET = $secret.SecretText
    $env:AZURE_TOKEN_SOURCE = 'Environment'

    $env:AZURE_KEYVAULT_NAME = $keyVault.VaultName
    $env:AZURE_KEYVAULT_RSA_CERTIFICATE = $rsaKey
    $env:AZURE_KEYVAULT_ECDSA_P256_CERTIFICATE = $ecdsaP256Key
    $env:AZURE_KEYVAULT_ECDSA_P256K_CERTIFICATE = $ecdsaP256KKey
    $env:AZURE_KEYVAULT_ECDSA_P384_CERTIFICATE = $ecdsaP384Key
    $env:AZURE_KEYVAULT_ECDSA_P521_CERTIFICATE = $ecdsaP521Key

    $msg = @(
        "Entering nested prompt with configured Azure environment."
        "`tSubscription: $($context.Subscription.Name) - $($context.Subscription.Id)"
        "`tTenantId: $($context.Tenant.Id)"
        "`tClient: $($app.DisplayName) - $($app.AppId)"
        "`tService Principal: $($sp.Id)"
        "`tScriptId: $ScriptId"
        "`tResource Group: $($rg.ResourceGroupName)"
        "`tKey Vault: $($keyVault.VaultName)"
        "`tRSA Certificate: $rsaKey"
        "`tECDSA P-256 Certificate: $ecdsaP256Key"
        "`tECDSA P-256K Certificate: $ecdsaP256KKey"
        "`tECDSA P-384 Certificate: $ecdsaP384Key"
        "`tECDSA P-521 Certificate: $ecdsaP521Key"
        if ($selectedTrustedSigningProfile) {
            "`tTrusted Signing Account: $($selectedTrustedSigningProfile.AccountName)"
            "`tTrusted Signing Profile: $($selectedTrustedSigningProfile.Name)"
        }
        else {
            "`tTrusted Signing: None"
        }
        "Type exit to exit prompt and cleanup test resources"
    ) -join ([Environment]::NewLine)
    Write-Host $msg -ForegroundColor Cyan
    $null = Push-Location -Path "$PSScriptRoot/.."
    try {
        $host.EnterNestedPrompt()
    }
    finally {
        $null = Pop-Location
    }
}
finally {
    if ($app) {
        Write-Host "Removing test Application" -ForegroundColor Cyan
        Remove-MgApplication -ApplicationId $app.Id
    }
    if ($rg) {
        Write-Host "Removing resource group" -ForegroundColor Cyan
        $null = $rg | Remove-AzResourceGroup -Force
    }
    if ($signingProfileRoleAssignment) {
        Write-Host "Removing Trusted Signing Certificate Profile Signer role assignment" -ForegroundColor Cyan
        $null = $signingProfileRoleAssignment | Remove-AzRoleAssignment
        Remove-AzRoleDefinition -Id $signingProfileRoleAssignment.RoleDefinitionId -Force
    }

    $env:AZURE_TENANT_ID = $originalEnvVars['AZURE_TENANT_ID']
    $env:AZURE_CLIENT_ID = $originalEnvVars['AZURE_CLIENT_ID']
    $env:AZURE_CLIENT_SECRET = $originalEnvVars['AZURE_CLIENT_SECRET']
    $env:AZURE_TOKEN_SOURCE = $originalEnvVars['AZURE_TOKEN_SOURCE']

    $env:AZURE_KEYVAULT_NAME = $originalEnvVars['AZURE_KEYVAULT_NAME']
    $env:AZURE_KEYVAULT_RSA_CERTIFICATE = $originalEnvVars['AZURE_KEYVAULT_RSA_CERTIFICATE']
    $env:AZURE_KEYVAULT_ECDSA_P256_CERTIFICATE = $originalEnvVars['AZURE_KEYVAULT_ECDSA_P256_CERTIFICATE']
    $env:AZURE_KEYVAULT_ECDSA_P256K_CERTIFICATE = $originalEnvVars['AZURE_KEYVAULT_ECDSA_P256K_CERTIFICATE']
    $env:AZURE_KEYVAULT_ECDSA_P384_CERTIFICATE = $originalEnvVars['AZURE_KEYVAULT_ECDSA_P384_CERTIFICATE']
    $env:AZURE_KEYVAULT_ECDSA_P521_CERTIFICATE = $originalEnvVars['AZURE_KEYVAULT_ECDSA_P521_CERTIFICATE']

    $env:AZURE_TRUSTED_SIGNER_ACCOUNT = $originalEnvVars['AZURE_TRUSTED_SIGNER_ACCOUNT']
    $env:AZURE_TRUSTED_SIGNER_PROFILE = $originalEnvVars['AZURE_TRUSTED_SIGNER_PROFILE']
    $env:AZURE_TRUSTED_SIGNER_ENDPOINT = $originalEnvVars['AZURE_TRUSTED_SIGNER_ENDPOINT']
}

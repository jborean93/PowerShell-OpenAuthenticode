# Authenticode Azure Trusted Signing
## about_AuthenticodeAzureTrustedSigning

# SHORT DESCRIPTION
OpenAuthenticode can use the Azure Trusted Signing service to sign files using a certificate profile stored in Azure.
These signing operations are based on a short lived certificate stored in Azure to generate an Authenticode signature used for code signing.
It sends the data that needs to be signed, typically a hash, to the Azure API and receives the signature back from that operation.
This guide will demonstrate how to easily set up an Azure App Principal through the Azure CLI that can be used for this operation.
It assumes that an Azure Trusted Signing account and certificate project has been setup and associated with a validated identity.
See [Trusted Signing overview](https://learn.microsoft.com/en-us/azure/trusted-signing/overview) for more information.

# LONG DESCRIPTION
Azure Trusted Signing is a cheap and easy way to setup a code signing certificate for Authenticode signing.
Unlike other code signing certificate, Azure Trusted Signing uses short lived certificate (72 hour validity) to sign the content.
This short lifetime of the certificate is a problem for PowerShell code signing at it relies on storing the certificate's thumbprint inside the `TrustedPublishers` store.
This means that practically every new release will require the end users to re-trust the certificate if the user has enabled code signing.
It can still be used for signing PowerShell content, as well as other Authenticode based files, but please keep in mind these limitations when it comes to PowerShell.
A future update to PowerShell may add a way to trust a developers unique EKU id value stored in Trusted Signing certificates to solve this problem.

The EKU OID used by Azure Trusted Signing starts with the prefix `1.3.6.1.4.1.311.97.` which can be used to uniquely identify a publisher across the various certificates.
The prefix `1.3.6.1.4.1.311.97.1.3.1.` and `1.3.6.1.4.1.311.97.1.4.1.` represent a private trust identity and private trust CI policy respectively.
See [Subscriber identity validation EKU](https://learn.microsoft.com/en-us/azure/trusted-signing/concept-trusted-signing-cert-management#subscriber-identity-validation-eku) for more information.

If you wish to extract the EKU for an Authenticode signed file before trusting it in PowerShell you can use the following code:

```powershell
Function Get-AzTrustedSigningEkuOid {
    [OutputType([PSObject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]
        $Path
    )

    begin {
        $ErrorActionPreference = 'Stop'

        $getCommand = if (Get-Command -Name Get-OpenAuthenticodeSignature -ErrorAction SilentlyContinue) {
            {
                (Get-OpenAuthenticodeSignature -LiteralPath $args[0] -SkipCertificateCheck).Certificate
            }
        }
        else {
            {
                (Get-AuthenticodeSignature -LiteralPath $args[0]).SignerCertificate
            }
        }

        $AzTrustedSignerOid = '1.3.6.1.4.1.311.97.1.0'
        $AzTrustedSignerOidPrefix = '1.3.6.1.4.1.311.97.'
    }

    process {
        foreach ($p in $Path) {
            $cert = & $getCommand $p

            $ekus = $cert.Extensions | Where-Object {
                $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
            } | Select-Object -First 1
            if (-not $ekus) {
                $err = [System.Management.Automation.ErrorRecord]::new(
                    [Exception]::new("Failed to find EKU extension in '$p' signature"),
                    "NoEkuFound",
                    "NotSpecified",
                    $p)
                $PSCmdlet.WriteError($err)
                return
            }

            $markerFound = $false
            $idOid = $ekus.EnhancedKeyUsages.Value | ForEach-Object -Process {
                if ($_ -eq $AzTrustedSignerOid) {
                    $markerFound = $true
                    return
                }

                if ($_ -like "${AzTrustedSignerOidPrefix}*") {
                    $_
                }
            } | Select-Object -First 1

            if (-not $markerFound) {
                $err = [System.Management.Automation.ErrorRecord]::new(
                    [Exception]::new("Failed to find Azure Trusted Signing EKU OID marker in '$p' signature"),
                    "NoAzureTrustedSigningOidMarkerFound",
                    "NotSpecified",
                    $p)
                $PSCmdlet.WriteError($err)
                return
            }
            if (-not $idOid) {
                $err = [System.Management.Automation.ErrorRecord]::new(
                    [Exception]::new("Failed to find Azure Trusted Signing EKU OID publisher in '$p' signature"),
                    "NoAzureTrustedSigningOidPublisherFound",
                    "NotSpecified",
                    $p)
                $PSCmdlet.WriteError($err)
                return
            }

            $isTrusted = $false
            if ($PSVersionTable.PSVersion -lt '6.0' -or $IsWindows) {
                $null = Get-ChildItem -LiteralPath Cert:\CurrentUser\TrustedPublisher | ForEach-Object -Process {
                    $ekus = $_.Extensions | Where-Object {
                        $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
                    } | ForEach-Object -Process {
                        $oids = $_.EnhancedKeyUsages.Value

                        if (($oids -contains $AzTrustedSignerOid) -and ($oids -contains $idOid)) {
                            $isTrusted = $true
                        }
                    }
                } | Select-Object -First 1
            }

            [PSCustomObject]@{
                Oid = $idOid
                IsTrusted = $isTrusted
                Certificate = $cert
            }
        }
    }
}
```

The `Oid` property is the Azure Trusted Signing EKU OID unique for the publisher.
The `IsTrusted` property is set to `$true` if that `Oid` is also present in an existing certificate stored in the `CurrentUser` or `LocalMachine` `TrustedPublisher` store.
This property can be used as a way to determine if the publisher has already been trusted before and whether to re-add the new certificate into the `TrustedPublisher` store or not.
For example this will add the certificate if the EKU OID is already trusted by another imported certificate.
It stores the cert into the `CurrentUser` `TrustedPublisher` store but it can be changed to `Cert:\LocalMachine\TrustedPublisher` to import it machine wide for all users.

```powershell
$certInfo = Get-AzTrustedSigningEkuOid -Path script.ps1

$storeName = "Cert:\CurrentUser\TrustedPublisher"
if ($certInfo.IsTrusted -and -not (Test-Path "$storeName\$($certInfo.Certificate.Thumbprint)")) {
    $store = Get-Item $storeName
    $store.Open('ReadWrite')
    $store.Add($certInfo.Certificate)
    $store.Dispose()
}
```

Because of the short lifespan of the certificate it should always be counter signed by a timestamp server.
Microsoft recommend using the server `http://timestamp.acs.microsoft.com` for this purpose and can be specified through the `-TimeStampServer` parameter.

To use a trusted signing profile we can create the key object from [Get-OpenAuthenticodeAzTrustedSigner](./Get-OpenAuthenticodeAzTrustedSigner.md) and use that object with the `-Key` parameter.

```powershell
# It is up to the caller to authenticate to Azure in whatever way they want.
# In this case it'll use Connect-AzAccount but other things you can use are
# the app client env vars or managed service identity.
Connect-AzAccount

$keyParams = @{
    AccountName = 'MySigningAccount'
    ProfileName = 'MyProfile'
    Endpoint    = 'EastUS'
}
$key = Get-OpenAuthenticodeAzTrustedSigning @keyParams

$signParams = @{
    Key             = $key
    TimeStampServer = 'http://timestamp.acs.microsoft.com'
    HashAlgorithm   = 'SHA256'
}
Set-OpenAuthenticodeSignature -FilePath $path @signParams
```

In this example we are authenticating to the Azure API with `Connect-AzAccount` which is one of the locations our Azure REST client will use for authentication.
From there we are retrieving a reference to the Azure Trusted Signing certificate profile to use for the signing operation.
The principal being authenticated must be assigned the role `'Trusted Signing Certificate Profile Signer'` on the certificate profile being used.
If you wish to define a custom role it must have the following `Actions` and `DataActions`:

```json
{
    "Actions": [],
    "DataActions": [
        "Microsoft.CodeSigning/certificateProfiles/Sign/action"
    ]
}
```

It can be scoped subscription wide, the resource group, the trusted signing account, or the certificate profile.

_Note: As of writing, Azure Trusted Signing is in preview so this may change if Microsoft adjust the backend._.

If using GitHub Actions it is possible to be able to use [Open ID Connect](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc) (`OIDC`) for authentication.
It is highly recommended to use `OIDC` when available as the client secret does not need to be stored in the repo.
GitHub will use `OIDC` to generate a short lived authentication token using the grants given to the service principal.
The following code can be used to add a federated credential that gives access to a GitHub Action workflow running on the `main` branch of the repo.
The app principal specified by `APP_NAME` still needs to have permissions to perform the signing operations.

```bash
# The name of the app principal to add the federated credential for
APP_NAME="..."

# The GitHub username the repo is in
GH_USER="..."

# The GitHub repo name for the user specified
GH_REPO="..."

# The GitHub repo branch to grant access to
GH_BRANCH="main"

OBJECT_ID="$(
    az ad app list \
        --display-name "${APP_NAME}" |
    jq -r '.[].id'
)"

az ad app federated-credential create \
    --id "${OBJECT_ID}" \
    --parameters @- << EOF
{
    "name": "OpenAuthenticode-${GH_USER}-${GH_REPO}-Branch-${GH_BRANCH}",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:${GH_USER}/${GH_REPO}:ref:refs/heads/${GH_BRANCH}",
    "description": "GitHub Actions OpenAuthenticode for git@github.com:${GH_USER}/${GH_REPO} refs/heads/${GH_BRANCH}",
    "audiences": [
        "api://AzureADTokenExchange"
    ]
}
EOF
```

It is possible to setup a federated credential with a tag, environment, or pull request, see [GitHub Actions federated identity](https://learn.microsoft.com/en-us/azure/active-directory/workload-identities/workload-identity-federation-create-trust?pivots=identity-wif-apps-methods-azp#github-actions) for more details.
There is currently a limit of 20 federated credentials per principal, simply create a new principal if this limit is reached.
Once the federated credential has been created it can be used in GitHub Actions like the following:

```yaml
...

jobs:
  build:
    name: build
    runs-on: ubuntu-latest
    permissions:
      # Needed for Azure OIDC authentication
      id-token: write
      # Needed to checkout repository
      contents: read

    steps:
    - name: Check out repository
      uses: actions/checkout@v3

    - name: OIDC Login to Azure
      if: github.ref == 'refs/heads/main'
      uses: azure/login@v1
      with:
        client-id: ${{ secrets.AZURE_CLIENT_ID }}
        tenant-id: ${{ secrets.AZURE_TENANT_ID }}
        subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

    - name: Sign module
      if: github.ref == 'refs/heads/main'
      shell: pwsh
      run: |
        Install-Module -Name OpenAuthenticode -Force
        Import-Module OpenAuthenticode

        $keyParams = @{
            VaultName = '${{ secrets.AZURE_VAULT_NAME }}'
            Certificate = '${{ secrets.AZURE_VAULT_CERT_NAME }}'
            AccountName = '${{ secrets.AZURE_TS_NAME }}'
            ProfileName = '${{ secrets.AZURE_TS_PROFILE }}'
            Endpoint    = '${{ secrets.AZURE_TS_ENDPOINT }}'
        }
        $key = Get-OpenAuthenticodeAzTrustedSigning @keyParams

        $signParams = @{
            Key             = $key
            TimeStampServer = 'http://timestamp.acs.microsoft.com'
            HashAlgorithm   = 'SHA256'
        }
        Set-OpenAuthenticodeSignature @signParams -FilePath '...'
...
```

The claim generated ensures only runs for commits to the `main` branch of that repo can authenticate with Azure.
See [TestAzureCodeOIDC](https://github.com/jborean93/TestAzureCodeOIDC) for a full example of how it can be integrated.

If the [Az.Accounts](https://www.powershellgallery.com/packages/Az.Accounts/) module is installed it can be used to authenticate with Azure using the parameters it exposes.
Once authenticated, the `Get-OpenAuthenticodeAzTrustedSigner` cmdlet will reuse that authenticated context when retrieving the key.

```powershell
$connectParams = @{
    TenantId = '...'
    ServicePrincipal = $true
    Credential = '..'
}
Connect-AzAccount @connectParams

$keyParams = @{
    AccountName = 'MySigningAccount'
    ProfileName = 'MyProfile'
    Endpoint    = 'EastUS'
}
$key = Get-OpenAuthenticodeAzTrustedSigning @keyParams

$signParams = @{
    Key             = $key
    TimeStampServer = 'http://timestamp.acs.microsoft.com'
    HashAlgorithm   = 'SHA256'
}
Set-OpenAuthenticodeSignature -FilePath $path @signParams
```

Because DefaultAzureCredential authenticates in a [pre-defined order](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet) `Get-OpenAuthenticodeAzKey` may not use the expected authentication method if others are available.
For example if a managed identity is configured on the compute resource, it will take priority over Az CLI and Azure PowerShell.

This behaviour can be overwritten with the `-TokenSource` parameter of [Get-OpenAuthenticodeAzKey](./Get-OpenAuthenticodeAzKey.md).

```powershell
$keyParams = @{
    AccountName = 'MySigningAccount'
    ProfileName = 'MyProfile'
    Endpoint    = 'EastUS'
    TokenSource = 'AzurePowerhell'
}
$key = Get-OpenAuthenticodeAzTrustedSigning @keyParams
```

# Authenticode Azure Keys
## about_AuthenticodeAzureKeys

# SHORT DESCRIPTION
OpenAuthenticode can use an Azure KeyVault certificate and key to sign data without having the key leave the vault.
It sends the data that needs to be signed, typically a hash, to the Azure API and receives the signature back from that operation.
This guide will demonstrate how to easily set up an Azure App Principal through the Azure CLI that can be used for this operation.
It assumes that an Azure KeyVault and signing certificate has already been created/imported.

# LONG DESCRIPTION
The following is a bash script that can be used to generate an Azure App Principal that can be used with [Get-OpenAuthenticodeAzKey](./Get-OpenAuthenticodeAzKey.md) to sign files.
The `APP_NAME`, `RESOURCE_GROUP`, `VAULT_NAME`, and `VAULT_CERT` variables need to be prefilled before running the code.
It also requires the Azure CLI to be installed, otherwise run this in `docker run -it mcr.microsoft.com/azure-cli` where the cli is already available.

```bash
# The name of the app principal granted access
APP_NAME="..."

# The name of the resource group the vault is stored in
RESOURCE_GROUP="..."

# The name of the Azure KeyVault.
VAULT_NAME="..."

# The name of the certificate in the above vault to use for signing
VAULT_CERT="..."

ROLE_NAME="KeyVault PowerShell-OpenAuthenticode"

SUBSCRIPTION_ID="$( az login | jq -r '.[].id' )"

ROLE_INFO="$(
    az role definition list \
        --name "${ROLE_NAME}" \
        --custom-role-only \
        --resource-group "${RESOURCE_GROUP}"
)"

if [ "${ROLE_INFO}" == "[]" ]; then
    ROLE_DEF="$(cat << EOF
{
    "Name": "${ROLE_NAME}",
    "Description": "Allow access to a cert for Authenticode signing with PowerShell-OpenAuthenticode.",
    "Actions": [],
    "DataActions": [
        "Microsoft.KeyVault/vaults/certificates/read",
        "Microsoft.KeyVault/vaults/keys/sign/action"
    ],
    "NotDataActions": [],
    "AssignableScopes": ["/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}"]
}
EOF
)"

    ROLE_INFO="$(
        az role definition create \
            --role-definition "${ROLE_DEF}"
    )"
    ROLE_ID="$(
        echo "${ROLE_INFO}" |
        jq -r '.name'
    )"
else
    ROLE_ID="$(
        echo "${ROLE_INFO}" |
        jq -r '.[].name'
    )"
fi

PRINCIPAL_INFO="$(
    az ad sp create-for-rbac \
        --name "${APP_NAME}"
)"

AZURE_CREDENTIALS="$(
    echo "${PRINCIPAL_INFO}" |
    jq -r "{AZURE_CLIENT_ID: .appId, AZURE_CLIENT_SECRET: .password, AZURE_TENANT_ID: .tenant, AZURE_SUBSCRIPTION_ID: \"${SUBSCRIPTION_ID}\", AZURE_VAULT_NAME: \"${VAULT_NAME}\", AZURE_VAULT_CERT: \"${VAULT_CERT}\"}"
)"
CLIENT_ID="$(
    echo "${PRINCIPAL_INFO}" |
    jq -r '.appId'
)"

az role assignment create \
    --assignee "${CLIENT_ID}" \
    --role "${ROLE_ID}" \
    --scope "/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.KeyVault/vaults/${VAULT_NAME}" > /dev/null

echo "These details should be saved as a secret where needed"
echo "${AZURE_CREDENTIALS}"
```

The resulting json contains all the information needed to sign files using OpenAuthenticode.

```powershell
# AZURE_CREDENTIALS contains the json from the above script
$credInfo = ConvertFrom-Json -InputObject $env:AZURE_CREDENTIALS
$vaultName = $credInfo.AZURE_VAULT_NAME
$vaultCert = $credInfo.AZURE_VAULT_CERT

$env:AZURE_CLIENT_ID = $credInfo.AZURE_CLIENT_ID
$env:AZURE_CLIENT_SECRET = $credInfo.AZURE_CLIENT_SECRET
$env:AZURE_TENANT_ID = $credInfo.AZURE_TENANT_ID
$key = Get-OpenAuthenticodeAzKey -Vault $vaultName -Certificate $vaultCert
$env:AZURE_CLIENT_ID = ''
$env:AZURE_CLIENT_SECRET = ''
$env:AZURE_TENANT_ID = ''

$signParams = @{
    Key = $key
    TimeStampServer = 'http://timestamp.digicert.com'
    HashAlgorithm = 'SHA256'
}
Set-OpenAuthenticodeSignature -FilePath $path @signParams
```

In this example the output json from the bash script has been stored in the environment variable `AZURE_CREDENTIALS`.
Ensure the credentials json is stored securely so that it cannot be used for any unauthorised signing operations.

If using GitHub Actions it is possible to not need the `AZURE_CLIENT_SECRET` and use [Open ID Connect](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc) (`OIDC`) for authentication.
It is highly recommended to use `OIDC` when available as the client secret does not need to be stored in the repo.
GitHub will use `OIDC` to generate a short lived authentication token using the grants given to the service principal.
The following code can be used to add a federated credential that gives access to a GitHub Action workflow running on the `main` branch of the repo.

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
        }
        $key = Get-OpenAuthenticodeAzKey @keyParams

        $signParams = @{
            Key = $key
            TimeStampServer = 'http://timestamp.digicert.com'
            Verbose = $true
        }
        Set-OpenAuthenticodeSignature @signParams -FilePath '...'
...
```

The claim generated ensures only runs for commits to the `main` branch of that repo can authenticate with Azure.
See [TestAzureCodeOIDC](https://github.com/jborean93/TestAzureCodeOIDC) for a full example of how it can be integrated.

If the [Az.Accounts](https://www.powershellgallery.com/packages/Az.Accounts/) module is installed it can be used to authenticate with Azure using the parameters it exposes.
Once authenticated the `Get-OpenAuthenticodeAzKey` cmdlet will reuse that authenticated context when retrieving the key.

```powershell
$credInfo = ConvertFrom-Json -InputObject $env:AZURE_CREDENTIALS
$vaultName = $credInfo.AZURE_VAULT_NAME
$vaultCert = $credInfo.AZURE_VAULT_CERT
$cred = ... # Left up to the reader to build

$connectParams = @{
    TenantId = $credInfo.AZURE_VAULT_TENANT_ID
    ServicePrincipal = $true
    Credential = $cred
}
Connect-AzAccount @connectParams

$key = Get-OpenAuthenticodeAzKey -Vault $vaultName -Certificate $vaultCert
$signParams = @{
    Key = $key
    TimeStampServer = 'http://timestamp.digicert.com'
    HashAlgorithm = 'SHA256'
}
Set-OpenAuthenticodeSignature -FilePath $path @signParams
```

Because DefaultAzureCredential authenticates in a [pre-defined order](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet) `Get-OpenAuthenticodeAzKey` may not use the expected authentication method if others are available. For example if a managed identity is configured on the compute resource, it will take priority over Az CLI and Azure PowerShell.

This behaviour can be overwritten with the `TokenSource` parameter of [Get-OpenAuthenticodeAzKey](./Get-OpenAuthenticodeAzKey.md).

```powershell
$key = Get-OpenAuthenticodeAzKey -Vault $vaultName -Certificate $vaultCert -TokenSource AzurePowerShell
```

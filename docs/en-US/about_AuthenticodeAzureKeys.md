# Authenticode Azure Keys
## about_AuthenticodeAzureKeys

# SHORT DESCRIPTION
OpenAuthenticode can use an Azure KeyVault certificate and key to sign data without having the key leave the vault.
It sends the data that needs to be signed, typically a hash, to the Azure API and receives the signature back from that operation.
This guide will demonstrate how to easily set up an Azure App Principal through the Azure CLI that can be used for this operation.
It assumes that an Azure KeyVault and signing certificate has already been created/imported.

# LONG DESCRIPTION
The following is a bash script that can be used to generate an Azure App Principal that can be used with [Get-OpenAuthenticodeAzKey](./Get-OpenAuthenticodeAzKey.md) to sign files.
The `APP_NAME`, `RESOURCE_GROUP`, and `VAULT_NAME` variables need to be prefilled before running the code.
It also requires the Azure CLI to be installed, otherwise run this in `docker run -it mcr.microsoft.com/azure-cli` where the cli is already available.

```bash
# The name of the app principal granted access
APP_NAME="..."

# The name of the resource group the vault is stored in
RESOURCE_GROUP="..."

# The name of the Azure KeyVault.
VAULT_NAME="..."

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
fi

ROLE_ID="$(
    echo "${ROLE_INFO}" |
    jq -r '.name'
)"

PRINCIPAL_INFO="$(
    az ad sp create-for-rbac \
    --name "${APP_NAME}" \
)"

AZURE_CREDENTIALS="$(
    echo "${PRINCIPAL_INFO}" |
    jq -r '{clientId: .appId, clientSecret: .password, tenantId: .tenant}'
)"
CLIENT_ID="$(
    echo "${PRINCIPAL_INFO}" |
    jq -r '.appId'
)"

az role assignment create \
    --assignee "${CLIENT_ID}" \
    --role "${ROLE_ID}" \
    --scope "/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.KeyVault/vaults/${VAULT_NAME}" > /dev/null

echo "Save this json as your GitHub Actions secret"
echo "${AZURE_CREDENTIALS}"
```

The resulting json contains the principal id and secret that can be used in the following PowerShell script to get the key and sign the files as required.

```powershell
# These are specific to your vault and certificate name.
$vaultName = '...'
$certName = '...'

# This should read the secret from the env var
# AZURE_CREDENTIALS.
$azPrincipal = ConvertFrom-Json -InputObject $env:AZURE_CREDENTIALS
$env:AZURE_CLIENT_ID = $azPrincipal.clientId
$env:AZURE_TENANT_ID = $azPrincipal.tenantId
$env:AZURE_CLIENT_SECRET = $azPrincipal.clientSecret

$key = Get-OpenAuthenticodeAzKey -Vault $vaultName -Certificate $certName
Set-OpenAuthenticodeSignature -Key $key -FilePath $path
```

In this example the output json from the bash script has been stored in the environment variable `AZURE_CREDENTIALS` and the `$vaultName` and `$certName` relate to the vault and the certificate in that vault that will be used to sign the files.
Ensure the credentials json is stored securely so that it cannot be used for any unauthorised signing operations.

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
    --name "${APP_NAME}" \
)"

AZURE_CREDENTIALS="$(
    echo "${PRINCIPAL_INFO}" |
    jq -r "{clientId: .appId, clientSecret: .password, tenantId: .tenant, vaultName: \"${VAULT_NAME}\", vaultCert: \"${VAULT_CERT}\"}"
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

The resulting json contains all the information needed to sign files using OpenAuthenticode.

```powershell
# AZURE_CREDENTIALS contains the json from the above script
$credInfo = ConvertFrom-Json -InputObject $env:AZURE_CREDENTIALS
$vaultName = $credInfo.vaultName
$vaultCert = $credInfo.vaultCert

$env:AZURE_CLIENT_ID = $credInfo.clientId
$env:AZURE_CLIENT_SECRET = $credInfo.clientSecret
$env:AZURE_TENANT_ID = $credInfo.tenantId
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

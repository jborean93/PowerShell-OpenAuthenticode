---
external help file: OpenAuthenticode.Module.dll-Help.xml
Module Name: OpenAuthenticode
online version: https://www.github.com/jborean93/PowerShell-OpenAuthenticode/blob/main/docs/en-US/Get-OpenAuthenticodeAzKey.md
schema: 2.0.0
---

# Get-OpenAuthenticodeAzKey

## SYNOPSIS
Get an Azure KeyVault certificate and key for use with Authenticode signing.

## SYNTAX

```
Get-OpenAuthenticodeAzKey [-Vault] <String> [-Certificate] <String> [<CommonParameters>]
```

## DESCRIPTION
Gets the Azure keyVault certificate and key from the vault and key name specified.
This key can be used with [Set-OpenAuthenticodeSignature](./Set-OpenAuthenticodeSignature.md) to sign a file without having to download the key locally.
The authenticated Azure principal must have the following Azure access policy permissions on the requested key:

* Key Permissions: `Sign`
* Certificate Permissions: `Get`

The signing workflow does not require the key to be present on the local machine as it calls the Azure `Sign` API with the Authenticode digest.
This ensures the key does not leave Azure itself but rather Azure is used to sign the data remotely.

Currently only certificates signed with an RSA can be used, ECDSA support is planned for the future.
The certificate must also have the Key Usage of `Digital Signature (80)` and Enhanced Key Usage `Code Signing (1.3.6.1.5.5.7.3.3)` for it to be used with Authenticode.

Currently authentication relies on the lookup behaviour of [DefaultAzureCredential](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/identity-readme?view=azure-dotnet).
It will lookup environment variables, device managed identities, az cli contexts, etc to authenticate with Azure.
It has not been set to allow for interactive authentication through the web browser.

See [about_AuthenticodeAzureKeys](./about_AuthenticodeAzureKeys.md) for more information on how a key can be used to sign files.

## EXAMPLES

### Example 1: Get key for use with signing
```powershell
PS C:\> $key = Get-OpenAuthenticodeAzKey -Vault code-signing-test -Certificate Authenticode
PS C:\> Set-AuthenticodeSignature test.ps1 -Key $key
```

Gets the Azure KeyVault key `Authenticode` in the vault `code-signing-test` and uses it to sign the file `test.ps1`.
This does not include any pre-requisite steps for setting up the authentication details used by `Get-OpenAuthenticodeAzKey`.

## PARAMETERS

### -Certificate
The name of the Azure KeyVault certificate/key to retrieve.

```yaml
Type: String
Parameter Sets: (All)
Aliases: CertificateName

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Vault
The name of the Azure KeyVault to find the certificate in.

```yaml
Type: String
Parameter Sets: (All)
Aliases: VaultName

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
None

## OUTPUTS

### OpenAuthenticode.Shared.AzureKey
The AzureKey object that can be used with the `-Key` parameter in `Set-OpenAuthenticodeSignature`.

## NOTES

## RELATED LINKS

[Azure Key Vault](https://azure.microsoft.com/en-au/products/key-vault/)
[DefaultAzureCredential Workflow](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/identity-readme?view=azure-dotnet)

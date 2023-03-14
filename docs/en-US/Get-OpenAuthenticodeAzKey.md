---
external help file: OpenAuthenticode.dll-Help.xml
Module Name: OpenAuthenticode
online version: https://www.github.com/jborean93/PowerShell-OpenAuthenticode/blob/main/docs/en-US/Get-OpenAuthenticodeAzKey.md
schema: 2.0.0
---

# Get-OpenAuthenticodeAzKey

## SYNOPSIS
Get the Azure KeyVault certificate and key for use with Authenticode signing.

## SYNTAX

```
Get-OpenAuthenticodeAzKey [-Vault] <String> [-Key] <String> [<CommonParameters>]
```

## DESCRIPTION
Gets an Azure KeyVault certificate and key to use with signing a file with Authenticode.
The principal used to get the key must have the following access permissions on the key:

* Key Permissions: `Sign`
* Certificate Permissions: `Get`

## EXAMPLES

### Example 1
```powershell
PS C:\> $key = Get-OpenAuthenticodeAzKey -Vault code-signing-test -Key Authenticode
PS C:\> Set-AuthenticodeSignature test.ps1 -AzureKey $key
```

Signs the file `test.ps1` with the Azure KeyVault key `Authenticode` in the vault `code-signing-test`.

## PARAMETERS

### -Key
The name of the Azure KeyVault certificate to retrieve.

```yaml
Type: String
Parameter Sets: (All)
Aliases: KeyName

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
## OUTPUTS

### OpenAuthenticode.AzureKey
The AzureKey object that can be used with the `-AzureKey` parameter in `Set-OpenAuthenticodeSignature`.

## NOTES

## RELATED LINKS

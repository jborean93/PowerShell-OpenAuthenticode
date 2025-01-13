---
external help file: OpenAuthenticode.Module.dll-Help.xml
Module Name: OpenAuthenticode
online version: https://www.github.com/jborean93/PowerShell-OpenAuthenticode/blob/main/docs/en-US/Get-OpenAuthenticodeAzTrustedSigner.md
schema: 2.0.0
---

# Get-OpenAuthenticodeAzTrustedSigner

## SYNOPSIS
Gets an Azure Trusted Signer key for use with Authenticode signing.

## SYNTAX

```
Get-OpenAuthenticodeAzTrustedSigner [-AccountName] <String> [-ProfileName] <String> [-Endpoint] <Uri>
 [-CorrelationId <String>] [-TokenSource <AzureTokenSource>] [-ProgressAction <ActionPreference>]
 [<CommonParameters>]
```

## DESCRIPTION
Gets an Azure Trusted Signer key from the profile and signing account name specified.
This key can be used with [Set-OpenAuthenticodeSignature](./Set-OpenAuthenticodeSignature.md) to sign a file using the [Azure Trusted Signing service](https://learn.microsoft.com/en-us/azure/trusted-signing/overview).

The authenticated Azure principal must have the following Azure access policy permissions on the requested profile certificate profile:

* action - `Microsoft.CodeSigning/*/read`
* data action - `Microsoft.CodeSigning/certificateProfiles/Sign/action`

The `Trusted Signing Certificate Profile Signer` role includes these permissions.

The Trusted Signing service from Azure is a convenient and cheap way for developers to sign their content using a short lived ephemeral certificate that is linked to either a verified public or private identity.

By default authentication relies on the lookup behaviour of [DefaultAzureCredential](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/identity-readme?view=azure-dotnet).
It will lookup environment variables, device managed identities, az cli contexts, etc to authenticate with Azure.
If the [Az.Accounts](https://www.powershellgallery.com/packages/Az.Accounts/) PowerShell module has been installed, the [Connect-AzAccount](https://learn.microsoft.com/en-us/powershell/module/az.accounts/connect-azaccount?view=azps-10.2.0) cmdlet can be used to authenticate the session before this cmdlet is called.
It has not been set to allow for interactive authentication through the web browser.
The `-TokenSource` parameter can be used to specify different a different authentication method.

See [about_AuthenticodeAzureTrustedSigning](./about_AuthenticodeAzureTrustedSigning.md) for more information on how a key can be used to sign files.

## EXAMPLES

### Example 1: Get key from East US endpoint
```powershell
PS C:\> $keyParams = @{
    ProfileName = 'MyProfile'
    AccountName = 'MyAccount'
    Endpoint = 'EastUS'
}
PS C:\> $key = Get-OpenAuthenticodeAzTrustedSigner @keyParams
PS C:\> Set-AuthenticodeSignature test.ps1 -Key $key
```

Gets the Azure Trusted Signing key for the certificate profile `MyProfile` in the code signing account `MyAccount` and uses it to sign the file `test.ps1`
This does not include any pre-requisite steps for setting up the authentication details used by this cmdlet.

## PARAMETERS

### -AccountName
The code signing account name that must exist in the `-Endpoint` location specified.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CorrelationId
A string value to associate with the sign requests for future correlation.
Support for the `-CorrelationId` may be dependent on the `-Endpoint` location specified.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Endpoint
The Azure endpoint URL that the code signing account is located in.
This can either by Azure URL value like `https://eus.codesigning.azure.net` or one of the human friendly names below:

* `EastUS` - `https://eus.codesigning.azure.net`
* `WestCentralUS` - `https://wcus.codesigning.azure.net`
* `WestUS2` - `https://wus2.codesigning.azure.net`
* `WestUS3` - `https://wus3.codesigning.azure.net`
* `NorthEurope` - `https://neu.codesigning.azure.net`
* `WestEurope` - `https://weu.codesigning.azure.net`

This parameter supports tab completion with the known values listed above.

```yaml
Type: Uri
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProfileName
The name of the Azure Trusted Signing certificate profile.
This profile must exist inside the code signing account specified by `-AccountName`.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
New common parameter introduced in PowerShell 7.4.

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TokenSource
The authentication method used.

Supported sources include:
* Default - [DefaultAzureCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet)
* Environment - [EnvironmentCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential?view=azure-dotnet)
* AzurePowerShell - [AzurePowerShellCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.azurepowershellcredential?view=azure-dotnet)
* AzureCli - [AzureCliCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.azureclicredential?view=azure-dotnet)
* ManagedIdentity - [ManagedIdentityCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.managedidentitycredential?view=azure-dotnet)

```yaml
Type: AzureTokenSource
Parameter Sets: (All)
Aliases:
Accepted values: Default, Environment, AzurePowerShell, AzureCli, ManagedIdentity

Required: False
Position: Named
Default value: Default
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
None

## OUTPUTS

### OpenAuthenticode.Module.AzureTrustedSigner
The AzureTrustedSigner key object that can be used with the `-Key` parameter in `Set-OpenAuthenticodeSignature`.

## NOTES
As Trusted Signing uses ephemeral keys, signed PowerShell scripts using this key provider may not a viable option for people distribution modules publicly.
This is because PowerShell also checks that the certificate's thumbprint is present in the `TrustedPeople` store which means every update would require the user to trust the certificate again.

## RELATED LINKS

[Azure Trusted Signing Overview](https://learn.microsoft.com/en-us/azure/trusted-signing/overview)

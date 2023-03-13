---
external help file: OpenAuthenticode.dll-Help.xml
Module Name: OpenAuthenticode
online version: https://www.github.com/jborean93/PowerShell-OpenAuthenticode/blob/main/docs/en-US/Set-OpenAuthenticodeSignature.md
schema: 2.0.0
---

# Set-OpenAuthenticodeSignature

## SYNOPSIS
Set an authenticode signature on a file.

## SYNTAX

```
Set-OpenAuthenticodeSignature [-Path] <String[]> -Certificate <X509Certificate2>
 [-HashAlgorithm <HashAlgorithmName>] [-IncludeOption <X509IncludeOption>] [-TimestampServer <String>]
 [-TimestampHashAlgorithm <HashAlgorithmName>] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet can sign the file provided with an Authenticode signature.

## EXAMPLES

### Example 1 - Signs a PowerShell ps1 script
```powershell
PS C:\> $pass = Read-Host -AsSecureString -Prompt "Enter pfx password"
PS C:\> $cert = Get-PfxCertificate -FilePath ~/code-signing.pfx -Password $pass
PS C:\> Set-OpenAuthenticodeSignature -Path test.ps1 -Certificate $cert
```

Signs the script `test.ps1` with the certificate specified.

### Example 2 - Signs a PowerShell ps1 script and a counter signature timestamp
```powershell
PS C:\> $pass = Read-Host -AsSecureString -Prompt "Enter pfx password"
PS C:\> $cert = Get-PfxCertificate -FilePath ~/code-signing.pfx -Password $pass
PS C:\> Set-OpenAuthenticodeSignature -Path test.ps1 -Certificate $cert -TimestampServer http://timestamp.digicert.com
```

Like example 1 but also adds a counter signature with the Digicert timestamp server.

## PARAMETERS

### -Certificate
The certificate used to sign the files specified.

```yaml
Type: X509Certificate2
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -HashAlgorithm
The hashing algorithm to use when generating the Authenticode signature.
This defaults to SHA256 if not specified.

```yaml
Type: HashAlgorithmName
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncludeOption
Determines which certificates in the certificate trust chain are included in the digital signature.
Defauls to `ExcludeRoot`.

```yaml
Type: X509IncludeOption
Parameter Sets: (All)
Aliases:
Accepted values: None, ExcludeRoot, EndCertOnly, WholeChain

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Path
The path to the files to sign.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: FilePath

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -TimestampHashAlgorithm
The hashing algorithm used in the counter signature timestamp if `-TimestampServer` was specified.
This defaults to the value of `-HashAlgorithm` if not specified.

```yaml
Type: HashAlgorithmName
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TimestampServer
The timestamp server used to counter sign the Authenticode signature.
The time stamp represents the exact time the certificate was added to the file.
A time stamp prevents the signature from being invalidated once the certificate has expired.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String[]
## OUTPUTS

### None

None

## NOTES

## RELATED LINKS

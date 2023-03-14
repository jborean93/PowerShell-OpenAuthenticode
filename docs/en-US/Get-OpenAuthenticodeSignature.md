---
external help file: OpenAuthenticode.dll-Help.xml
Module Name: OpenAuthenticode
online version: https://www.github.com/jborean93/PowerShell-OpenAuthenticode/blob/main/docs/en-US/Get-OpenAuthenticodeSignature.md
schema: 2.0.0
---

# Get-OpenAuthenticodeSignature

## SYNOPSIS
Get an authenticode signature of a file.

## SYNTAX

```
Get-OpenAuthenticodeSignature [-Path] <String[]> [-SkipCertificateCheck] [<CommonParameters>]
```

## DESCRIPTION
Gets the Authenticode signature information from the path specified.
This information includes the certificate that signed the file, the hash algorithm used, and the timestamp countersignature information if it was used.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-OpenAuthenticodeSignature -Path test.ps1
```

Gets the Authenticode signature information from the PowerShell script `test.ps1`.

## PARAMETERS

### -Path
The path to the files to retrieve the Authenticode information for.

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

### -SkipCertificateCheck
Do not validate the certificate that signed the file with the normal CA trust validation.
When setting this switch, only the signature itself is validated.

```yaml
Type: SwitchParameter
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
Accepts a list of paths for the `-Path` parameter.

## OUTPUTS

### System.Security.Cryptography.Pkcs.SignedCms / OpenAuthenticode.AuthenticodeSignature
The Authenticode signature details from the path specified if it was signed. This object has the following extra properties added as part of the extended type data of `OpenAuthenticode.AuthenticodeSignature`:

+ `Path`: The file path that this signature is for

+ `Certificate`: The X.509 certificate that signed the file

+ `HashAlgorithm`: The hash algorithm that was used in the Authenticode signature

+ `TimeStampInfo`: Information about the counter signature timestamp including its certificate, timestamp date in UTC, and timestamp hashing algorithm

## NOTES
Unlike [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature?view=powershell-7.3) this cmdlet will write an error if there is a Authenticode signature validation problem.
The error should contain the details on what went wrong.

## RELATED LINKS

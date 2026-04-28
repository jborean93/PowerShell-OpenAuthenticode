---
external help file: OpenAuthenticode.dll-Help.xml
Module Name: OpenAuthenticode
online version: https://www.github.com/jborean93/PowerShell-OpenAuthenticode/blob/main/docs/en-US/Get-OpenAuthenticodeSignature.md
schema: 2.0.0
---

# Get-OpenAuthenticodeSignature

## SYNOPSIS
Gets information about the Authenticode signature for a file.

## SYNTAX

### Path (Default)
```
Get-OpenAuthenticodeSignature [-Path] <String[]> [-SkipCertificateCheck]
 [-TrustStore <X509Certificate2Collection>] [-Provider <AuthenticodeProvider>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### LiteralPath
```
Get-OpenAuthenticodeSignature -LiteralPath <String[]> [-SkipCertificateCheck]
 [-TrustStore <X509Certificate2Collection>] [-Provider <AuthenticodeProvider>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### Stream
```
Get-OpenAuthenticodeSignature -Stream <Stream> [-SkipCertificateCheck]
 [-TrustStore <X509Certificate2Collection>] [-Provider <AuthenticodeProvider>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Gets the Authenticode signature information from the path or stream specified.
This information includes the certificate that signed the file, the hash algorithm used, and the timestamp countersignature information if it was used.
An error record is written if the path specified does not have an authenticode signature present.

See [about_AuthenticodeProviders](./about_AuthenticodeProviders.md) for more information about what providers are currently supported.
When using a file path that has no extension, an explicit `-Provider` must be specified to indicate what Authenticode provider needs to be used to retrieve and validate the signature.

It is also possible to provide a stream to validate using the `-Stream` parameter which accepts any readable and seekable stream object.
When using `-Stream`, the `-Provider` parameter must be specified to indicate what Authenticode provider to use.

If a file has multiple signatures embedded, each signature and their hash algorithm will be output as their own objects.
For example a file signed with the SHA1 hash and SHA256 hash will output 2 objects.

## EXAMPLES

### Example 1: Get the Authenticode signature for a file
```powershell
PS C:\> Get-OpenAuthenticodeSignature -Path test.ps1
```

Gets the Authenticode signature information from the PowerShell script `test.ps1`.

### Example 2: Get the Authenticode signature for multiple files
```powershell
PS C:\> Get-OpenAuthenticodeSignature -Path file1.ps1, signed.ps1
```

Gets the Authenticode signature information for multiple PowerShell script files.

### Example 3: Get the Authenticode signature for a file without an extension
```powershell
PS C:\> Get-OpenAuthenticodeSignature -Path hook -Provider PowerShell
```

Gets the Authenticode signature for a PowerShell script without a file extension.

### Example 4: Get the Authenticode signature from a stream
```powershell
PS C:\> $bytes = [System.IO.File]::ReadAllBytes("script.ps1")
PS C:\> $stream = [System.IO.MemoryStream]::new($bytes)
PS C:\> try {
>>     Get-OpenAuthenticodeSignature -Stream $stream -Provider PowerShell
>> } finally {
>>     $stream.Dispose()
>> }
```

Gets the Authenticode signature for a PowerShell script from a MemoryStream.
The stream must be readable and seekable, and the `-Provider` parameter must be specified.

## PARAMETERS

### -LiteralPath
Specifies the path to the files to extract the Authenticode signature from.
Unlike `-Path`, the path is used exactly as it is typed, no wildcard matching will occur.

```yaml
Type: String[]
Parameter Sets: LiteralPath
Aliases: PSPath

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Path
The path to the files to retrieve the Authenticode information for.
Wildcards are permitted and a signature will be outputted for every file that matches the wildcard.
This is only supported for paths in the FileSystem provider.

```yaml
Type: String[]
Parameter Sets: Path
Aliases: FilePath

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: True
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

### -Provider
Specify the Authenticode provider used to extract the signature.
This is required if the `-Stream` parameter is specified.
If `-Path`, or `-LiteralPath` is specified, the provider is found based on the extension of the file being read.
If the file has no extension then an explicit provider must be specified.

Valid providers are:

* `NotSpecified` - Uses the file extension to find the provider
* `PowerShell` - Uses the PowerShell script Authenticode provider
* `PowerShellMof` - Uses the PowerShell script Authenticode provider for MOF files like `.mof`
* `PowerShellXml` - Uses the PowerShell script Authenticode provider for XML files like `.psc1`, `.ps1xml`, and `.cdxml`
* `PEBinary` - Windows `.exe`, `.dll` files, including cross platform dotnet assemblies

```yaml
Type: AuthenticodeProvider
Parameter Sets: (All)
Aliases:
Accepted values: NotSpecified, PowerShell, PowerShellMof, PowerShellXml, PEBinary

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipCertificateCheck
Skips the CA trust validation of the certificate that signed the file.
The signature will still be validated to ensure the file has been tampered with but if this switch is present, the certificate CA trust will not be checked.

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

### -Stream
Specifies a stream to extract the Authenticode signature from.
The stream must be readable and seekable.
When using this parameter, the `-Provider` parameter must be specified to indicate what Authenticode provider to use.

This parameter is useful for verifying signatures from in-memory content or custom stream sources.

```yaml
Type: Stream
Parameter Sets: Stream
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -TrustStore
A collection of certificate to use as a custom trusted store location instead of the system provided certificates.
Any self signed certificates in this collection will be treated as a trusted root CA during the certificate validation, other certificates will be treated as intermediaries used to help build the trust chain.
This should only be used for testing purposes and the system store should be used in most production scenarios.

```yaml
Type: X509Certificate2Collection
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

### System.IO.Stream
Accepts a stream for the `-Stream` parameter.

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

[Authenticode Digital Signatures](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)

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
Get-OpenAuthenticodeSignature [-Path] <String[]> [-Encoding <Encoding>] [-Provider <AuthenticodeProvider>]
 [-SkipCertificateCheck] [-TrustStore <X509Certificate2Collection>] [<CommonParameters>]
```

### LiteralPath
```
Get-OpenAuthenticodeSignature -LiteralPath <String[]> [-Encoding <Encoding>] [-Provider <AuthenticodeProvider>]
 [-SkipCertificateCheck] [-TrustStore <X509Certificate2Collection>] [<CommonParameters>]
```

### Content
```
Get-OpenAuthenticodeSignature -Content <String> [-Provider <AuthenticodeProvider>] [-SkipCertificateCheck]
 [-TrustStore <X509Certificate2Collection>] [<CommonParameters>]
```

### RawContent
```
Get-OpenAuthenticodeSignature -RawContent <Byte[]> [-Encoding <Encoding>] [-Provider <AuthenticodeProvider>]
 [-SkipCertificateCheck] [-TrustStore <X509Certificate2Collection>] [<CommonParameters>]
```

## DESCRIPTION
Gets the Authenticode signature information from the path or content specified.
This information includes the certificate that signed the file, the hash algorithm used, and the timestamp countersignature information if it was used.
An error record is written if the path specified does not have an authenticode signature present.

See [about_AuthenticodeProviders](./about_AuthenticodeProviders.md) for more information about what providers are currently supported.
When using a file path that has no extension, an explicit `-Provider` must be specified to indicate what Authenticode provider needs to be used to retrieve and validate the signature.

It is also possible to provide a file to validate using the `-Content` and `-RawContent` which accepts a string and byte array respectively.
The `-Content` value is useful for files that are read as string like PowerShell scripts rather than binary files like a `.dll`.

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

### Example 4: Get the Authenticode signature for a script in memory
```powershell
PS C:\> $myScript = Get-Content -Path script.ps1 -Raw
PS C:\> Get-OpenAuthenticodeSignature -Content $myScript -Provider PowerShell
```

Gets the Authenticode signature for a PowerShell script as a string.

### Example 5: Get the Authenticode signature from a file's bytes
```powershell
PS C:\> $bytes = Get-Content -Path script.ps1 -AsByteStream -Raw
PS C:\> Get-OpenAuthenticodeSignature -RawContent $bytes -Provider PowerShell -Encoding ANSI
```

Gets the Authenticode signature from the files raw bytes.
The `-Encoding` parameter is not necessarily for most Authenticode providers but for PowerShell it is a helpful hint to tell it how to read those bytes as a string.
By default PowerShell will use the encoding of the BOM if present, otherwise uses `UTF8`.
In this example the encoding is set to `ANSI` which is typically `windows-1252`.
The `ANSI` encoding refers to the legacy encoding that Windows PowerShell (before 5.1) used to read scripts.

## PARAMETERS

### -Content
Gets the Authenticode signature from the file strings contents.
This is useful if the file is stored in memory and not on the filesystem.
The `-Provider` parameter must be provided when using `-Content`.

If the string value is from a file with a BOM it is important to ensure the string has the BOM chars present.
An example of how to prefix a string with an encoding BOM is as follows.



$encoding = [System.Text.Encoding]::Unicode
$bom = $encoding.GetString($encoding.GetPreamble())
$content = $bom + (Get-Content $path -Raw)

_Note: it is far safer to just use `-Path` in the case above. This example is just to display how a BOM can be prefixed if it was required._

```yaml
Type: String
Parameter Sets: Content
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Encoding
A hint to provide to the Authenticode provider that indicates what the file string encoding method is.
This is only used by Authenticode providers that need to read the file as a string, like PowerShell.
The default used is dependent on the Authenticode provider but most commonly will be `UTF-8`.

This accepts a `System.Text.Encoding` type but also a string or int representing the encoding from `[System.Text.Encoding]::GetEncoding(...)`.
Some common encoding values are:

* `Utf8` - UTF-8 but without a Byte Order Mark (BOM)
* `ASCII` - ASCII (bytes 0-127)
* `ANSI` - The ANSI encoding commonly used in legacy Windows encoding
* `OEM` - The value of `[System.Text.Encoding]::Default` which is UTF-8 without a BOM
* `Unicode` - UTF-16-LE
* `Utf8Bom` - UTF-8 but with a BOM
* `Utf8NoBom` - Same as `Utf8`

The `ANSI` encoding typically refers to the legacy Windows encoding used in older PowerShell versions.
If creating a script that should be used across the various PowerShell versions, it is highly recommended to use an encoding with a `BOM` like `Utf8Bom` or `Unicode`.

```yaml
Type: Encoding
Parameter Sets: Path, LiteralPath, RawContent
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

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

### -Provider
Specify the Authenticode provider used to extract the signature.
This is required if the `-Content` or `-RawContent` parameter is specified.
If `-Path`, or `-LiteralPath` is specified, the provider is found based on the extension of the file being read.
If the file has no extension then an explicit provider must be specified.

Valid providers are:

* `NotSpecified` - Uses the file extension to find the provider
* `PowerShell` - Uses the PowerShell script Authenticode provider

```yaml
Type: AuthenticodeProvider
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RawContent
Gets the Authenticode signature from the file bytes directly.
This is useful if the file is stored in memory and not on the filesystem.
The `-Provider` parameter must be provided when using `-RawContent`.

```yaml
Type: Byte[]
Parameter Sets: RawContent
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
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

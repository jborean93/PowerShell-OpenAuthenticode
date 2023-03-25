---
external help file: OpenAuthenticode.dll-Help.xml
Module Name: OpenAuthenticode
online version: https://www.github.com/jborean93/PowerShell-OpenAuthenticode/blob/main/docs/en-US/Add-OpenAuthenticodeSignature.md
schema: 2.0.0
---

# Add-OpenAuthenticodeSignature

## SYNOPSIS
Adds an authenticode signature to a file.

## SYNTAX

### PathCertificate (Default)
```
Add-OpenAuthenticodeSignature [-Path] <String[]> -Certificate <X509Certificate2> [-Encoding <Encoding>]
 [-HashAlgorithm <HashAlgorithmName>] [-IncludeOption <X509IncludeOption>] [-PassThru]
 [-TimeStampHashAlgorithm <HashAlgorithmName>] [-TimeStampServer <String>] [-Provider <AuthenticodeProvider>]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

### PathKey
```
Add-OpenAuthenticodeSignature [-Path] <String[]> -Key <KeyProvider> [-Encoding <Encoding>]
 [-HashAlgorithm <HashAlgorithmName>] [-IncludeOption <X509IncludeOption>] [-PassThru]
 [-TimeStampHashAlgorithm <HashAlgorithmName>] [-TimeStampServer <String>] [-Provider <AuthenticodeProvider>]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

### LiteralPathCertificate
```
Add-OpenAuthenticodeSignature -LiteralPath <String[]> -Certificate <X509Certificate2> [-Encoding <Encoding>]
 [-HashAlgorithm <HashAlgorithmName>] [-IncludeOption <X509IncludeOption>] [-PassThru]
 [-TimeStampHashAlgorithm <HashAlgorithmName>] [-TimeStampServer <String>] [-Provider <AuthenticodeProvider>]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

### LiteralPathKey
```
Add-OpenAuthenticodeSignature -LiteralPath <String[]> -Key <KeyProvider> [-Encoding <Encoding>]
 [-HashAlgorithm <HashAlgorithmName>] [-IncludeOption <X509IncludeOption>] [-PassThru]
 [-TimeStampHashAlgorithm <HashAlgorithmName>] [-TimeStampServer <String>] [-Provider <AuthenticodeProvider>]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet can add a signature to a file that contains no signature or to an existing signature set without removing the old one.
This signature can be validated using [Get-OpenAuthenticodeSignature](./Get-OpenAuthenticodeSignature.md) or any of the Authenticode APIs, including the ones of a Windows host.
Use [Set-OpenAuthenticodeSignature](./Set-OpenAuthenticodeSignature.md) to replace the existing signature with the newly generated one instead of appending a signature.

It is possible to sign a file using a certificate object with an associated key.
The simplest way to get a certificate is to use the [Get-PfxCertificate cmdlet](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-pfxcertificate?view=powershell-7.3) which works on both Windows and non-Windows hosts.
It is also possible to get a code signing certificate through the `Cert:\` provider alongside the `-CodeSigningCert` parameter on Windows.
The certificate must have the Key Usage of `Digital Signature (80)` and Enhanced Key Usage `Code Signing (1.3.6.1.5.5.7.3.3)` for it to be used with Authenticode.
While it should be signed by a trusted CA authority for it to be validated normally, it is not a requirement to sign the file.

See [about_AuthenticodeProviders](./about_AuthenticodeProviders.md) for more information about what providers are currently supported.
When using a file path that has no extension, an explicit `-Provider` must be specified to indicate what Authenticode provider needs to be used to sign and embed the signature in the file specified.

Adding a signature will edit the file provided, use `-WhatIf` to test whether a signature can be added without actually changing the file.

## EXAMPLES

### Example 1: Signs a PowerShell ps1 script with SHA256 and SHA512
```powershell
PS C:\> $pass = Read-Host -AsSecureString -Prompt "Enter pfx password"
PS C:\> $cert = Get-PfxCertificate -FilePath ~/code-signing.pfx -Password $pass
PS C:\> Add-OpenAuthenticodeSignature -Path test.ps1 -Certificate $cert
PS C:\> Add-OpenAuthenticodeSignature -Path test.ps1 -Certificate $cert -HashAlgorithm SHA512
```

Signs the script `test.ps1` with the certificate specified.
The initial signature will be for SHA256 but it will also contain a SHA512 signature as well.

### Example 2: Signs a PowerShell ps1 script and a counter signature timestamp
```powershell
PS C:\> $pass = Read-Host -AsSecureString -Prompt "Enter pfx password"
PS C:\> $cert = Get-PfxCertificate -FilePath ~/code-signing.pfx -Password $pass
PS C:\> Add-OpenAuthenticodeSignature -Path test.ps1 -Certificate $cert -TimestampServer http://timestamp.digicert.com
PS C:\> Add-OpenAuthenticodeSignature -Path test.ps1 -Certificate $cert -HashAlgorithm SHA512 -TimestampServer http://timestamp.digicert.com
```

Like example 1 but also adds a counter signature with the Digicert timestamp server.

## PARAMETERS

### -Certificate
The certificate used to sign the files specified.
Use the `Get-PfxCertificate` or `Get-ChildItem Cert:\... -CodeSigningCert` (Windows only) to get a certificate to use for signing.
The certificate must have access to its associated private key for it to be able to sign the file.
It should also have the Key Usage of `Digital Signature (80)` and Enhanced Key Usage `Code Signing (1.3.6.1.5.5.7.3.3)`.

```yaml
Type: X509Certificate2
Parameter Sets: PathCertificate, LiteralPathCertificate
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
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
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -HashAlgorithm
The hashing algorithm to use when generating the Authenticode signature.
This defaults to SHA256 if not specified.

Known algorithms are:

* `SHA1`
* `SHA256`
* `SHA384`
* `SHA512`

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
Existing options are:

* `None` - No chain information is included
* `ExcludeRoot` - The entire chain is included except for the root certificate
* `EndCertOnly` - Only the end certificate is included
* `WholeChain` - The whole chain is included

The default is `ExcludeRoot` which will include all the certs and their intermediaries in the Authenticode signature, except the root CA certificate.

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

### -Key
A custom key object that can be used to signed the file.
Currently this is only supported by Azure KeyVault keys and this value can be retrieved from [Get-OpenAuthenticodeAzKey](./Get-OpenAuthenticodeAzKey.md).

```yaml
Type: KeyProvider
Parameter Sets: PathKey, LiteralPathKey
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LiteralPath
Specifies the path to the files to sign with an Authenticode signature.
Unlike `-Path`, the path is used exactly as it is typed, no wildcard matching will occur.

If the path does not have a file extension, the `-Provider` parameter must be set to tell the cmdlet how it should be signed.

```yaml
Type: String[]
Parameter Sets: LiteralPathCertificate, LiteralPathKey
Aliases: PSPath

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -PassThru
Output the signature information that was added to the file.
If not set, the cmdlet will not output anything.

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

### -Path
The path to the files to sign with an Authenticode signature.
Wildcards are permitted and a signature will be outputted for every file that matches the wildcard.
This is only supported for paths in the FileSystem provider.

If the path does not have a file extension, the `-Provider` parameter must be set to tell the cmdlet how it should be signed.

```yaml
Type: String[]
Parameter Sets: PathCertificate, PathKey
Aliases: FilePath

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: True
```

### -Provider
Specify the Authenticode provider used to sign the file.
If the file has no extension then an explicit provider must be specified.

Valid providers are:

* `NotSpecified` - Uses the file extension to find the provider
* `PowerShell` - Uses the PowerShell script Authenticode provider
* `PowerShellXml` - Uses the PowerShell script Authenticode provider for XML files like `.psc1` and `.ps1xml`
* `PEBinary` - Windows `.exe`, `.dll` files, including cross platform dotnet assemblies

```yaml
Type: AuthenticodeProvider
Parameter Sets: (All)
Aliases:
Accepted values: NotSpecified, PowerShell, PEBinary

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TimeStampHashAlgorithm
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

### -TimeStampServer
The timestamp server used to counter sign the Authenticode signature.
The time stamp represents the exact time the certificate was added to the file.
A time stamp prevents the signature from being invalidated once the certificate has expired.

The value specified here is the URL to an RFC 3161 compliant time stamping server.
It is possible to specify the hashing algorithm the timestamp server uses with the `-TimeStampHashAlgorithm`.

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

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

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

### None
No output is present if `-PassThru` is not specified.

### System.Security.Cryptography.Pkcs.SignedCms / OpenAuthenticode.AuthenticodeSignature
If `-PassThru` is specified, this will output the Authenticode signature details that was added to the path specified. This object has the following extra properties added as part of the extended type data of `OpenAuthenticode.AuthenticodeSignature`:

+ `Path`: The file path that this signature is for

+ `Certificate`: The X.509 certificate that signed the file

+ `HashAlgorithm`: The hash algorithm that was used in the Authenticode signature

+ `TimeStampInfo`: Information about the counter signature timestamp including its certificate, timestamp date in UTC, and timestamp hashing algorithm

## NOTES
Nested signatures are stored as unsigned attributes on the file's existing Authenticode signature data.

## RELATED LINKS

[Authenticode Digital Signatures](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)

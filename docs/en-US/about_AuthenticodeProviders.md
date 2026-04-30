# Authenticode Providers
## about_AuthenticodeProviders

# SHORT DESCRIPTION
Authenticode uses custom providers to provide a way to get and set signatures in various file types.
This document goes through the basic provider interface and what providers are currently supported in this module.

# LONG DESCRIPTION
Currently the following providers have been implemented in this module.

|Provider|File Extensions|
|-|-|
|PowerShell|`.ps1`, `.psd1`, `.psm1`|
|PowerShellMof|`.mof`|
|PowerShellXml|`.psc1`, `.ps1xml`, `.cdxml`|
|PEBinary|`.dll`, `.exe`|
|Appx|`.appx`, `.msix`|
|AppxBundle|`.appxbundle`, `.msixbundle`|

The `Get-OpenAuthenticodeSignature`, `Set-OpenAuthenticodeSignature`, and `Add-OpenAuthenticodeSignature` uses the extension on the file path provided to determine what provider to use.
If the file has no extension, or the `-Stream` parameter is used with `Get-OpenAuthenticodeSignature`, an explicit provider must be specified with `-Provider`.
An explicit provider can also be specified to override the extension lookup if that is desired for any reason.

Each provider provides a way to:

* Get the existing signature
* Set a new signature
* Get a hashed digest in the form of the Authenticode `SpcIndirectData` structure
* Add custom attributes to be signed to the [CmsSigner PKCS 7 block](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.cmssigner?view=dotnet-plat-ext-7.0)
* Save (add/remove/set) the signature to the file requested

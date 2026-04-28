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
|Appx|`.appx`, `.msix`, `.appxbundle`, `.msixbundle`|

The `Get-OpenAuthenticodeSignature`, `Set-OpenAuthenticodeSignature`, and `Add-OpenAuthenticodeSignature` uses the extension on the file path provided to determine what provider to use.
If the file has no extension, or the `-Stream` parameter is used with `Get-OpenAuthenticodeSignature`, an explicit provider must be specified with `-Provider`.
An explicit provider can also be specified to override the extension lookup if that is desired for any reason.

Each provider provides a way to:

* Get the existing signature
* Set a new signature
* Get a hashed digest in the form of the Authenticode `SpcIndirectData` structure
* Add custom attributes to be signed to the [CmsSigner PKCS 7 block](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.cmssigner?view=dotnet-plat-ext-7.0)
* Save (add/remove/set) the signature to the file requested

## APPX/MSIX Provider

The APPX provider supports signing Windows App Packages (APPX/MSIX) and bundles.

### Supported Formats

* `.appx` - Legacy Windows app package
* `.msix` - Modern Windows app package (preferred)
* `.appxbundle` - Bundle of multiple APPX packages
* `.msixbundle` - Bundle of multiple MSIX packages

### Hash Algorithms

APPX/MSIX packages only support SHA-256, SHA-384, and SHA-512 hash algorithms. SHA-1 is explicitly rejected for security reasons.

### Signing Process

APPX/MSIX packages are ZIP-based archives. The provider hashes the following files within the package:

1. `AppxBlockMap.xml` - Integrity manifest containing block-level hashes
2. `[Content_Types].xml` - MIME type definitions
3. `AppxMetadata/CodeIntegrity.cat` - Optional catalog file (if present)

The signature is stored in `AppxSignature.p7x` as a detached PKCS#7 signature within the package.

### Examples

```powershell
# Sign an MSIX package
Set-OpenAuthenticodeSignature -Path MyApp.msix -Certificate $cert -HashAlgorithm SHA256

# Verify an APPX signature
Get-OpenAuthenticodeSignature -Path MyApp.appx

# Remove signature from a package
Clear-OpenAuthenticodeSignature -Path MyApp.msix
```

### Notes

* MSIX packages require SHA-256 or higher for Windows 10+ compatibility
* Bundles are signed as a whole, not individual packages within
* The provider validates ZIP structure and required files during load

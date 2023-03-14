# Authenticode Providers
## about_AuthenticodeProviders

# SHORT DESCRIPTION
Authenticode uses custom providers to provide a way to get and set signatures in various file types.
This document goes through the basic provider interface and what providers are currently supported in this module.

# LONG DESCRIPTION
Currently the following providers have been implemented in this module.

|Provider|File Extensions|String Contents|
|-|-|-|
|PowerShell|`.ps1`, `.psc1`, `.psd1`, `.psm1`, `.ps1xml`|Yes|

The `Get-OpenAuthenticodeSignature` and `Set-OpenAuthenticodeSignature` uses the extension on the file path provided to determine what provider to use.
If the file has no provider, or one of the content parameters are used, an explicit provider can be specified with `-Provider`.
An explicit provider can also be specified to override the extension lookup if that is desired for any reason.
If a provider supports string contents, the `-Content` parameter can be used with `Get-AuthenticodeSignature` to get a signature from a string value.

Each provider provides a way to:

* Get the existing signature
* Set a new signature
* Get a hashed digest in the form of the Authenticode `SpcIndirectData` structure
* Add custom attributes to be signed to the [CmsSigner PKCS 7 block](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.cmssigner?view=dotnet-plat-ext-7.0)
* Save (add/remove/set) the signature to the file requested


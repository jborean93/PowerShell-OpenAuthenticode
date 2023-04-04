# Changelog for OpenAuthenticode

## v0.3.0 - TBD

* Added support for verifying security catalog files (`.cat`) through the `SecurityCatalogProvider`

## v0.2.0 - 2023-03-25

* Added support for `.dll` and `.exe` files through the `PEBinary` provider
* Fixed up support for PowerShell XML signatures for `.psc1`, `.ps1xml`
* Output nested signatures when a file has been signed with multiple hash algorithms
* Renamed output property `HashAlgorithmName` to just `HashAlgorithm`
* Added the following cmdlets
  * [Add-OpenAuthenticodeSignature](./docs/en-US/Add-OpenAuthenticodeSignature.md) - adds a signature to an existing signature set
  * [Clear-OpenAuthenticodeSignature](./docs/en-US/Clear-OpenAuthenticodeSignature.md) - removes any signatures on a file

## v0.1.0 - 2023-03-17

+ Initial version of the `OpenAuthenticode` module

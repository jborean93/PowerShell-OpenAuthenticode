# Changelog for OpenAuthenticode

## v0.6.0 - TBD

* Added the `-TokenSource` parameter for `Get-OpenAuthenticodeAzKey` to specify the authentication method used.
* Added the following cmdlets
  * [Get-OpenAuthenticodeAzTrustedSigner](./docs/en-US/Get-OpenAuthenticodeAzTrustedSigner.md) - uses Azure Trusted Signer to sign the provided files

## v0.5.0 - 2024-12-07

* Remove support for PowerShell 7.2 and 7.3 as they are end of life versions
* Bump the Azure and OTP dependencies to the latest version available
* Fix up PowerShell script encoding detection when no BOM is present

## v0.4.0 - 2023-08-25

* Fix support for ECDSA based key that was broken in `v0.3.0`
* Add support for ECDSA keys from Azure using `Get-OpenAuthenticodeAzKey`

## v0.3.0 - 2023-08-24

* Reworked Assembly Load Context to properly store extra dlls in new ALC
* Added `Get-OpenAuthenticodeSslDotComKey` which can use SSL.com's eSigner API to sign content
* Added the `-Silent` parameter for `Set-OpenAuthenticodeSignature` and `Add-OpenAuthenticodeSignature` to disable Windows certificate PIN prompts
  * The original behaviour was to always be silent but has been changed, use this parameter to fallback to the old behaviour.

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

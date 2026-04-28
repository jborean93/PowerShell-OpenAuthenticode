# Changelog for OpenAuthenticode

## v0.7.0 - TBD

### Breaking Changes

* **Removed `-Content`, `-RawContent`, and `-Encoding` parameters** from `Get-OpenAuthenticodeSignature`
  * Use `-Stream` parameter with a `MemoryStream` for in-memory content verification
  * Encoding is now automatically detected for PowerShell scripts
  * Migration examples:
    ```powershell
    # Old: -Content parameter
    Get-OpenAuthenticodeSignature -Content $scriptText -Provider PowerShell

    # New: Use -Stream with MemoryStream
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($scriptText)
    $stream = [System.IO.MemoryStream]::new($bytes)
    try {
        Get-OpenAuthenticodeSignature -Stream $stream -Provider PowerShell
    } finally {
        $stream.Dispose()
    }

    # Old: -RawContent parameter
    Get-OpenAuthenticodeSignature -RawContent $bytes -Provider PowerShell

    # New: Use -Stream with MemoryStream
    $stream = [System.IO.MemoryStream]::new($bytes)
    try {
        Get-OpenAuthenticodeSignature -Stream $stream -Provider PowerShell
    } finally {
        $stream.Dispose()
    }
    ```

* **Removed `-Encoding` parameter** from `Set-`, `Add-`, and `Clear-OpenAuthenticodeSignature`
  * Encoding is now automatically detected from file content (BOM or UTF-8 validation)
  * Original file encoding is preserved when saving

### Added

* **New `-Stream` parameter** for `Get-OpenAuthenticodeSignature`
  * Allows verification of authenticode signatures from any readable, seekable stream
  * Requires `-Provider` parameter to specify file type

### Changed

* Cmdlets now use file streams internally instead of loading entire files into memory
* Improved memory efficiency when processing large files (PE binaries)
* Updated versions of the Azure dependencies to the latest available
* Updated internal AsyncPSCmdlet implementation to fix various bugs and cancellation scenarios
* Internal module setup has been simplified, this should have no impact on end users but some public types may have changed namespaces which may be problematic if PowerShell was referencing those types through the `[OpenAuthenticode.*]` syntax

## v0.6.3 - 2025-09-12

* Provide better when an invalid URI was specified for `Get-OpenAuthenticodeAzTrustedSigner -Endpoint`

## v0.6.2 - 2025-09-01

* Update Azure dependencies to the latest versions

## v0.6.1 - 2025-02-12

* Fix up certificate selection logic for `Get-OpenAuthenticodeAzTrustedSigner` to retrieve the correct leaf certificate on Windows.

## v0.6.0 - 2025-02-12

* Added the `-TokenSource` parameter for `Get-OpenAuthenticodeAzKey` to specify the authentication method used.
* Move all signing operations to the `EndProcessing` of the cmdlet to batch up multiple requests if present.
* Removed `Get-OpenAuthenticodeSslDotComKey` due to lack of use
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


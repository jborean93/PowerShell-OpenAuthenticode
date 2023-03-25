# PowerShell OpenAuthenticode

[![Test workflow](https://github.com/jborean93/PowerShell-OpenAuthenticode/workflows/Test%20OpenAuthenticode/badge.svg)](https://github.com/jborean93/PowerShell-OpenAuthenticode/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/PowerShell-OpenAuthenticode/branch/main/graph/badge.svg?token=b51IOhpLfQ)](https://codecov.io/gh/jborean93/PowerShell-OpenAuthenticode)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/OpenAuthenticode.svg)](https://www.powershellgallery.com/packages/OpenAuthenticode)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/PowerShell-OpenAuthenticode/blob/main/LICENSE)

A cross platform Authenticode library for PowerShell signatures.
Currently this only support PowerShell script files, `.ps1`, `.psd1`, `.psm1`, `.ps1xml`, etc files.
More format are planned for the future.

See [OpenAuthenticode index](docs/en-US/OpenAuthenticode.md) for more details.

## Requirements

These cmdlets have the following requirements

* PowerShell v7.2 or newer

## Examples

### Get Authenticode Signatures from File

```powershell
Get-OpenAuthenticodeSignature -Path test.ps1, test.dll
```

This gets all the Authenticode signatures present in the files `test.ps1` and `test.dll`.
The output object contains each signature, the hash algorithm used, the timestamp information, as well as the certificate used to sign it.
It will also attempt to validate the signature is trusted by a known CA, the `-SkipCertificateCheck` can be passed in to ignore any CA trust failures.

### Set Authenticode signature

```powershell
$cert = Get-Item Cert:\CurrentUser\My\* -CodeSigningCert
Set-OpenAuthenticodeSignature -Path test.ps1 -Certificate $cert
```

Signs the file `test.ps1` with the certificate provided using the default hash algorithm SHA256.
The certificate retrieval only works on Windows, use `Get-PfxCertificate` on other platforms of the [X509Certificate2](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2?view=net-7.0) class directly on other platforms to get the certificate object to sign.
The [Get-OpenAuthenticodeAzKey](docs/en-US/Get-OpenAuthenticodeAzKey.md) cmdlet can be used to retrieve a code signing certificate from Azure KeyVault to use to sign the certificate.
The [Add-OpenAuthenticodeSignature](docs/en-US/Add-OpenAuthenticodeSignature.md) cmdlet can be used to add a signature to an existing set Authenticode signatures rather than replace the existing signature.

## Installing

The easiest way to install this module is through [PowerShellGet](https://docs.microsoft.com/en-us/powershell/gallery/overview).

You can install this module by running;

```powershell
# Install for only the current user
Install-Module -Name OpenAuthenticode -Scope CurrentUser

# Install for all users
Install-Module -Name OpenAuthenticode -Scope AllUsers
```

## Contributing

Contributing is quite easy, fork this repo and submit a pull request with the changes.
To build this module run `.\build.ps1 -Task Build` in PowerShell.
To test a build run `.\build.ps1 -Task Test` in PowerShell.
This script will ensure all dependencies are installed before running the test suite.

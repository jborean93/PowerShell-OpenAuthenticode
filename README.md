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

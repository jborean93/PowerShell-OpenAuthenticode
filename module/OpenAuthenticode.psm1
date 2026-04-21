# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

using namespace System.IO
using namespace System.Management.Automation
using namespace System.Reflection

$importModule = Get-Command -Name Import-Module -Module Microsoft.PowerShell.Core
$moduleName = [Path]::GetFileNameWithoutExtension($PSCommandPath)


# This is used to load the shared assembly in the Default ALC which then sets
# an ALC for the moulde and any dependencies of that module to be loaded in
# that ALC.

$isReload = $true
if (-not ('OpenAuthenticode.LoadContext' -as [type])) {
    $isReload = $false

    Add-Type -Path ([Path]::Combine($PSScriptRoot, 'bin', 'net8.0', "$moduleName.dll"))
}

$mainModule = [OpenAuthenticode.LoadContext]::Initialize()
$innerMod = &$importModule -Assembly $mainModule -PassThru:$isReload

if ($innerMod) {
    # Bug in pwsh, Import-Module in an assembly will pick up a cached instance
    # and not call the same path to set the nested module's cmdlets to the
    # current module scope.
    # https://github.com/PowerShell/PowerShell/issues/20710
    $addExportedCmdlet = [PSModuleInfo].GetMethod(
        'AddExportedCmdlet',
        [BindingFlags]'Instance, NonPublic'
    )
    foreach ($cmd in $innerMod.ExportedCommands.Values) {
        $addExportedCmdlet.Invoke($ExecutionContext.SessionState.Module, @(, $cmd))
    }
}

Update-FormatData -AppendPath (Join-Path $PSScriptRoot "$moduleName.Format.ps1xml")
Update-TypeData -AppendPath (Join-Path $PSScriptRoot "$moduleName.Type.ps1xml")

# Use this for testing that the dlls are loaded correctly and outside the Default ALC.
# [System.AppDomain]::CurrentDomain.GetAssemblies() |
#     Where-Object { $_.GetName().Name -like "*openauthenticode*" } |
#     ForEach-Object {
#         $alc = [Runtime.Loader.AssemblyLoadContext]::GetLoadContext($_)
#         [PSCustomObject]@{
#             Name = $_.FullName
#             Location = $_.Location
#             ALC = $alc
#         }
#     } | Format-List

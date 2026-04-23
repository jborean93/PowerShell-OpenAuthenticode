# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

using namespace System.IO
using namespace System.Management.Automation
using namespace System.Reflection

$importModule = Get-Command -Name Import-Module -Module Microsoft.PowerShell.Core
$moduleName = [Path]::GetFileNameWithoutExtension($PSCommandPath)
$loaderName = "$moduleName.Loader.LoadContext"

$isReload = $true
if (-not ($loaderName -as [type])) {
    $isReload = $false

    Add-Type -Path ([Path]::Combine($PSScriptRoot, 'bin', 'net8.0', "$moduleName.Loader.dll"))
}

$mainModule = ($loaderName -as [type])::Initialize($moduleName)
$innerMod = &$importModule -Assembly $mainModule -PassThru:$isReload

if ($innerMod) {
    # Bug in pwsh, Import-Module in an assembly will pick up a cached instance
    # and not call the same path to set the nested module's cmdlets to the
    # current module scope.
    # https://github.com/PowerShell/PowerShell/issues/20710
    $addExportedCmdlet = [PSModuleInfo].GetMethod(
        'AddExportedCmdlet',
        [BindingFlags]'Instance, NonPublic')
    $addExportedAlias = [PSModuleInfo].GetMethod(
        'AddExportedAlias',
        [BindingFlags]'Instance, NonPublic')
    foreach ($cmd in $innerMod.ExportedCmdlets.Values) {
        $addExportedCmdlet.Invoke($ExecutionContext.SessionState.Module, @(, $cmd))
    }
    foreach ($alias in $innerMod.ExportedAliases.Values) {
        $addExportedAlias.Invoke($ExecutionContext.SessionState.Module, @(, $alias))
    }
}

Update-FormatData -AppendPath (Join-Path $PSScriptRoot "$moduleName.Format.ps1xml")
Update-TypeData -AppendPath (Join-Path $PSScriptRoot "$moduleName.Type.ps1xml")

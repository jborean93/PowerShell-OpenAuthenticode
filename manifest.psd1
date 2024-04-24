@{
    DotnetProject = 'OpenAuthenticode.Module'
    InvokeBuildVersion = '5.11.1'
    PesterVersion = '5.5.0'
    BuildRequirements = @(
        @{
            ModuleName = 'Microsoft.PowerShell.PSResourceGet'
            ModuleVersion = '1.0.4.1'
        }
        @{
            ModuleName = 'platyPS'
            RequiredVersion = '0.14.2'
        }
    )
    TestRequirements = @()
}

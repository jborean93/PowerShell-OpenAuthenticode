using namespace System.Collections
using namespace System.IO

#Requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [Manifest]
    $Manifest
)

#region Build

task Clean {
    if (Test-Path -LiteralPath $Manifest.ReleasePath) {
        Remove-Item -LiteralPath $Manifest.ReleasePath -Recurse -Force
    }
    New-Item -Path $Manifest.ReleasePath -ItemType Directory | Out-Null
}

task BuildManaged {
    $arguments = @(
        'publish'
        '--configuration', $Manifest.Configuration
        '--verbosity', 'quiet'
        '-nologo'
        "-p:Version=$($Manifest.Module.Version)"
    )

    $csproj = (Get-Item -Path "$($Manifest.DotnetPath)/*.csproj").FullName
    foreach ($framework in $Manifest.TargetFrameworks) {
        Write-Host "Compiling for $framework" -ForegroundColor Cyan
        $outputDir = [Path]::Combine($Manifest.ReleasePath, "bin", $framework)
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        dotnet @arguments --framework $framework --output $outputDir $csproj

        if ($LASTEXITCODE) {
            throw "Failed to compiled code for $framework"
        }
    }
}

task BuildModule {
    $copyParams = @{
        Path = [Path]::Combine($Manifest.PowerShellPath, '*')
        Destination = $Manifest.ReleasePath
        Recurse = $true
        Force = $true
    }
    Copy-Item @copyParams
}

task BuildDocs {
    Get-ChildItem -LiteralPath $Manifest.DocsPath -Directory | ForEach-Object {
        Write-Host "Building docs for $($_.Name)" -ForegroundColor Cyan
        $helpParams = @{
            Path = $_.FullName
            OutputPath = [Path]::Combine($Manifest.ReleasePath, $_.Name)
        }
        New-ExternalHelp @helpParams | Out-Null
    }
}

task Sign {
    $accountName = $env:AZURE_TS_NAME
    $profileName = $env:AZURE_TS_PROFILE
    $endpoint = $env:AZURE_TS_ENDPOINT
    if (-not $accountName -or -not $profileName -or -not $endpoint) {
        return
    }

    Import-Module -Name (Join-Path $Manifest.ReleasePath "$($Manifest.Module.Name).psd1") -ErrorAction Stop

    Write-Host "Authenticating with Azure TrustedSigning $accountName $profileName for signing" -ForegroundColor Cyan
    $keyParams = @{
        AccountName = $accountName
        ProfileName = $profileName
        Endpoint = $endpoint
    }
    $key = Get-OpenAuthenticodeAzTrustedSigner @keyParams
    $signParams = @{
        Key = $key
        TimeStampServer = 'http://timestamp.acs.microsoft.com'
    }

    $toSign = Get-ChildItem -LiteralPath $Manifest.ReleasePath -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension -in ".ps1", ".psm1", ".psd1", ".ps1xml" -or (
                $_.Extension -eq ".dll" -and $_.BaseName -like "$($Manifest.Module.Name)*"
            )
        } |
        ForEach-Object -Process {
            Write-Host "Signing '$($_.FullName)'"
            $_.FullName
        }

    Set-OpenAuthenticodeSignature -LiteralPath $toSign @signParams
}

task Package {
    $repoParams = @{
        Name = "$($Manifest.Module.Name)-Local"
        Uri = $Manifest.OutputPath
        Trusted = $true
        Force = $true
    }
    Register-PSResourceRepository @repoParams
    try {
        Publish-PSResource -Path $Manifest.ReleasePath -Repository $repoParams.Name -SkipModuleManifestValidate
    }
    finally {
        Unregister-PSResourceRepository -Name $repoParams.Name
    }
}

#endregion Build

#region Test

task TestSetup {
    $config = @{
        codeCoverage = @{
            Configuration = @{
                Format = 'cobertura'
                DeterministicReport = $env:GITHUB_ACTIONS -eq 'true'
            }
        }
    }
    $configJson = $config | ConvertTo-Json -Depth 3
    Set-Content -Path $Manifest.TestSettingsPath -Value $configJson -Encoding UTF8
}

task UnitTests {
    $testsPath = [Path]::Combine($Manifest.TestPath, 'units')
    if (-not (Test-Path -LiteralPath $testsPath)) {
        Write-Host "No unit tests found, skipping" -ForegroundColor Yellow
        return
    }

    Get-ChildItem -LiteralPath $testsPath -Directory | ForEach-Object {
        Write-Host "Running unit tests for $($_.Name)" -ForegroundColor Cyan

        $coveragePath = [Path]::Combine($Manifest.TestResultsPath, "Unit.$($_.Name).Coverage.cobertura.xml")
        $arguments = @(
            'test'
            '--project', $_.FullName
            '--results-directory', $Manifest.TestResultsPath
            '--coverage'
            '--coverage-output', $coveragePath
            '--coverage-settings', $Manifest.TestSettingsPath
        )

        dotnet @arguments
        if ($LASTEXITCODE) {
            throw "Unit tests $($_.Name) failed"
        }
    }
}

task PesterTests {
    $testsPath = [Path]::Combine($Manifest.TestPath, '*.tests.ps1')
    if (-not (Test-Path -Path $testsPath)) {
        Write-Host "No Pester tests found, skipping" -ForegroundColor Yellow
        return
    }

    $dotnetTools = @(dotnet tool list --global) -join "`n"
    if (-not $dotnetTools.Contains('dotnet-coverage')) {
        Write-Host 'Installing dotnet tool dotnet-coverage' -ForegroundColor Yellow
        dotnet tool install --global dotnet-coverage
    }

    $pwsh = Assert-PowerShell -Version $Manifest.PowerShellVersion -Arch $Manifest.PowerShellArch
    $resultsFile = [Path]::Combine($Manifest.TestResultsPath, 'Pester.xml')
    if (Test-Path -LiteralPath $resultsFile) {
        Remove-Item $resultsFile -ErrorAction Stop -Force
    }
    $pesterScript = [Path]::Combine($PSScriptRoot, 'PesterTest.ps1')
    $pwshArguments = @(
        '-NoProfile'
        '-NonInteractive'
        if (-not $IsUnix) {
            '-ExecutionPolicy', 'Bypass'
        }
        '-File', $pesterScript
        '-TestPath', $Manifest.TestPath
        '-OutputFile', $resultsFile
    )

    $watchFolder = [Path]::Combine($Manifest.ReleasePath, 'bin', $Manifest.TestFramework)
    $coveragePath = [Path]::Combine($Manifest.TestResultsPath, "Integration.Coverage.cobertura.xml")

    $arguments = @(
        'collect'
        $pwsh
        $pwshArguments
        '--output', $coveragePath
        '--settings', $Manifest.TestSettingsPath
    )
    $origEnv = $env:PSModulePath
    try {
        $pwshHome = Split-Path -Path $pwsh -Parent
        $env:PSModulePath = @(
            [Path]::Combine($pwshHome, "Modules")
            [Path]::Combine($Manifest.OutputPath, "Modules")
        ) -join ([Path]::PathSeparator)

        # PowerShell will expand wildcards in a splatted argument with no
        # way to disable it. We need to specify it as a normal argument
        # so *.dll is passed to dotnet-coverage and not expanded by PowerShell.
        # https://github.com/PowerShell/PowerShell/issues/24178
        dotnet-coverage @arguments --include-files "$watchFolder/*.dll"
    }
    finally {
        $env:PSModulePath = $origEnv
    }

    if ($LASTEXITCODE) {
        throw "Pester failed tests"
    }
}

task CoverageReport {
    $dotnetTools = @(dotnet tool list --global) -join "`n"
    if (-not $dotnetTools.Contains('dotnet-reportgenerator-globaltool')) {
        Write-Host 'Installing dotnet tool dotnet-reportgenerator-globaltool' -ForegroundColor Yellow
        dotnet tool install --global dotnet-reportgenerator-globaltool
    }

    $mergedCoveragePath = [Path]::Combine($Manifest.TestResultsPath, "Coverage.cobertura.xml")
    if (Test-Path -LiteralPath $mergedCoveragePath) {
        Remove-Item $mergedCoveragePath -Force
    }

    $coverageFiles = Get-ChildItem -Path $Manifest.TestResultsPath -Filter "*.Coverage.cobertura.xml"
    dotnet-coverage merge $coverageFiles.FullName --output $mergedCoveragePath --output-format cobertura
    if ($LASTEXITCODE) {
        throw "Failed to merge coverage files"
    }

    $reportPath = [Path]::Combine($Manifest.TestResultsPath, "CoverageReport")
    $reportArgs = @(
        "-reports:$mergedCoveragePath"
        "-sourcedirs:$($Manifest.RepositoryPath)/src"
        "-targetdir:$reportPath"
        '-filefilters:-*.g.cs'  # Filter out source generated files
        '-reporttypes:Html_Dark;JsonSummary'
    )
    reportgenerator @reportArgs
    if ($LASTEXITCODE) {
        throw "reportgenerator failed with RC of $LASTEXITCODE"
    }

    $coverageScript = [Path]::Combine($PSScriptRoot, 'CoverageReport.ps1')
    & $coverageScript -Path $mergedCoveragePath
}

#endregion Test

task Build -Jobs Clean, BuildManaged, BuildModule, BuildDocs, Sign, Package

task Test -Jobs TestSetup, UnitTests, PesterTests, CoverageReport

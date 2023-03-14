. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Set-OpenAuthenticodeSignature" {
    BeforeAll {
        $caCert = New-X509Certificate -Subject CN=PowerShellCA -Extension @(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        )
        $cert = New-CodeSigningCert -Subject CN=PowerShell -Issuer $caCert

        $setParams = @{
            Certificate = $cert
        }

        $extraTrustStore = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $extraTrustStore.Add($caCert)
        $trustParams = @{
            TrustStore = $extraTrustStore
        }
    }

    It "Sets using wildcard" {
        $folder = "temp:/folder"
        if (Test-Path -LiteralPath $folder) {
            Remove-Item -LiteralPath $folder -Force -Recurse
        }
        $null = New-Item -Path temp:/folder -ItemType Directory -Force
        $null = New-Item -Path $folder -Name script1.ps1 -Force -Value "Write-Host test`r`n"
        $null = New-Item -Path $folder -Name script2.ps1 -Force -Value "Write-Host test`r`n"

        Set-OpenAuthenticodeSignature -Path $folder/*.ps1 @setParams

        $actual = Get-OpenAuthenticodeSignature -Path $folder/*.ps1 @trustParams
        $actual.Count | Should -Be 2
    }

    It "Fails with -Path non filesystem" {
        $actual = Set-OpenAuthenticodeSignature -Path env:PSModulePath @setParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "The resolved path 'PSModulePath' is not a FileSystem path but Environment"
    }

    It "Fails with -LiteralPath non filesystem" {
        $actual = Set-OpenAuthenticodeSignature -LiteralPath env:PSModulePath @setParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "The resolved path 'PSModulePath' is not a FileSystem path but Environment"
    }

    It "Fails with missing -Path" {
        $actual = Set-OpenAuthenticodeSignature -Path missing @setParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "Cannot find path '$(Join-Path $pwd.Path missing)' because it does not exist."
    }

    It "Fails with missing -LiteralPath" {
        $actual = Set-OpenAuthenticodeSignature -LiteralPath missing @setParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "Cannot find path '$(Join-Path $pwd.Path missing)' because it does not exist."
    }

    It "Fails with extension less file and no -Provider" {
        $scriptPath = New-Item -Path temp: -Name script -Force -Value "Write-Host test`r`n"
        $actual = Set-OpenAuthenticodeSignature -Path $scriptPath @setParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "Authenticode support for '' has not been implemented"
    }
}

. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "Get-OpenAuthenticodeSignature" {
    It "Gets using wildcard" {
        $actual = Get-OpenAuthenticodeSignature -Path $PSScriptRoot/data/*.ps1 -SkipCertificateCheck
        $actual.Count | Should -Be 3
    }

    It "Fails with -Path non filesystem" {
        $actual = Get-OpenAuthenticodeSignature -Path env:PSModulePath -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "The resolved path 'PSModulePath' is not a FileSystem path but Environment"
    }

    It "Fails with -LiteralPath non filesystem" {
        $actual = Get-OpenAuthenticodeSignature -LiteralPath env:PSModulePath -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "The resolved path 'PSModulePath' is not a FileSystem path but Environment"
    }

    It "Fails with missing -Path" {
        $actual = Get-OpenAuthenticodeSignature -Path missing -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "Cannot find path '$(Join-Path $pwd.Path missing)' because it does not exist."
    }

    It "Fails with missing -LiteralPath" {
        $actual = Get-OpenAuthenticodeSignature -LiteralPath missing -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "Cannot find path '$(Join-Path $pwd.Path missing)' because it does not exist."
    }

    It "Fails with -Content and no -Provider" {
        $actual = Get-OpenAuthenticodeSignature -Content "abc" -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "A -Provider must be specified when using -Content or -RawContent"
    }

    It "Fails with -RawContent and no -Provider" {
        $actual = Get-OpenAuthenticodeSignature -RawContent ([byte[]]@(0)) -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "A -Provider must be specified when using -Content or -RawContent"
    }

    It "Fails with extension less file and no -Provider" {
        $scriptPath = New-Item -Path temp: -Name script -Force -Value "Write-Host test`r`n"
        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "Authenticode support for '' has not been implemented"
    }
}

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

    It "Fails with -Stream and no -Provider" {
        $stream = [System.IO.MemoryStream]::new([byte[]]@(0))
        try {
            $actual = Get-OpenAuthenticodeSignature -Stream $stream -ErrorAction SilentlyContinue -ErrorVariable err
            $actual | Should -BeNullOrEmpty
            $err.Count | Should -Be 1
            [string]$err | Should -Be "A -Provider must be specified when using -Stream"
        }
        finally {
            $stream.Dispose()
        }
    }

    It "Fails with non-readable stream" {
        $stream = [System.IO.MemoryStream]::new()
        $stream.Dispose()  # Make it non-readable
        $actual = Get-OpenAuthenticodeSignature -Stream $stream -Provider PowerShell -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -BeLike "*Stream must be readable*"
    }

    It "Fails with extension less file and no -Provider" {
        $scriptPath = New-Item -Path temp: -Name script -Force -Value "Write-Host test`r`n"
        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err | Should -Be "Authenticode support for '' has not been implemented"
    }
}

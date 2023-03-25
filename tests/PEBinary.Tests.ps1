. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "PE Binary Authenticode" {
    BeforeAll {
        $caCert = New-X509Certificate -Subject CN=PowerShellCA -Extension @(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        )
        $cert = New-CodeSigningCert -Subject CN=PowerShell -Issuer $caCert

        $extraTrustStore = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $extraTrustStore.Add($caCert)
        $trustParams = @{
            TrustStore = $extraTrustStore
        }
    }

    BeforeEach {
        $dllPath = Join-Path temp: test.dll
        Copy-Item -LiteralPath ([OpenAuthenticode.SignatureHelper].Assembly.Location) -Destination $dllPath
        $dllPath = (Get-Item -LiteralPath $dllPath).FullName
        Clear-OpenAuthenticodeSignature -LiteralPath $dllPath
    }

    AfterEach {
        Remove-Item -LiteralPath $dllPath -Force
    }

    It "Gets error in PE binary without signature" {
        $filePath = [OpenAuthenticode.SignatureHelper].Assembly.Location

        $actual = Get-OpenAuthenticodeSignature -path $filePath -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$filePath' does not contain an authenticode signature"
    }

    It "Gets multiple signatures from PE with 2 hash algorithms" {
        $filePath = Join-Path $PSScriptRoot data paexec_1_30.exe
        $actual = Get-OpenAuthenticodeSignature -Path $filePath

        $actual.Count | Should -Be 2
        $actual[0].Path | Should -Be $filePath
        $actual[0].Certificate.Thumbprint | Should -Be BAE492CDA57A6483A65371631409F7CF41989B2B
        $actual[0].HashAlgorithm | Should -Be SHA1
        $actual[0].TimeStampInfo.Certificate.Thumbprint | Should -Be F387224D8633829235A994BCBD8F96E9FE1C7C73
        $actual[0].TimeStampInfo.HashAlgorithm | Should -Be SHA256

        $actual[1].Path | Should -Be $filePath
        $actual[1].Certificate.Thumbprint | Should -Be BAE492CDA57A6483A65371631409F7CF41989B2B
        $actual[1].HashAlgorithm | Should -Be SHA256
        $actual[1].TimeStampInfo.Certificate.Thumbprint | Should -Be F387224D8633829235A994BCBD8F96E9FE1C7C73
        $actual[1].TimeStampInfo.HashAlgorithm | Should -Be SHA1
    }

    It "Signs a dll with the default hash" {
        $setParams = @{
            Path = $dllPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $dllPath
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $dllPath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs and adds a signature" {
        $setParams = @{
            Path = $dllPath
            Certificate = $cert
        }
        Add-OpenAuthenticodeSignature @setParams

        $actual = Add-OpenAuthenticodeSignature @setParams -HashAlgorithm SHA384
        $actual | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams
        $actual.Count | Should -Be 2
        $actual[0].HashAlgorithm | Should -Be SHA256
        $actual[0].Certificate.Thumbprint | Should -Be $cert.Thumbprint
        $actual[1].HashAlgorithm | Should -Be SHA384
        $actual[1].Certificate.Thumbprint | Should -Be $cert.Thumbprint

        $actual = Add-OpenAuthenticodeSignature @setParams -HashAlgorithm SHA512 -PassThru
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $dllPath
        $actual.HashAlgorithm | Should -Be SHA512
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams
        $actual.Count | Should -Be 3
        $actual[0].HashAlgorithm | Should -Be SHA256
        $actual[0].Certificate.Thumbprint | Should -Be $cert.Thumbprint
        $actual[1].HashAlgorithm | Should -Be SHA384
        $actual[1].Certificate.Thumbprint | Should -Be $cert.Thumbprint
        $actual[2].HashAlgorithm | Should -Be SHA512
        $actual[2].Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $dllPath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs and adds a signature with a timestamp" {
        $setParams = @{
            Path = $dllPath
            Certificate = $cert
            TimeStampServer = "http://timestamp.digicert.com"
        }
        Add-OpenAuthenticodeSignature @setParams
        Add-OpenAuthenticodeSignature @setParams -TimestampHashAlgorithm SHA384

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams
        $actual.Count | Should -Be 2
        $actual[0].HashAlgorithm | Should -Be SHA256
        $actual[0].TimeStampInfo | Should -BeOfType ([OpenAuthenticode.CounterSignature])
        $actual[0].TimeStampInfo.Certificate | Should -Not -BeNullOrEmpty
        $actual[0].TimeStampInfo.HashAlgorithm | Should -Be SHA256
        $actual[0].Certificate.Thumbprint | Should -Be $cert.Thumbprint
        $actual[1].HashAlgorithm | Should -Be SHA256
        $actual[1].TimeStampInfo | Should -BeOfType ([OpenAuthenticode.CounterSignature])
        $actual[1].TimeStampInfo.Certificate | Should -Not -BeNullOrEmpty
        $actual[1].TimeStampInfo.HashAlgorithm | Should -Be SHA384
        $actual[1].Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $dllPath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }


    It "Clears signed dll" {
        $setParams = @{
            Path = $dllPath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        Clear-OpenAuthenticodeSignature -Path $dllPath

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$dllPath' does not contain an authenticode signature"
    }

    It "Clears signed dll in -WhatIf" {
        $setParams = @{
            Path = $dllPath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        Clear-OpenAuthenticodeSignature -Path $dllPath -WhatIf

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.Certificates.Thumbprint | Should -Be $cert.Thumbprint
    }

    It "Clears unsigned dll without errors" {
        Clear-OpenAuthenticodeSignature -Path $dllPath

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$dllPath' does not contain an authenticode signature"
    }

    It "Write error on unsigned dll" {
        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$dllPath' does not contain an authenticode signature"
    }

    It "Signs a dll with hash <Name>" -TestCases @(
        @{Name = "SHA1" },
        @{Name = "SHA256" },
        @{Name = "SHA384" },
        @{Name = "SHA512" }
    ) {
        param ($Name)

        $setParams = @{
            Path = $dllPath
            Certificate = $cert
            HashAlgorithm = $Name
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $dllPath
        $actual.HashAlgorithm | Should -Be $Name
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $dllPath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signed with timestamp" {
        $setParams = @{
            Path = $dllPath
            Certificate = $cert
            HashAlgorithm = "SHA384"
            TimeStampServer = "http://timestamp.digicert.com"
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $dllPath
        $actual.HashAlgorithm | Should -Be SHA384
        $actual.TimeStampInfo | Should -BeOfType ([OpenAuthenticode.CounterSignature])
        $actual.TimeStampInfo.Certificate | Should -Not -BeNullOrEmpty
        $actual.TimeStampInfo.HashAlgorithm | Should -Be SHA384
        $actual.TimeStampInfo.TimeStamp | Should -BeOfType ([System.DateTime])
        $actual.TimeStampInfo.TimeStamp.Kind | Should -Be Utc
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $dllPath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signed with timestamp with hash <Name>" -TestCases @(
        @{Name = "SHA256" },
        @{Name = "SHA384" },
        @{Name = "SHA512" }
    ) {
        param ($Name)

        $setParams = @{
            Path = $dllPath
            Certificate = $cert
            TimeStampServer = "http://timestamp.digicert.com"
            TimeStampHashAlgorithm = $Name
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $dllPath
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeOfType ([OpenAuthenticode.CounterSignature])
        $actual.TimeStampInfo.Certificate | Should -Not -BeNullOrEmpty
        $actual.TimeStampInfo.HashAlgorithm | Should -Be $Name
        $actual.TimeStampInfo.TimeStamp | Should -BeOfType ([System.DateTime])
        $actual.TimeStampInfo.TimeStamp.Kind | Should -Be Utc
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $dllPath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs PE binary with extra data on the end" {
        $fs = [System.IO.File]::Open($dllPath, "Open", "Write")
        try {
            $null = $fs.Seek(0, 'End')
            $fs.WriteByte(1)
            $fs.WriteByte(2)
            $fs.WriteByte(3)
        }
        finally {
            $fs.Dispose()
        }

        $setParams = @{
            Path = $dllPath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $dllPath
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $dllPath
            $actual.Status | Should -Not -Be HashMismatch
        }

        Clear-OpenAuthenticodeSignature -Path $dllPath

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$dllPath' does not contain an authenticode signature"

        Set-OpenAuthenticodeSignature @setParams

        $actual = Get-OpenAuthenticodeSignature -Path $dllPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $dllPath
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $dllPath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }
}

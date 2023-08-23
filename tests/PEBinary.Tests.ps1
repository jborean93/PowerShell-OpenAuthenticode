. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "PE Binary Authenticode" {
    BeforeAll {
        $caCert = New-X509Certificate -Subject CN=PowerShellCA -Extension @(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        )
        $cert = New-CodeSigningCert -Subject CN=PowerShell -Issuer $caCert

        $caCertECDSA = New-X509Certificate -Subject CN=PowerShellCA-ECDSA -Extension @(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        ) -KeyAlgorithm ECDSA_nistP256
        $certECDSA = New-CodeSigningCert -Subject CN=PowerShell-ECDSA -Issuer $caCertECDSA -KeyAlgorithm ECDSA_nistP256

        $extraTrustStore = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $extraTrustStore.Add($caCert)
        $extraTrustStore.Add($caCertECDSA)
        $trustParams = @{
            TrustStore = $extraTrustStore
        }
    }

    BeforeEach {
        $exePath = Join-Path temp: test.exe
        $sourceExe = Join-Path $PSScriptRoot data test.exe
        Copy-Item -LiteralPath $sourceExe -Destination $exePath
        $exePath = (Get-Item -LiteralPath $exePath).FullName
        Clear-OpenAuthenticodeSignature -LiteralPath $exePath
    }

    AfterEach {
        Remove-Item -LiteralPath $exePath -Force
    }

    It "Gets error in PE binary without signature" {
        $actual = Get-OpenAuthenticodeSignature -path $sourceExe -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$sourceExe' does not contain an authenticode signature"
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
            Path = $exePath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $exePath
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $exePath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs and adds a signature" {
        $setParams = @{
            Path = $exePath
            Certificate = $cert
        }
        Add-OpenAuthenticodeSignature @setParams

        $actual = Add-OpenAuthenticodeSignature @setParams -HashAlgorithm SHA384
        $actual | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams
        $actual.Count | Should -Be 2
        $actual[0].HashAlgorithm | Should -Be SHA256
        $actual[0].Certificate.Thumbprint | Should -Be $cert.Thumbprint
        $actual[1].HashAlgorithm | Should -Be SHA384
        $actual[1].Certificate.Thumbprint | Should -Be $cert.Thumbprint

        $actual = Add-OpenAuthenticodeSignature @setParams -HashAlgorithm SHA512 -PassThru
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $exePath
        $actual.HashAlgorithm | Should -Be SHA512
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams
        $actual.Count | Should -Be 3
        $actual[0].HashAlgorithm | Should -Be SHA256
        $actual[0].Certificate.Thumbprint | Should -Be $cert.Thumbprint
        $actual[1].HashAlgorithm | Should -Be SHA384
        $actual[1].Certificate.Thumbprint | Should -Be $cert.Thumbprint
        $actual[2].HashAlgorithm | Should -Be SHA512
        $actual[2].Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $exePath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs and adds a signature with a timestamp" {
        $setParams = @{
            Path = $exePath
            Certificate = $cert
            TimeStampServer = "http://timestamp.digicert.com"
        }
        Add-OpenAuthenticodeSignature @setParams
        Add-OpenAuthenticodeSignature @setParams -TimestampHashAlgorithm SHA384

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams
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
            $actual = Get-AuthenticodeSignature -FilePath $exePath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }


    It "Clears signed dll" {
        $setParams = @{
            Path = $exePath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        Clear-OpenAuthenticodeSignature -Path $exePath

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$exePath' does not contain an authenticode signature"
    }

    It "Clears signed dll in -WhatIf" {
        $setParams = @{
            Path = $exePath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        Clear-OpenAuthenticodeSignature -Path $exePath -WhatIf

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.Certificates.Thumbprint | Should -Be $cert.Thumbprint
    }

    It "Clears unsigned dll without errors" {
        Clear-OpenAuthenticodeSignature -Path $exePath

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$exePath' does not contain an authenticode signature"
    }

    It "Write error on unsigned dll" {
        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$exePath' does not contain an authenticode signature"
    }

    It "Signs a dll with RSA hash <Name>" -TestCases @(
        @{Name = "SHA1" },
        @{Name = "SHA256" },
        @{Name = "SHA384" },
        @{Name = "SHA512" }
    ) {
        param ($Name)

        $setParams = @{
            Path = $exePath
            Certificate = $cert
            HashAlgorithm = $Name
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $exePath
        $actual.HashAlgorithm | Should -Be $Name
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $exePath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs a script with ECDSA hash <Name>" -TestCases @(
        @{Name = "SHA1" },
        @{Name = "SHA256" },
        @{Name = "SHA384" },
        @{Name = "SHA512" }
    ) {
        param ($Name)

        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test"

        $setParams = @{
            Path = $scriptPath
            Certificate = $certECDSA
            HashAlgorithm = $Name
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be $Name
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $certECDSA.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signed with timestamp" {
        $setParams = @{
            Path = $exePath
            Certificate = $cert
            HashAlgorithm = "SHA384"
            TimeStampServer = "http://timestamp.digicert.com"
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $exePath
        $actual.HashAlgorithm | Should -Be SHA384
        $actual.TimeStampInfo | Should -BeOfType ([OpenAuthenticode.CounterSignature])
        $actual.TimeStampInfo.Certificate | Should -Not -BeNullOrEmpty
        $actual.TimeStampInfo.HashAlgorithm | Should -Be SHA384
        $actual.TimeStampInfo.TimeStamp | Should -BeOfType ([System.DateTime])
        $actual.TimeStampInfo.TimeStamp.Kind | Should -Be Utc
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $exePath
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
            Path = $exePath
            Certificate = $cert
            TimeStampServer = "http://timestamp.digicert.com"
            TimeStampHashAlgorithm = $Name
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $exePath
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeOfType ([OpenAuthenticode.CounterSignature])
        $actual.TimeStampInfo.Certificate | Should -Not -BeNullOrEmpty
        $actual.TimeStampInfo.HashAlgorithm | Should -Be $Name
        $actual.TimeStampInfo.TimeStamp | Should -BeOfType ([System.DateTime])
        $actual.TimeStampInfo.TimeStamp.Kind | Should -Be Utc
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $exePath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs PE binary with extra data on the end" {
        $fs = [System.IO.File]::Open($exePath, "Open", "Write")
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
            Path = $exePath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $exePath
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $exePath
            $actual.Status | Should -Not -Be HashMismatch
        }

        Clear-OpenAuthenticodeSignature -Path $exePath

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$exePath' does not contain an authenticode signature"

        Set-OpenAuthenticodeSignature @setParams

        $actual = Get-OpenAuthenticodeSignature -Path $exePath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $exePath
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $exePath
            $actual.Status | Should -Not -Be HashMismatch
        }
    }
}

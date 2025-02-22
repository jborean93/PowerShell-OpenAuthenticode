. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "PowerShell Authenticode" {
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

    It "Signs a script with default hash" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs a small script with default hash" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value '"a"'

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs ps1xml script" {
        $scriptPath = New-Item -Path temp: -Name script.ps1xml -Force -Value "<?xml version=`"1.0`" encoding=`"utf-8`"?>`n<Configuration />"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs and adds a signature" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        Add-OpenAuthenticodeSignature @setParams

        $actual = Add-OpenAuthenticodeSignature @setParams -HashAlgorithm SHA384
        $actual | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual.Count | Should -Be 2
        $actual[0].HashAlgorithm | Should -Be SHA256
        $actual[0].Certificate.Thumbprint | Should -Be $cert.Thumbprint
        $actual[1].HashAlgorithm | Should -Be SHA384
        $actual[1].Certificate.Thumbprint | Should -Be $cert.Thumbprint

        $actual = Add-OpenAuthenticodeSignature @setParams -HashAlgorithm SHA512 -PassThru
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA512
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual.Count | Should -Be 3
        $actual[0].HashAlgorithm | Should -Be SHA256
        $actual[0].Certificate.Thumbprint | Should -Be $cert.Thumbprint
        $actual[1].HashAlgorithm | Should -Be SHA384
        $actual[1].Certificate.Thumbprint | Should -Be $cert.Thumbprint
        $actual[2].HashAlgorithm | Should -Be SHA512
        $actual[2].Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs and adds a signature with a timestamp" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
            TimeStampServer = "http://timestamp.digicert.com"
        }
        Add-OpenAuthenticodeSignature @setParams
        Add-OpenAuthenticodeSignature @setParams -TimestampHashAlgorithm SHA384

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
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
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Clears signed script" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        Clear-OpenAuthenticodeSignature -Path $scriptPath

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$($scriptPath.FullName)' does not contain an authenticode signature"
    }

    It "Clears signed script in -WhatIf" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        Clear-OpenAuthenticodeSignature -Path $scriptPath -WhatIf

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.Certificates.Thumbprint | Should -Be $cert.Thumbprint
    }

    It "Clears unsigned script without errors" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        Clear-OpenAuthenticodeSignature -Path $scriptPath

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$($scriptPath.FullName)' does not contain an authenticode signature"
    }

    It "Detects a tampered file" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        $existing = Get-Content -LiteralPath $scriptPath -Raw
        [System.IO.File]::WriteAllText($scriptPath.FullName, "# test`r`n$existing")

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "Signature mismatch: * != *"
    }

    It "Invalidates signed script with content beyond the signature" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        Add-Content -LiteralPath $scriptPath -Value "Write-Host other"

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$($scriptPath.FullName)' does not contain an authenticode signature"
    }

    It "Write error on unsigned file" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$($scriptPath.FullName)' does not contain an authenticode signature"
    }

    It "Gets cert failure when using untrusted cert" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "Certificate trust could not be established. *"

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -SkipCertificateCheck
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs file with -PassThru" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
            PassThru = $true
        }
        $actual = Set-OpenAuthenticodeSignature @setParams

        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs file with -WhatIf" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
            WhatIf = $true
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -ErrorAction SilentlyContinue -ErrorVariable err @trustParams
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1
        [string]$err[0] | Should -Be "File '$scriptPath' does not contain an authenticode signature"
    }

    It "Signs a script with RSA hash <Name>" -TestCases @(
        @{Name = "SHA256" },
        @{Name = "SHA384" },
        @{Name = "SHA512" }
    ) {
        param ($Name)

        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
            HashAlgorithm = $Name
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be $Name
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
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
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
            HashAlgorithm = "SHA384"
            TimeStampServer = "http://timestamp.digicert.com"
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA384
        $actual.TimeStampInfo | Should -BeOfType ([OpenAuthenticode.CounterSignature])
        $actual.TimeStampInfo.Certificate | Should -Not -BeNullOrEmpty
        $actual.TimeStampInfo.HashAlgorithm | Should -Be SHA384
        $actual.TimeStampInfo.TimeStamp | Should -BeOfType ([System.DateTime])
        $actual.TimeStampInfo.TimeStamp.Kind | Should -Be Utc
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signed with timestamp with hash <Name>" -TestCases @(
        @{Name = "SHA256" },
        @{Name = "SHA384" },
        @{Name = "SHA512" }
    ) {
        param ($Name)

        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
            TimeStampServer = "http://timestamp.digicert.com"
            TimeStampHashAlgorithm = $Name
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeOfType ([OpenAuthenticode.CounterSignature])
        $actual.TimeStampInfo.Certificate | Should -Not -BeNullOrEmpty
        $actual.TimeStampInfo.HashAlgorithm | Should -Be $Name
        $actual.TimeStampInfo.TimeStamp | Should -BeOfType ([System.DateTime])
        $actual.TimeStampInfo.TimeStamp.Kind | Should -Be Utc
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Gets timestamp info from Authenticode signed script" {
        <#
        Generated with on a Windows host (see common.ps1 for New-CodeSigningCert)
            $cert = New-CodeSigningCert -Subject CN=PowerShell
            Set-Content C:\temp\test.ps1 'Write-Host test'
            Set-AuthenticodeSignature -FilePath C:\temp\test.ps1 -Certificate $cert -TimestampServer http://timestamp.digicert.com
        #>
        $scriptPath = Join-Path $PSScriptRoot data authenticode-timestamp.ps1
        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -SkipCertificateCheck

        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeOfType ([OpenAuthenticode.CounterSignature])
        $actual.TimeStampInfo.Certificate.SubjectName.Name | Should -Be "CN=DigiCert Timestamp 2022 - 2, O=DigiCert, C=US"
        $actual.TimeStampInfo.Certificate.Thumbprint | Should -Be "F387224D8633829235A994BCBD8F96E9FE1C7C73"
        $actual.TimeStampInfo.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo.TimeStamp.ToFileTimeUtc() | Should -Be 133233320890000000  # 2023-03-15T05:34:49
        $actual.Certificate.Thumbprint | Should -Be "FA6CB31E8491104CFD561284F2A743A88631FC23"
    }

    It "Fails on expired signature" {
        $scriptPath = Join-Path $PSScriptRoot data expired-no-timestamp.ps1

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -SkipCertificateCheck
        $extraTrustStore = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $extraTrustStore.Add($actual.Certificate)

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -TrustStore $extraTrustStore -ErrorAction SilentlyContinue -ErrorVariable err
        $actual | Should -BeNullOrEmpty
        $err.Count | Should -Be 1

        $expected = if ($IsWindows) {
            "*A required certificate is not within its validity period*"
        }
        else {
            "*certificate has expired"
        }
        [string]$err[0] | Should -BeLike $expected
    }

    It "Works with expired signature but was timestamped" {
        $scriptPath = Join-Path $PSScriptRoot data expired-timestamp.ps1

        # Call it initially to get the cert that signed it for trusting
        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -SkipCertificateCheck

        # Call it again without -SkipCertificateCheck but with a custom trust
        # store to ensure the timestamp doesn't matter
        $extraTrustStore = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $extraTrustStore.Add($actual.Certificate)
        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -TrustStore $extraTrustStore

        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeOfType ([OpenAuthenticode.CounterSignature])
        $actual.TimeStampInfo.Certificate.SubjectName.Name | Should -Be "CN=DigiCert Timestamp 2022 - 2, O=DigiCert, C=US"
        $actual.TimeStampInfo.Certificate.Thumbprint | Should -Be "F387224D8633829235A994BCBD8F96E9FE1C7C73"
        $actual.TimeStampInfo.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo.TimeStamp.ToFileTimeUtc() | Should -Be 133233811810000000  # 2023-03-15T19:13:01
        $actual.Certificate.Thumbprint | Should -Be "FAC502505B5A24C06E9620AFA93C070406396E65"
        $actual.Certificate.NotAfter | Should -BeLessThan ([DateTime]::Now)
    }

    It "Signs files without BOM - <Scenario>" -TestCases @(
        @{
            Scenario = 'UTF-8 sequence across 2 octets'
            Content = [byte[]]@(0x74, 0x65, 0x73, 0x74, 0xC3, 0xA9)
        }
        @{
            Scenario = 'UTF-8 sequence across 3 octets'
            Content = [byte[]]@(0x74, 0x65, 0x73, 0x74, 0xE1, 0xB4, 0x81)
        }
        @{
            Scenario = 'UTF-8 sequence across 4 octets'
            Content = [byte[]]@(0x74, 0x65, 0x73, 0x74, 0xF0, 0x9D, 0x84, 0x9E)
        }
        @{
            Scenario = 'UTF-8 sequence present just before 32 bytes'
            Content = [System.Text.UTF8Encoding]::new($false).GetBytes("$('a' * 30)$([char]0xE9)")
        }
        @{
            Scenario = 'UTF-8 sequence that gets cut at 32 bytes'
            Content = [System.Text.UTF8Encoding]::new($false).GetBytes("$('a' * 31)$([char]0xE9)")
        }
        @{
            Scenario = 'UTF-8 sequence after 32 bytes'
            Content = [System.Text.UTF8Encoding]::new($false).GetBytes("$('a' * 32)$([char]0xE9)")
        }
        @{
            Scenario = 'Invalid UTF-8 sequence before 32 bytes'
            Content = [byte[]]@(0x20, 0xC3, 0xA9, 0x20, 0xE9, 0x74)
        }
        @{
            Scenario = 'Signed octet with invalid UTF-8 length'
            Content = [byte[]]@(0x80, 0x74, 0x65, 0x73, 0x74)
        }
        @{
            Scenario = 'No non-ASCII chars'
            Content = [System.Text.Encoding]::ASCII.GetBytes("Write-Host cafe`n")
        }
    ) {
        param($Content)

        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        [System.IO.File]::WriteAllBytes($scriptPath.FullName, $Content)

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs file with Unicode encoding" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        $encoding = [System.Text.Encoding]::Unicode
        [System.IO.File]::WriteAllText($scriptPath.FullName, "Write-Host caf$([char]0x00E9)", $encoding)

        # Unicode has a BOM so no need for an explicit Encoding param

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs file with Unicode BE encoding" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        $encoding = [System.Text.UnicodeEncoding]::new($true, $true)
        [System.IO.File]::WriteAllText($scriptPath.FullName, "Write-Host caf$([char]0x00E9)", $encoding)

        # Unicode BE has a BOM so no need for an explicit Encoding param

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs file with UTF-8 encoding" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        $encoding = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($scriptPath.FullName, "Write-Host caf$([char]0x00E9)", $encoding)

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs file with UTF-8 encoding longer than 32 bytes" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        $encoding = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($scriptPath.FullName, "$('a' * 32)$([char]0x00E9)", $encoding)

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs file with explicit encoding <Encoding>" -TestCases @(
        @{ Encoding = 'ASCII'; EncodingObject = [System.Text.Encoding]::ASCII }
        @{ Encoding = 'BigEndianUnicode'; EncodingObject = [System.Text.UnicodeEncoding]::new($true, $true) }
        @{ Encoding = 'ANSI'; EncodingObject = [System.Text.Encoding]::GetEncoding([CultureInfo]::CurrentCulture.TextInfo.ANSICodePage) }
        @{ Encoding = 'BigEndianUtf32'; EncodingObject = [System.Text.UTF32Encoding]::new($true, $true) }
        @{ Encoding = 'Unicode'; EncodingObject = [System.Text.UnicodeEncoding]::new() }
        @{ Encoding = 'UTF8'; EncodingObject = [System.Text.UTF8Encoding]::new() }
        @{ Encoding = 'UTF8Bom'; EncodingObject = [System.Text.UTF8Encoding]::new($true) }
        @{ Encoding = 'UTF8NoBom'; EncodingObject = [System.Text.UTF8Encoding]::new($false) }
        @{ Encoding = 'UTF32'; EncodingObject = [System.Text.UTF32Encoding]::new() }
        @{ Encoding = 'windows-1252'; EncodingObject = [System.Text.Encoding]::GetEncoding('windows-1252') }
        @{ Encoding = 65001; EncodingObject = [System.Text.UTF8Encoding]::new() }
        @{ Encoding = [System.Text.UTF8Encoding]::new(); EncodingOBject = [System.Text.UTF8Encoding]::new() }
    ) {
        param($Encoding, $EncodingObject)

        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        [System.IO.File]::WriteAllText($scriptPath.FullName, "Write-Host caf$([char]0x00E9)", $EncodingObject)

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
            Encoding = $Encoding
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -Encoding $Encoding @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs file with UTF-8 with BOM encoding" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        $encoding = [System.Text.UTF8Encoding]::new($true)
        [System.IO.File]::WriteAllText($scriptPath.FullName, "Write-Host caf$([char]0x00E9)", $encoding)

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs file without extension" {
        $scriptPath = New-Item -Path temp: -Name script -Force -Value "Write-Host test`r`n"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
            Provider = 'PowerShell'
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -Provider PowerShell @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint
    }

    It "Signs file with no end newline" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        [System.IO.File]::WriteAllText($scriptPath.FullName, "Write-Host test")

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs file with ending newline <Label>" -TestCases @(
        @{ Label = "\n"; Value = "`n" }
        @{ Label = "\r\n"; Value = "`r`n" }
        @{ Label = "\n\n"; Value = "`n`n" }
        @{ Label = "\r\n\r\n"; Value = "`r`n`r`n" }
        @{ Label = "\r\n\n"; Value = "`r`n`n" }
    ) {
        param ($Label, $Value)

        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        [System.IO.File]::WriteAllText($scriptPath.FullName, "Write-Host test$Value")

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -Be $scriptPath.FullName
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs file with string content" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        $content = Get-Content $scriptPath -Raw
        $actual = Get-OpenAuthenticodeSignature -Content $content -Provider PowerShell @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -BeNullOrEmpty
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint
    }

    It "Signs file with string content - Unicode file" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        $encoding = [System.Text.Encoding]::Unicode
        [System.IO.File]::WriteAllText($scriptPath.FullName, "Write-Host test", $encoding)

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        $bom = $encoding.GetString($encoding.GetPreamble())
        $content = $bom + (Get-Content $scriptPath -Raw)
        $actual = Get-OpenAuthenticodeSignature -Content $content -Provider PowerShell @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -BeNullOrEmpty
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint
    }

    It "Signs file with bytes content" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        $content = Get-Content $scriptPath -Raw -AsByteStream
        $actual = Get-OpenAuthenticodeSignature -RawContent $content -Provider PowerShell @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -BeNullOrEmpty
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint
    }

    It "Signs file with bytes content - Unicode file" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        $encoding = [System.Text.Encoding]::Unicode
        [System.IO.File]::WriteAllText($scriptPath.FullName, "Write-Host test", $encoding)

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
        }
        Set-OpenAuthenticodeSignature @setParams

        $content = Get-Content $scriptPath -Raw -AsByteStream
        $actual = Get-OpenAuthenticodeSignature -RawContent $content -Provider PowerShell @trustParams
        $actual | Should -BeOfType ([System.Security.Cryptography.Pkcs.SignedCms])
        $actual.Path | Should -BeNullOrEmpty
        $actual.HashAlgorithm | Should -Be SHA256
        $actual.TimeStampInfo | Should -BeNullOrEmpty
        $actual.Certificate.Thumbprint | Should -Be $cert.Thumbprint
    }
}

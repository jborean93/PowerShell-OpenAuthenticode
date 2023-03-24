. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Describe "PowerShell Authenticode" {
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

    It "Signs a script with hash <Name>" -TestCases @(
        @{Name = "SHA1" },
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

    It "Signs file with windows-1252 encoding" {
        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force
        $encoding = [System.Text.Encoding]::GetEncoding([CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
        [System.IO.File]::WriteAllText($scriptPath.FullName, "Write-Host caf$([char]0x00E9)`n", $encoding)

        $setParams = @{
            Path = $scriptPath
            Certificate = $cert
            Encoding = $encoding
        }
        $res = Set-OpenAuthenticodeSignature @setParams
        $res | Should -BeNullOrEmpty

        # On Linux the default encoding without a BOM is UTF-8 so this will fail validation
        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -ErrorAction SilentlyContinue -ErrorVariable err @trustParams
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike 'Signature mismatch: * != *'

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -Encoding ANSI @trustParams
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

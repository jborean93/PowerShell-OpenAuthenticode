. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Function Test-Available {
    [OutputType([bool])]
    [CmdletBinding()]
    param ()

    if (
        $env:AZURE_TENANT_ID -and
        (
            (
                $env:AZURE_CONNECT_APPLICATION -and
                (Get-Command -Name Connect-AzAccount -ErrorAction SilentlyContinue)
            ) -or
            (
                $env:AZURE_CLIENT_ID -and
                (
                    $env:AZURE_CLIENT_SECRET -or
                    $env:AZURE_CLIENT_CERTIFICATE_PATH
                )
            )
        ) -and
        $env:AZURE_KEYVAULT_NAME
    ) {
        $true
    }
    else {
        $false
    }
}

Describe "Get-OpenAuthenticodeAzKey" -Skip:(-not (Test-Available)) {
    BeforeAll {
        if ($env:AZURE_CONNECT_APPLICATION -and (Get-Command -Name Connect-AzAccount -ErrorAction SilentlyContinue)) {
            Connect-AzAccount -TenantId $env:AZURE_TENANT_ID
        }

        $rsaKey = if ($env:AZURE_KEYVAULT_RSA_CERTIFICATE) {
            Get-OpenAuthenticodeAzKey -Vault $env:AZURE_KEYVAULT_NAME -Certificate $env:AZURE_KEYVAULT_RSA_CERTIFICATE
        }
        $ecdsaP256Key = if ($env:AZURE_KEYVAULT_ECDSA_P256_CERTIFICATE) {
            Get-OpenAuthenticodeAzKey -Vault $env:AZURE_KEYVAULT_NAME -Certificate $env:AZURE_KEYVAULT_ECDSA_P256_CERTIFICATE
        }
        $ecdsaP256KKey = if ($env:AZURE_KEYVAULT_ECDSA_P256K_CERTIFICATE) {
            Get-OpenAuthenticodeAzKey -Vault $env:AZURE_KEYVAULT_NAME -Certificate $env:AZURE_KEYVAULT_ECDSA_P256K_CERTIFICATE
        }
        $ecdsaP384Key = if ($env:AZURE_KEYVAULT_ECDSA_P384_CERTIFICATE) {
            Get-OpenAuthenticodeAzKey -Vault $env:AZURE_KEYVAULT_NAME -Certificate $env:AZURE_KEYVAULT_ECDSA_P384_CERTIFICATE
        }
        $ecdsaP521Key = if ($env:AZURE_KEYVAULT_ECDSA_P521_CERTIFICATE) {
            Get-OpenAuthenticodeAzKey -Vault $env:AZURE_KEYVAULT_NAME -Certificate $env:AZURE_KEYVAULT_ECDSA_P521_CERTIFICATE
        }
        $ecdsaKeys = @{
            P256 = $ecdsaP256Key
            P256K = $ecdsaP256KKey
            P384 = $ecdsaP384Key
            P521 = $ecdsaP521Key
        }
    }
    AfterAll {
        if ($rsaKey) { $rsaKey.Dispose() }
        if ($ecdsaP256Key) { $ecdsaP256Key.Dispose() }
        if ($ecdsaP256KKey) { $ecdsaP256KKey.Dispose() }
        if ($ecdsaP384Key) { $ecdsaP384Key.Dispose() }
        if ($ecdsaP521Key) { $ecdsaP521Key.Dispose() }
    }

    It "Signs with RSA key and hash <Name>" -TestCases @(
        @{ Name = "Default" }
        @{ Name = "SHA1" }
        @{ Name = "SHA256" }
        @{ Name = "SHA384" }
        @{ Name = "SHA512" }
    ) {
        param ($Name)

        if (-not $rsaKey) {
            Set-ItResult -Skipped -Because "Env var AZURE_KEYVAULT_RSA_CERTIFICATE is not set"
        }

        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"
        $setParams = @{
            Path = $scriptPath
            Key = $rsaKey
        }
        if ($Name -eq "Default") {
            $Name = "SHA256"
        }
        else {
            $setParams.HashAlgorithm = $Name
        }
        Set-OpenAuthenticodeSignature @setParams

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -SkipCertificateCheck
        $actual.HashAlgorithm | Should -Be $Name
        $actual.Certificate.GetKeyAlgorithm() | Should -Be "1.2.840.113549.1.1.1"  # RSA

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "Signs with ECDSA <KeyAlgorithm> key" -TestCases @(
        @{ KeyAlgorithm = "P256"; ExpectedAlgorithm = "SHA256" }
        @{ KeyAlgorithm = "P256K"; ExpectedAlgorithm = "SHA256" }
        @{ KeyAlgorithm = "P384"; ExpectedAlgorithm = "SHA384" }
        @{ KeyAlgorithm = "P521"; ExpectedAlgorithm = "SHA512" }
    ) {
        param ($KeyAlgorithm, $ExpectedAlgorithm)

        if (-not $ecdsaKeys[$KeyAlgorithm]) {
            Set-ItResult -Skipped -Because "Env var AZURE_KEYVAULT_ECDSA_$($KeyAlgorithm)_CERTIFICATE is not set"
        }

        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"
        $setParams = @{
            Path = $scriptPath
            Key = $ecdsaKeys[$KeyAlgorithm]
        }
        Set-OpenAuthenticodeSignature @setParams

        $actual = Get-OpenAuthenticodeSignature -Path $scriptPath -SkipCertificateCheck
        $actual.HashAlgorithm | Should -Be $ExpectedAlgorithm
        $actual.Certificate.GetKeyAlgorithm() | Should -Be "1.2.840.10045.2.1"  # ECC

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }

    It "It attempts to sign ECDSA key with the wrong algorithm" {
        $key = $null
        foreach ($kvp in $ecdsaKeys.GetEnumerator()) {
            if ($null -ne $kvp.Value) {
                $key = $kvp.Value
                break
            }
        }

        if (-not $key) {
            Set-ItResult -Skipped -Because "No ECDSA env vars AZURE_KEYVAULT_ECDSA_*_CERTIFICATE are set"
        }

        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"
        $setParams = @{
            Path = $scriptPath
            Key = $key
            HashAlgorithm = 'SHA1'
        }
        Set-OpenAuthenticodeSignature @setParams -ErrorAction SilentlyContinue -ErrorVariable err
        $err.Count | Should -Be 1
        [string]$err[0] | Should -BeLike "The digest size 20 is not valid for digest algorithm of this ECDSA key '*'. Ensure -HashAlgorithm * was specified or omit *"
    }
}

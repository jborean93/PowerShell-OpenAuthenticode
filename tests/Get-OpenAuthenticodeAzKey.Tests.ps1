. ([IO.Path]::Combine($PSScriptRoot, 'common.ps1'))

Function Test-Available {
    [OutputType([bool])]
    [CmdletBinding()]
    param ()

    if (
        $env:AZURE_TENANT_ID -and
        $env:AZURE_CLIENT_ID -and
        (
            $env:AZURE_CLIENT_SECRET -or
            $env:AZURE_CLIENT_CERTIFICATE_PATH
        ) -and
        $env:AZURE_KEYVAULT_NAME -and
        (
            $env:AZURE_KEYVAULT_RSA_CERTIFICATE
        )
    ) {
        $true
    }
    else {
        $false
    }
}

Describe "Get-OpenAuthenticodeAzKey" -Skip:(-not (Test-Available)) {
    BeforeAll {
        $rsaKey = if ($env:AZURE_KEYVAULT_RSA_CERTIFICATE) {
            Get-OpenAuthenticodeAzKey -Vault $env:AZURE_KEYVAULT_NAME -Certificate $env:AZURE_KEYVAULT_RSA_CERTIFICATE
        }

    }
    AfterAll {
        if ($rsaKey) { $rsaKey.Dispose() }
    }

    It "Signs with RSA key and hash <Name>" -TestCases @(
        @{Name = "Default" }
        @{Name = "SHA1" }
        @{Name = "SHA256" }
        @{Name = "SHA384" }
        @{Name = "SHA512" }
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
        $actual.HashAlgorithmName | Should -Be $Name
        $actual.Certificate.GetKeyAlgorithm() | Should -Be "1.2.840.113549.1.1.1"

        If (Get-Command -Name Get-AuthenticodeSignature -ErrorAction Ignore) {
            $actual = Get-AuthenticodeSignature -FilePath $scriptPath.FullName
            $actual.Status | Should -Not -Be HashMismatch
        }
    }
}

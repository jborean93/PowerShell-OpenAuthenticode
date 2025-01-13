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
            ) -or
            $env:AZURE_TOKEN_SOURCE
        ) -and
        $env:AZURE_TRUSTED_SIGNER_ACCOUNT -and
        $env:AZURE_TRUSTED_SIGNER_PROFILE -and
        $env:AZURE_TRUSTED_SIGNER_ENDPOINT

    ) {
        $true
    }
    else {
        $false
    }
}

Describe "Get-OpenAuthenticodeAzTrustedSigner" -Skip:(-not (Test-Available)) {
    BeforeAll {
        if ($env:AZURE_CONNECT_APPLICATION -and (Get-Command -Name Connect-AzAccount -ErrorAction SilentlyContinue)) {
            Connect-AzAccount -TenantId $env:AZURE_TENANT_ID
        }

        $keyParams = @{
            AccountName = $env:AZURE_TRUSTED_SIGNER_ACCOUNT
            ProfileName = $env:AZURE_TRUSTED_SIGNER_PROFILE
            Endpoint = $env:AZURE_TRUSTED_SIGNER_ENDPOINT
        }
        if($env:AZURE_TOKEN_SOURCE) {
            $keyParams.TokenSource = $env:AZURE_TOKEN_SOURCE
        }
        $key = Get-OpenAuthenticodeAzTrustedSigner @keyParams
    }
    AfterAll {
        if ($key) { $key.Dispose() }
    }

    It "Signs with RSA key and hash <Name>" -TestCases @(
        @{ Name = "Default" }
        @{ Name = "SHA256" }
        @{ Name = "SHA384" }
        @{ Name = "SHA512" }
    ) {
        param ($Name)

        if (-not $key) {
            Set-ItResult -Skipped -Because "Env var AZURE_TRUSTED_SIGNER_ACCOUNT or AZURE_TRUSTED_SIGNER_PROFILE or AZURE_TRUSTED_SIGNER_ENDPOINT is not set"
        }

        $scriptPath = New-Item -Path temp: -Name script.ps1 -Force -Value "Write-Host test`r`n"
        $setParams = @{
            Path = $scriptPath
            Key = $key
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
}

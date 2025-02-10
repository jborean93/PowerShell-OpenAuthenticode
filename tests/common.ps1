$moduleName = (Get-Item ([IO.Path]::Combine($PSScriptRoot, '..', 'module', '*.psd1'))).BaseName
$manifestPath = [IO.Path]::Combine($PSScriptRoot, '..', 'output', $moduleName)

if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue)) {
    Import-Module $manifestPath
}

if (-not (Get-Variable IsWindows -ErrorAction SilentlyContinue)) {
    # Running WinPS so guaranteed to be Windows.
    Set-Variable -Name IsWindows -Value $true -Scope Global
}

# Newer Linux distributions do not support SHA1 signatures in their
# OpenSSL policies. This disables the SHA1 tests if this fails.
if (-not (Get-Variable -Name SkipSha1 -Scope Global -ErrorAction SilentlyContinue)) {
    $Global:SkipSha1 = $false
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
        $null = $rsa.SignData(
            [Array]::Empty[byte](),
            [System.Security.Cryptography.HashAlgorithmName]::SHA1,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }
    catch [System.Security.Cryptography.CryptographicException] {
        $Global:SkipSha1 = $true
    }
    finally {
        $rsa.Dispose()
    }
}

Function global:New-X509Certificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter()]
        [System.Security.Cryptography.HashAlgorithmName]
        $HashAlgorithm = "SHA256",

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Issuer,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Extension[]]
        $Extension,

        [Parameter()]
        [string]
        $KeyAlgorithm = 'RSA'
    )

    if ($KeyAlgorithm -eq 'RSA') {
        $key = [System.Security.Cryptography.RSA]::Create(4096)
        $copyFunc = { [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($args[0], $key) }
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject,
            $key,
            $HashAlgorithm,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }
    elseif ($KeyAlgorithm.StartsWith('ECDSA_', [System.StringComparison]::OrdinalIgnoreCase)) {
        $curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName($KeyAlgorithm.Substring(6))
        $key = [System.Security.Cryptography.ECDsa]::Create($curve)
        $copyFunc = { [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($args[0], $key) }
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject,
            $key,
            $HashAlgorithm)
    }
    # I don't know too much about algorithms but ECDH and ECDSA seem to be the same
    # I think ECDH is just the public key algorithm or something
    # elseif ($KeyAlgorithm.StartsWith('ECDH_', [System.StringComparison]::OrdinalIgnoreCase)) {
    #     $curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName($KeyAlgorithm.Substring(5))
    #     $key = [System.Security.Cryptography.ECDiffieHellman]::Create($curve)
    #     $copyFunc = { $args[0].CopyWithPrivateKey($key) }
    #     $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    #         $Subject,
    #         [System.Security.Cryptography.X509Certificates.PublicKey]::new($key),
    #         $HashAlgorithm)
    # }
    else {
        throw "Unsupported KeyAlgorithm '$KeyAlgorithm'"
    }

    $Extension | ForEach-Object { $request.CertificateExtensions.Add($_) }
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false)
    )

    if ($Issuer) {
        $Issuer.Extensions | ForEach-Object {
            if ($_ -isnot [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]) {
                return
            }

            # Use X509AuthorityKeyIdentifierExtension when pwsh 7.2 is dropped
            $skid = $_.Rawdata

            $akid = [byte[]]::new($skid.Length + 2)
            $akid[0] = 0x30
            $akid[1] = $skid.Length
            $akid[2] = 0x80
            [System.Buffer]::BlockCopy($skid, 1, $akid, 3, $skid.Length - 1)
            $request.CertificateExtensions.Add(
                [System.Security.Cryptography.X509Certificates.X509Extension]::new("2.5.29.35", $akid, $false)
            )
        }

        $notBefore = $Issuer.NotBefore
        $notAfter = $Issuer.NotAfter
        $serialNumber = [byte[]]::new(9)
        [System.Random]::new().NextBytes($serialNumber)

        $cert = $request.Create($Issuer, $notBefore, $notAfter, $serialNumber)

        # For whatever reason Create does not create an X509 cert with the private key.
        &$copyFunc $cert
    }
    else {
        $notBefore = [DateTimeOffset]::UtcNow.AddDays(-1)
        $notAfter = [DateTimeOffset]::UtcNow.AddDays(30)
        $request.CreateSelfSigned($notBefore, $notAfter)
    }
}

Function global:New-CodeSigningCert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter()]
        [System.Security.Cryptography.HashAlgorithmName]
        $HashAlgorithm = "SHA256",

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Issuer,

        [Parameter()]
        [string]
        $KeyAlgorithm = 'RSA'
    )

    $enhancedKeyUsageOids = [System.Security.Cryptography.OidCollection]::new()
    $null = $enhancedKeyUsageOids.Add(
        [System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.3")) # Code Signing

    $extensions = @(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
            $true)

        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
            $enhancedKeyUsageOids, $true)
    )

    New-X509Certificate @PSBoundParameters -Extension $extensions
}

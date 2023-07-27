using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace OpenAuthenticode.Shared;

public sealed class AzureKey : KeyProvider, IDisposable
{
    private readonly CryptographyClient _client;
    private readonly string _keyAlgorithm;
    private readonly Dictionary<string, SignatureAlgorithm> _algorithmMap;
    private readonly static byte[] _rsaSha1Digest = new byte[] {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
        0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
    };

    public override X509Certificate2 Certificate { get; }

    internal override AsymmetricAlgorithm Key { get; }

    private AzureKey(CryptographyClient client, X509Certificate2 cert)
    {
        _client = client;
        _keyAlgorithm = cert.GetKeyAlgorithm(); ;

        Certificate = cert;
        if (_keyAlgorithm == "1.2.840.113549.1.1.1") // RSA
        {
            _algorithmMap = new()
            {
                {HashAlgorithmName.SHA1.Name!, new SignatureAlgorithm("RSNULL")},
                {HashAlgorithmName.SHA256.Name!, SignatureAlgorithm.RS256},
                {HashAlgorithmName.SHA384.Name!, SignatureAlgorithm.RS384},
                {HashAlgorithmName.SHA512.Name!, SignatureAlgorithm.RS512},
            };
            Key = new AzureKeyVaultRSAKey(this);
        }
        // else if (_keyAlgorithm == "1.2.840.10045.2.1") // ECC
        // {
        //     _algorithmMap = new()
        //     {
        //         {HashAlgorithmName.SHA256.Name!, SignatureAlgorithm.ES256},
        //         {HashAlgorithmName.SHA384.Name!, SignatureAlgorithm.ES384},
        //         {HashAlgorithmName.SHA512.Name!, SignatureAlgorithm.ES512},
        //     };
        //     Key = new AzureKeyVaultECDSAKey(this);
        // }
        else
        {
            throw new NotImplementedException($"Azure Key vault does not support the key algorithm {_keyAlgorithm}");
        }
    }

    internal static AzureKey Create(string vaultName, string keyName)
    {
        string keyVaultUrl = $"https://{vaultName}.vault.azure.net/";

        DefaultAzureCredential cred = new(includeInteractiveCredentials: false);

        CertificateClient certClient = new(new Uri(keyVaultUrl), cred);
        KeyVaultCertificateWithPolicy certInfo = certClient.GetCertificate(keyName);
        X509Certificate2 cert = new(certInfo.Cer);

        Uri keyId = new($"{keyVaultUrl}keys/{keyName}/");
        CryptographyClient c = new(keyId, cred);
        return new AzureKey(c, cert);
    }

    internal byte[] Sign(byte[] hash, HashAlgorithmName hashAlgorithm)
    {
        if (!_algorithmMap.TryGetValue(hashAlgorithm.Name!, out var signatureAlgorithm))
        {
            throw new NotImplementedException($"Unknown algorithm {hashAlgorithm.Name} for {_keyAlgorithm}");
        }
        if (signatureAlgorithm == "RSNULL")
        {
            hash = CreateRSASha1Digest(hash);
        }

        return _client.Sign(signatureAlgorithm, hash).Signature;
    }

    private static byte[] CreateRSASha1Digest(byte[] hash)
    {
        byte[] pkcs1Digest = new byte[_rsaSha1Digest.Length + 20];
        _rsaSha1Digest.CopyTo(pkcs1Digest, 0);
        hash.CopyTo(pkcs1Digest, _rsaSha1Digest.Length);

        return pkcs1Digest;
    }

    public void Dispose()
    {
        Key?.Dispose();
        GC.SuppressFinalize(this);
    }
    ~AzureKey() => Dispose();
}

internal sealed class AzureKeyVaultRSAKey : RSA
{
    private readonly AzureKey _key;
    public AzureKeyVaultRSAKey(AzureKey key)
    {
        _key = key;
    }

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (padding.Mode != RSASignaturePaddingMode.Pkcs1)
        {
            throw new CryptographicException($"Unsupported padding mode {padding.Mode}");
        }

        return _key.Sign(hash, hashAlgorithm);
    }

    public override RSAParameters ExportParameters(bool includePrivateParameters) => throw new NotImplementedException();

    public override void ImportParameters(RSAParameters parameters) => throw new NotImplementedException();
}

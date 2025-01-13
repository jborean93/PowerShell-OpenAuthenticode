using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using AzureSignatureAlgorithm = Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm;

namespace OpenAuthenticode.Module;

public sealed class AzureKey : KeyProvider, IDisposable
{
    private readonly CryptographyClient _client;

    public override X509Certificate2 Certificate { get; }

    internal override AsymmetricAlgorithm Key { get; }

    internal override HashAlgorithmName? DefaultHashAlgorithm { get; }

    private AzureKey(CryptographyClient client, X509Certificate2 cert, string? curveName)
    {
        _client = client;
        Certificate = cert;

        using RSA? rsaPubKey = cert.GetRSAPublicKey();
        if (rsaPubKey != null)
        {
            Key = new AzureKeyVaultRSAKey(_client);
            return;
        }

        using ECDsa? ecdsaPubKey = cert.GetECDsaPublicKey();
        if (ecdsaPubKey != null)
        {
            int digestSize;
            AzureSignatureAlgorithm sigAlgo;
            if (curveName == CertificateKeyCurveName.P256)
            {
                DefaultHashAlgorithm = HashAlgorithmName.SHA256;
                sigAlgo = AzureSignatureAlgorithm.ES256;
                digestSize = 32;
            }
            else if (curveName == CertificateKeyCurveName.P256K)
            {
                DefaultHashAlgorithm = HashAlgorithmName.SHA256;
                sigAlgo = AzureSignatureAlgorithm.ES256K;
                digestSize = 32;
            }
            else if (curveName == CertificateKeyCurveName.P384)
            {
                DefaultHashAlgorithm = HashAlgorithmName.SHA384;
                sigAlgo = AzureSignatureAlgorithm.ES384;
                digestSize = 48;
            }
            else if (curveName == CertificateKeyCurveName.P521)
            {
                DefaultHashAlgorithm = HashAlgorithmName.SHA512;
                sigAlgo = AzureSignatureAlgorithm.ES512;
                digestSize = 64;
            }
            else
            {
                throw new NotImplementedException($"Unsupported ECDSA Key vault key with curve {curveName}");
            }

            Key = new AzureKeyVaultECDSAKey(_client, sigAlgo, digestSize, DefaultHashAlgorithm.ToString()!);
            return;
        }

        string keyAlgorithm = cert.PublicKey.Oid.Value ?? "";
        if (!string.IsNullOrWhiteSpace(cert.PublicKey.Oid.FriendlyName))
        {
            keyAlgorithm += $" - {cert.PublicKey.Oid.FriendlyName}";
        }
        throw new NotImplementedException($"Azure Key vault does not support the key algorithm {keyAlgorithm}");
    }

    internal static AzureKey Create(string vaultName, string keyName, AzureTokenSource tokenSource)
    {
        string keyVaultUrl = $"https://{vaultName}.vault.azure.net/";

        TokenCredential cred = TokenCredentialBuilder.GetTokenCredential(tokenSource);

        CertificateClient certClient = new(new Uri(keyVaultUrl), cred);
        KeyVaultCertificateWithPolicy certInfo = certClient.GetCertificate(keyName);
        X509Certificate2 cert = new(certInfo.Cer);

        string? curveName = certInfo.Policy.KeyCurveName?.ToString();
        CryptographyClient c = new(certInfo.KeyId, cred);
        return new AzureKey(c, cert, curveName);
    }

    public void Dispose()
    {
        Key?.Dispose();
        GC.SuppressFinalize(this);
    }
    ~AzureKey() => Dispose();
}

internal sealed class AzureKeyVaultRSAKey : AzureRSAKey
{
    private readonly CryptographyClient _client;

    public AzureKeyVaultRSAKey(CryptographyClient client)
    {
        _client = client;
    }

    public override byte[] SignHashCore(byte[] hash, string azureAlgorithm)
    {

        AzureSignatureAlgorithm sigAlgo = new(azureAlgorithm);
        return _client.Sign(sigAlgo, hash).Signature;
    }
}

internal sealed class AzureKeyVaultECDSAKey : ECDsa
{
    private readonly CryptographyClient _client;
    private readonly AzureSignatureAlgorithm _sigAlgo;
    private readonly int _digestSize;
    private readonly string _neededAlgorithm;

    public AzureKeyVaultECDSAKey(
        CryptographyClient client,
        AzureSignatureAlgorithm signatureAlgorithm,
        int digestSize,
        string neededAlgorithm
    )
    {
        _client = client;
        _digestSize = digestSize;
        _neededAlgorithm = neededAlgorithm;
        _sigAlgo = signatureAlgorithm;
    }

    public override byte[] SignHash(byte[] hash)
    {
        if (hash.Length != _digestSize)
        {
            string msg = "The digest size {0} is not valid for digest algorithm of this ECDSA key '{1}'. " +
            "Ensure -HashAlgorithm {1} was specified or omit the parameter to use the defaults.";
            throw new CryptographicException(string.Format(msg, hash.Length, _neededAlgorithm));
        }

        return _client.Sign(_sigAlgo, hash).Signature;
    }

    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        throw new NotImplementedException();
    }
}

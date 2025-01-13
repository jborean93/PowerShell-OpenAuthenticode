using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.CodeSigning;
using Azure.CodeSigning.Models;
using AzureSignatureAlgorithm = Azure.CodeSigning.Models.SignatureAlgorithm;

namespace OpenAuthenticode.Module;

public sealed class AzureTrustedSigner : KeyProvider, IDisposable
{
    private readonly CertificateProfileClient _client;

    public override X509Certificate2 Certificate { get; }

    internal override AsymmetricAlgorithm Key { get; }

    internal override HashAlgorithmName? DefaultHashAlgorithm { get; }

    public AzureTrustedSigner(
        CertificateProfileClient client,
        X509Certificate2 cert,
        string accountName,
        string profileName,
        string? correlationId)
    {
        _client = client;
        Certificate = cert;

        using RSA rsaPubKey = cert.GetRSAPublicKey()
            ?? throw new NotImplementedException("The Azure Trusted Signer key implementation currently only supports RSA keys.");
        Key = new AzureTrustedSignerRSAKey(_client, accountName, profileName, correlationId);
    }

    public void Dispose()
    {
        Key?.Dispose();
        GC.SuppressFinalize(this);
    }
    ~AzureTrustedSigner() => Dispose();
}

internal sealed class AzureTrustedSignerRSAKey : AzureRSAKey
{
    private readonly CertificateProfileClient _client;
    private readonly string _accountName;
    private readonly string _profileName;
    private readonly string? _correlationId;

    public AzureTrustedSignerRSAKey(
        CertificateProfileClient client,
        string accountName,
        string profileName,
        string? correlationId = null)
    {
        _client = client;
        _accountName = accountName;
        _profileName = profileName;
        _correlationId = correlationId;
    }

    public override byte[] SignHashCore(byte[] hash, string azureAlgorithm)
    {
        AzureSignatureAlgorithm sigAlgo = new(azureAlgorithm);

        SignRequest request = new(sigAlgo, hash);
        CertificateProfileSignOperation operation = _client.StartSign(
            codeSigningAccountName: _accountName,
            certificateProfileName: _profileName,
            body: request,
            xCorrelationId: _correlationId);
        SignStatus response = operation.WaitForCompletionAsync().GetAwaiter().GetResult();

        return response.Signature;
    }
}

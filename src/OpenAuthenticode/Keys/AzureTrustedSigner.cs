using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Azure.CodeSigning;
using Azure.CodeSigning.Models;
using OpenAuthenticode.Commands;
using AzureSignatureAlgorithm = Azure.CodeSigning.Models.SignatureAlgorithm;

namespace OpenAuthenticode.Keys;

public sealed class AzureTrustedSigner : KeyProvider
{
    private readonly CertificateProfileClient _client;
    private readonly string _accountName;
    private readonly string _profileName;
    private readonly string? _correlationId;

    public AzureTrustedSigner(
        CertificateProfileClient client,
        X509Certificate2 cert,
        string accountName,
        string profileName,
        string? correlationId)
            : base(
                cert,
                KeyType.RSA,
                supportsParallelSigning: true,
                allowedAlgorithms: [HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512])
    {
        _client = client;
        _accountName = accountName;
        _profileName = profileName;
        _correlationId = correlationId;
    }

    internal override async Task<byte[]> SignHashAsync(
        AsyncPipeline pipeline,
        string path,
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken)
    {
        string algorithmName = AzureKeyAlgorithms.GetAzureRsaAlgorithm(hashAlgorithm);
        SignRequest request = new(new AzureSignatureAlgorithm(algorithmName), hash);

        pipeline.WriteVerbose($"Starting Azure Trusted Signing operation for '{path}'.");
        CertificateProfileSignOperation operation = await _client.StartSignAsync(
            codeSigningAccountName: _accountName,
            certificateProfileName: _profileName,
            body: request,
            xCorrelationId: _correlationId,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        pipeline.WriteVerbose($"Waiting for Azure Trusted Signing operation for '{path}' to complete.");
        SignStatus response = await operation.WaitForCompletionAsync(
            cancellationToken: cancellationToken).ConfigureAwait(false);

        pipeline.WriteVerbose($"Azure Trusted Signing operation for '{path}' completed with status '{response.Status}'.");
        return response.Signature;
    }
}

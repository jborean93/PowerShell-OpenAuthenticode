using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Keys.Cryptography;
using AzureSignatureAlgorithm = Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm;

namespace OpenAuthenticode.Module;

public sealed class AzureKey : KeyProvider
{
    private readonly static byte[] _rsaSha1Digest = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
        0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
    ];

    private readonly CryptographyClient _client;
    private readonly AzureSignatureAlgorithm? _ecdsaAlgorithm;

    public AzureKey(
        CryptographyClient client,
        X509Certificate2 certificate,
        KeyType keyType,
        HashAlgorithmName[] allowedAlgorithms,
        HashAlgorithmName? defaultHashAlgorithm,
        AzureSignatureAlgorithm? ecdsaAlgorithm)
            : base(
                certificate,
                keyType,
                supportsParallelSigning: true,
                allowedAlgorithms: allowedAlgorithms,
                defaultHashAlgorithm: defaultHashAlgorithm)
    {
        _client = client;
        _ecdsaAlgorithm = ecdsaAlgorithm;
    }

    internal override async Task<byte[]> SignHashAsync(
        AsyncPSCmdlet cmdlet,
        string path,
        byte[] hash,
        HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA1)
        {
            hash = CreateRSASha1Digest(hash);
        }

        // ECDsa keys define the _signatureAlgorithm whereas RSA keys is based
        // on the hash algorithm requested.
        AzureSignatureAlgorithm sigAlgo = _ecdsaAlgorithm ??
            new(AzureKeyAlgorithms.GetAzureRsaAlgorithm(hashAlgorithm));

        cmdlet.WriteVerbose($"Starting Azure Key Vault Signing operation for '{path}'.");
        SignResult result = await _client.SignAsync(
            sigAlgo,
            hash,
            cancellationToken: cmdlet.CancelToken).ConfigureAwait(false);

        cmdlet.WriteVerbose($"Azure Key Vault Signing operation for '{path}'.");
        return result.Signature;
    }

    private static byte[] CreateRSASha1Digest(byte[] hash)
    {
        byte[] pkcs1Digest = new byte[_rsaSha1Digest.Length + 20];
        _rsaSha1Digest.CopyTo(pkcs1Digest, 0);
        hash.CopyTo(pkcs1Digest, _rsaSha1Digest.Length);

        return pkcs1Digest;
    }
}

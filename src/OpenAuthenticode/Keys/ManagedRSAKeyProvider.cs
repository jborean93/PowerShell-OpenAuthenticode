using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using OpenAuthenticode.Commands;

namespace OpenAuthenticode.Keys;

public sealed class ManagedRSAKeyProvider : KeyProvider
{
    private readonly RSA _rsa;

    public ManagedRSAKeyProvider(
        X509Certificate2 certificate) : base(certificate, KeyType.RSA)
    {
        _rsa = certificate.GetRSAPrivateKey()
            ?? throw new ArgumentException("Failed to retrieve RSA private key from certificate.");
    }

    protected override void Dispose(bool isDisposing)
    {
        if (isDisposing)
        {
            _rsa.Dispose();
        }

        base.Dispose(isDisposing);
    }

    internal override Task<byte[]> SignHashAsync(
        AsyncPipeline pipeline,
        string path,
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(_rsa.SignHash(hash, hashAlgorithm, RSASignaturePadding.Pkcs1));
    }
}

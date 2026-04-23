using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using OpenAuthenticode.Commands;

namespace OpenAuthenticode.Keys;

public sealed class ManagedECDsaKeyProvider : KeyProvider
{
    private readonly ECDsa _ecdsa;

    public ManagedECDsaKeyProvider(
        X509Certificate2 certificate) : base(certificate, KeyType.ECDsa)
    {
        _ecdsa = certificate.GetECDsaPrivateKey()
            ?? throw new ArgumentException("Failed to retrieve ECDsa private key from certificate.");
    }

    protected override void Dispose(bool isDisposing)
    {
        if (isDisposing)
        {
            _ecdsa.Dispose();
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
        return Task.FromResult(_ecdsa.SignHash(hash));
    }
}

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OpenAuthenticode.Module;

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
        AsyncPSCmdlet cmdlet,
        string path,
        byte[] hash,
        HashAlgorithmName hashAlgorithm)
    {
        return Task.FromResult(_rsa.SignHash(hash, hashAlgorithm, RSASignaturePadding.Pkcs1));
    }
}

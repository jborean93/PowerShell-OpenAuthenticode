using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OpenAuthenticode.Module;

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
        AsyncPSCmdlet cmdlet,
        string path,
        byte[] hash,
        HashAlgorithmName hashAlgorithm)
    {
        return Task.FromResult(_ecdsa.SignHash(hash));
    }
}

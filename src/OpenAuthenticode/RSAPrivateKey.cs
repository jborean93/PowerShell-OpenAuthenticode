using System;
using System.Security.Cryptography;

namespace OpenAuthenticode;

internal abstract class RSAPrivateKey : RSA
{
    public RSAPrivateKey(int keySize)
    {
        KeySizeValue = keySize;
    }

    public abstract byte[] SignHashCore(byte[] hash, HashAlgorithmName hashAlgorithm);

    public override byte[] SignHash(
        byte[] hash,
        HashAlgorithmName hashAlgorithm,
        RSASignaturePadding padding)
    {
        if (padding.Mode != RSASignaturePaddingMode.Pkcs1)
        {
            throw new CryptographicException($"Unsupported padding mode {padding.Mode}");
        }

        return SignHashCore(hash, hashAlgorithm);
    }

    public override RSAParameters ExportParameters(bool includePrivateParameters) => throw new NotImplementedException();

    public override void ImportParameters(RSAParameters parameters) => throw new NotImplementedException();
}


using System;
using System.Security.Cryptography;

namespace OpenAuthenticode.Module;

internal abstract class AzureRSAKey : RSA
{
    private readonly static byte[] _rsaSha1Digest = [
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
        0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
    ];

    public abstract byte[] SignHashCore(byte[] hash, string azureAlgorithm);

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (padding.Mode != RSASignaturePaddingMode.Pkcs1)
        {
            throw new CryptographicException($"Unsupported padding mode {padding.Mode}");
        }

        string azureAlgo;
        if (hashAlgorithm == HashAlgorithmName.SHA1)
        {
            hash = CreateRSASha1Digest(hash);
            azureAlgo = "RSNULL";
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
            azureAlgo = "RS256";
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA384)
        {
            azureAlgo = "RS384";
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA512)
        {
            azureAlgo = "RS512";
        }
        else
        {
            string msg = "Support for the hash algorithm requested '{0}' for this RSA key has not been implemented";
            throw new CryptographicException(string.Format(msg, hashAlgorithm.Name));
        }

        return SignHashCore(hash, azureAlgo);
    }

    public override RSAParameters ExportParameters(bool includePrivateParameters) => throw new NotImplementedException();

    public override void ImportParameters(RSAParameters parameters) => throw new NotImplementedException();

    private static byte[] CreateRSASha1Digest(byte[] hash)
    {
        byte[] pkcs1Digest = new byte[_rsaSha1Digest.Length + 20];
        _rsaSha1Digest.CopyTo(pkcs1Digest, 0);
        hash.CopyTo(pkcs1Digest, _rsaSha1Digest.Length);

        return pkcs1Digest;
    }
}

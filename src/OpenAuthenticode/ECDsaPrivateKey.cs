using System;
using System.Security.Cryptography;

namespace OpenAuthenticode;

internal abstract class ECDsaPrivateKey : ECDsa
{
    public abstract byte[] SignHashCore(byte[] hash);

    public override byte[] SignHash(byte[] hash) => SignHashCore(hash);

    public override bool VerifyHash(byte[] hash, byte[] signature)
        => throw new NotImplementedException();
}

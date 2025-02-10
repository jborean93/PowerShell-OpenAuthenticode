using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenAuthenticode;

public enum KeyType
{
    RSA,
    ECDsa,
}

public static class X509Certificate2Extensions
{
    public static KeyType GetOpenAuthenticodeKeyType(this X509Certificate2 certificate)
    {
        using RSA? rsa = certificate.GetRSAPublicKey();
        if (rsa is not null)
        {
            return KeyType.RSA;
        }

        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa is not null)
        {
            return KeyType.ECDsa;
        }

        string keyAlgorithm = certificate.PublicKey.Oid.Value ?? "";
        if (!string.IsNullOrWhiteSpace(certificate.PublicKey.Oid.FriendlyName))
        {
            keyAlgorithm += $" - {certificate.PublicKey.Oid.FriendlyName}";
        }
        throw new NotImplementedException(
            $"Certificate public key algorithm '{keyAlgorithm}' is not supported, cannot use this certificate for signing");
    }
}

using System;
using System.Security.Cryptography;

namespace OpenAuthenticode.Module;

public sealed class AzureKeyAlgorithms
{
    public static string GetAzureRsaAlgorithm(HashAlgorithmName hashAlgorithm) => hashAlgorithm.Name switch
    {
        "SHA1" => "RSNULL",
        "SHA256" => "RS256",
        "SHA384" => "RS384",
        "SHA512" => "RS512",
        _ => throw new NotImplementedException(
            $"Support for the hash algorithm requested '{hashAlgorithm.Name}' for this RSA key has not been implemented"),
    };

    public static (string, HashAlgorithmName) GetAzureEcdsaInfo(string curve) => curve switch
    {
        "P256" => ("ES256", HashAlgorithmName.SHA256),
        "P256K" => ("ES256", HashAlgorithmName.SHA256),
        "P384" => ("ES384", HashAlgorithmName.SHA384),
        "P521" => ("ES512", HashAlgorithmName.SHA512),
        _ => throw new NotImplementedException(
            $"Support for the ECDSA curve requested {curve} for this ECDSA key has not been implemented."),
    };
}

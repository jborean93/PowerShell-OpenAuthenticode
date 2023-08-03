using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OpenAuthenticode;

/// <summary>
/// Abstract class used to define the base definition for custom key providers
/// for use in OpenAuthenticode.
/// </summary>
public abstract class KeyProvider
{
    /// <summary>
    /// The Public Certificate to use as the signer of the file.
    /// </summary>
    public abstract X509Certificate2 Certificate { get; }

    /// <summary>
    /// They key used to sign the file.
    /// </summary>
    internal abstract AsymmetricAlgorithm Key { get; }

    internal virtual void RegisterHashToSign(Span<byte> hash, Span<byte> content, HashAlgorithmName hashAlgorithm)
    { }

    internal virtual Task AuthorizeRegisteredHashes(AsyncPSCmdlet cmdlet)
        => Task.CompletedTask;
}

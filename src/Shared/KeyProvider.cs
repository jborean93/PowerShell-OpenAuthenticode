using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

[assembly: InternalsVisibleTo("OpenAuthenticode")]

namespace OpenAuthenticode.Shared;

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
}

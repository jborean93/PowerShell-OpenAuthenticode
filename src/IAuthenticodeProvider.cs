using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;

namespace OpenAuthenticode;

/// <summary>
/// Authenticode provider interface.
/// </summary>
internal interface IAuthenticodeProvider
{
    /// <summary>
    /// Gets and sets the PKCS #7 signature data.
    /// An empty byte[] is treated as having no signature.
    /// </summary>
    public byte[] Signature { get; set; }

    /// <summary>
    /// Gets the hashed data contents for the file which is then signed.
    /// </summary>
    /// <remarks>
    /// It is up to the provider implementation to set the indirect data
    /// content as needed. The data content is then placed in the SignedCms
    /// object and signed with the certificate provided.
    /// </remarks>
    /// <param name="digestAlgorithm">The digest/hash algorithm to use</param>
    /// <returns>The indirect data content to sign</returns>
    public SpcIndirectData HashData(Oid digestAlgorithm);

    public virtual void AddAttributes(CmsSigner signer) { }

    /// <summary>
    /// Saves the file contents and signature (if present) to the path
    /// specified.
    /// </summary>
    /// <param name="path">The path to save the file to</param>
    public void Save(string path);
}

/// <summary>
/// Stores the registered providers.
/// </summary>
internal sealed class AuthenticodeProvider
{
    private static readonly (string[], Func<byte[], Encoding?, IAuthenticodeProvider>)[] _providers = new
        (string[], Func<byte[], Encoding?, IAuthenticodeProvider>)[]
    {
        (PowerShellScriptProvider.FileExtensions, PowerShellScriptProvider.Create),
    };

    /// <summary>
    /// Get the provider for the extension provided.
    /// </summary>
    /// <remarks>
    /// Authenticode works on file extensions and will automatically select
    /// the provider based on the file extension in the
    /// <paramref name="extension"/> parameter.
    ///
    /// The <paramref name="fileEncoding"/> parameter can be used to provide a
    /// hint to the authenticode provider chosen about how the byte[] data is
    /// encoded. This will only be used by providers that need to read the data
    /// contents as a string, like
    /// <see cref="Authenticode.PowerShellScriptProvider"/>. If not not set, or
    /// null, the encoding used is determined by the defaults in the provider
    /// itself.
    /// </remarks>
    /// <param name="extension">The extension used to select the provider</param>
    /// <param name="data">The raw data for the provider to manage</param>
    /// <param name="encoding">The encoding hint for reading the data bytes as a string</param>
    /// <returns>The provider that can be used to get/set signatures for the path specified</returns>
    public static IAuthenticodeProvider GetProvider(string extension, byte[] data, Encoding? fileEncoding = null)
    {
        ArgumentNullException.ThrowIfNull(extension, nameof(extension));
        extension = extension.ToLowerInvariant();

        foreach ((var extensions, var createFunc) in _providers)
        {
            if (Array.Exists(extensions, e => e == extension))
            {
                return createFunc(data, fileEncoding);
            }
        }

        throw new NotImplementedException($"Authenticode support for '{extension}' has not been implemented");
    }
}

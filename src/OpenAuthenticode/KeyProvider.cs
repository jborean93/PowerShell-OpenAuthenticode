using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace OpenAuthenticode;

/// <summary>
/// Abstract class used to define the base definition for custom key providers
/// for use in OpenAuthenticode.
/// </summary>
public abstract class KeyProvider : IDisposable
{
    private readonly bool _supportsParallelSigning;
    private readonly List<HashOperation> _operations = new();
    private bool _captureHashes = true;

    /// <summary>
    /// Creates a new instance of the KeyProvider class.
    /// </summary>
    /// <param name="certificate">The public certificate associated with the key.</param>
    /// <param name="keyType">The key type this is wrapping.</param>
    /// <param name="supportsParallelSigning">Whether this key supports parallel signing or it must be done sequentially.</param>
    /// <param name="allowedAlgorithms">The allowed hash algorithms for this key or null to allow all.</param>
    /// <param name="defaultHashAlgorithm">The default hash algorithm associated with the key if any.</param>
    internal KeyProvider(
        X509Certificate2 certificate,
        KeyType keyType,
        bool supportsParallelSigning = false,
        HashAlgorithmName[]? allowedAlgorithms = null,
        HashAlgorithmName? defaultHashAlgorithm = null)
    {
        _supportsParallelSigning = supportsParallelSigning;

        Certificate = certificate;
        AllowedAlgorithms = allowedAlgorithms;
        DefaultHashAlgorithm = defaultHashAlgorithm;
        Key = keyType switch
        {
            KeyType.RSA => new CachedRSAPrivateKey(this),
            KeyType.ECDsa => new CachedECDsaPrivateKey(this),
            _ => throw new NotImplementedException(),
        };
    }

    /// <summary>
    /// The Public Certificate to use as the signer of the file.
    /// </summary>
    public X509Certificate2 Certificate { get; init; }

    /// <summary>
    /// The allowed hash algorithms for this key.
    /// </summary>
    internal HashAlgorithmName[]? AllowedAlgorithms { get; init; }

    /// <summary>
    /// The hash algorithm to use for this key if none was specified.
    /// </summary>
    internal HashAlgorithmName? DefaultHashAlgorithm { get; init; }

    /// <summary>
    /// The key to use for the CMS signing operation.
    /// </summary>
    internal AsymmetricAlgorithm Key { get; init; }

    /// <summary>
    /// Gets the registered signed hash for the given digest hash.
    /// </summary>
    /// <param name="hash">The digest hash to get the signature for.</param>
    /// <returns>The signature for the given hash.</returns>
    /// <exception cref="CapturedHashException">Thrown when the hash is not found for the cmdlet to capture.</exception>
    internal byte[] GetRegisteredHashSignature(byte[] hash)
    {
        if (_captureHashes)
        {
            throw new CapturedHashException(hash);
        }

        for (int i = 0; i < _operations.Count; i++)
        {
            if (hash.SequenceEqual(_operations[i].Digest))
            {
                return _operations[i].Signature;
            }
        }

        // This should not happen, as all registered hashes should be signed.
        throw new RuntimeException("Signed digest not found");
    }

    /// <summary>
    /// Registers a hash and its content to be signed later.
    /// </summary>
    /// <param name="path">The path to the file that was hashed.</param>
    /// <param name="hash">The authenticode hash digest of the file.</param>
    /// <remarks>
    /// This method is used to capture the hash of a file that needs to be signed
    /// later. It can be overriden by custom key providers if they need more
    /// data like the hash of the file content.
    /// </remarks>
    internal virtual void RegisterHashAndContext(
        string path,
        ReadOnlySpan<byte> hash)
    {
        _operations.Add(new(path, hash.ToArray()));
    }

    /// <summary>
    /// Finalizes the hash signing operation.
    /// </summary>
    /// <param name="cmdlet">The cmdlet to use for logging.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use for the signing operation.</param>
    /// <returns>True if the operation was successful, false otherwise.</returns>
    /// <remarks>
    /// When called, the provider will sign all the hashes that were registered.
    /// </remarks>
    internal async Task<bool> FinalizeHashAsync(
        AsyncPSCmdlet cmdlet,
        HashAlgorithmName hashAlgorithm)
    {
        _captureHashes = false;
        return await TrySignAllAsync(
            cmdlet,
            _operations.ToArray(),
            hashAlgorithm).ConfigureAwait(false);
    }

    /// <summary>
    /// Attempts to sign all the registered digests.
    /// </summary>
    /// <param name="cmdlet">The cmdlet to use for logging.</param>
    /// <param name="operations">The registered digests to sign.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use for the signing operation.</param>
    /// <returns>True if the operation was successful, false otherwise.</returns>
    /// <remarks>
    /// By default this will call SignHashAsync for each operation either in parallel or sequentially.
    /// It can be overriden to provide custom signing logic.
    /// </remarks>
    internal virtual async Task<bool> TrySignAllAsync(
        AsyncPSCmdlet cmdlet,
        HashOperation[] operations,
        HashAlgorithmName hashAlgorithm)
    {
        if (_supportsParallelSigning)
        {
            Task<byte[]>[] signTasks = [.. operations.Select(
                i => SignHashAsync(cmdlet, i.Path, i.Digest, hashAlgorithm))];
            Task<byte[][]> waitTask = Task.WhenAll(signTasks);

            byte[][] signed;
            try
            {
                signed = await Task.WhenAll(signTasks).ConfigureAwait(false);
            }
            catch (Exception)
            {
                StringBuilder msg = new();
                msg.Append("Failure when attempting to sign in parallel, the following errors occurred.");
                for (int i = 0; i < signTasks.Length; i++)
                {
                    Task t = signTasks[i];
                    if (t.Exception is not null)
                    {
                        msg.AppendLine().Append($"  {operations[i].Path}: {t.Exception}");
                    }
                }

                ErrorRecord err = new(
                    waitTask.Exception,
                    "ParallelSigningError",
                    ErrorCategory.NotSpecified,
                    null)
                {
                    ErrorDetails = new(msg.ToString()),
                };
                cmdlet.WriteError(err);
                return false;
            }

            for (int i = 0; i < operations.Length; i++)
            {
                operations[i].Signature = signed[i];
            }
        }
        else
        {
            for (int i = 0; i < operations.Length; i++)
            {
                string path = operations[i].Path;

                try
                {
                    operations[i].Signature = await SignHashAsync(
                        cmdlet,
                        path,
                        operations[i].Digest,
                        hashAlgorithm).ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    ErrorRecord err = new(
                        e,
                        "SigningError",
                        ErrorCategory.NotSpecified,
                        path)
                    {
                        ErrorDetails = new ErrorDetails($"Failed to sign {path}: {e.Message}"),
                    };
                    cmdlet.WriteError(err);
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// Signs the hash of a file asynchronously.
    /// </summary>
    /// <param name="cmdlet">The cmdlet to use for logging.</param>
    /// <param name="path">The path to the file to sign.</param>
    /// <param name="hash">The hash of the file to sign.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use for the signing operation.</param>
    /// <returns>The signature of the hash of the file.</returns>
    internal virtual Task<byte[]> SignHashAsync(
        AsyncPSCmdlet cmdlet,
        string path,
        byte[] hash,
        HashAlgorithmName hashAlgorithm)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Clears any outstanding hashes that were registered for signing.
    /// </summary>
    internal void ClearHashOperations()
    {
        _captureHashes = true;
        _operations.Clear();
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            Key.Dispose();
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private sealed class CachedRSAPrivateKey : RSAPrivateKey
    {
        private readonly KeyProvider _provider;

        public CachedRSAPrivateKey(KeyProvider provider)
        {
            _provider = provider;
        }

        public override byte[] SignHashCore(byte[] hash, HashAlgorithmName hashAlgorithm)
            => _provider.GetRegisteredHashSignature(hash);
    }

    private sealed class CachedECDsaPrivateKey : ECDsaPrivateKey
    {
        private readonly KeyProvider _provider;

        public CachedECDsaPrivateKey(KeyProvider provider)
        {
            _provider = provider;
        }

        public override byte[] SignHashCore(byte[] hash)
            => _provider.GetRegisteredHashSignature(hash);
    }
}

/// <summary>
/// A hash operation that needs to be signed.
/// </summary>
/// <param name="Path">The path to the file being signed</param>
/// <param name="Digest">The Authenticode digest that needs to be signed.</param>
internal record HashOperation(
    string Path,
    byte[] Digest)
{
    public byte[] Signature { get; set; } = [];
}

/// <summary>
/// Custom exception used by the cmdlets to capture the hash that needs to be
/// signed. The CMS types do not expose a way to capture this without actually
/// trying to create the signature.
/// </summary>
internal class CapturedHashException : Exception
{
    internal byte[] Hash { get; }

    internal CapturedHashException(byte[] hash)
    {
        Hash = hash;
    }
}

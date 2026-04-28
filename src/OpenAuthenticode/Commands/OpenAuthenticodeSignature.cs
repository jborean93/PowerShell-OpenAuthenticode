using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.PowerShell.Commands;
using OpenAuthenticode.Keys;
using OpenAuthenticode.Providers;

namespace OpenAuthenticode.Commands;

public class OpenAuthenticodeSignatureBase : AsyncPSCmdlet
{
    internal string[] _paths = [];
    internal bool _expandWildCardPaths = false;

    [Parameter()]
    public AuthenticodeProvider? Provider { get; set; }

    internal async Task<(string, ProviderInfo)[]> NormalizePathsAsync(
        AsyncPipeline pipeline,
        CancellationToken cancellationToken)
    {
        List<(string, ProviderInfo)> result = new();
        if (_expandWildCardPaths)
        {
            foreach (string p in _paths)
            {
                Collection<string> resolvedPaths;
                ProviderInfo provider;
                try
                {
                    resolvedPaths = GetResolvedProviderPathFromPSPath(p, out provider);
                }
                catch (ItemNotFoundException e)
                {
                    await pipeline.WriteErrorAsync(
                        new(e, "FileNotFound", ErrorCategory.ObjectNotFound, p),
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                    continue;
                }

                foreach (string resolvedPath in resolvedPaths)
                {
                    result.Add((resolvedPath, provider));
                }
            }
        }
        else
        {
            foreach (string p in _paths)
            {
                string resolvedPath = SessionState.Path.GetUnresolvedProviderPathFromPSPath(
                    p, out var provider, out var _);
                result.Add((resolvedPath, provider));
            }
        }

        return [..result];
    }
}

[Cmdlet(VerbsCommon.Clear, "OpenAuthenticodeSignature",
    DefaultParameterSetName = "Path",
    SupportsShouldProcess = true)]
public sealed class ClearOpenAuthenticodeSignature : OpenAuthenticodeSignatureBase
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "Path"
    )]
    [Alias("FilePath")]
    [SupportsWildcards]
    [ValidateNotNullOrEmpty]
    public string[] Path
    {
        get => _paths;
        set
        {
            _expandWildCardPaths = true;
            _paths = value;
        }
    }

    [Parameter(
        Mandatory = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "LiteralPath"
    )]
    [Alias("PSPath")]
    [ValidateNotNullOrEmpty]
    public string[] LiteralPath
    {
        get => _paths;
        set
        {
            _expandWildCardPaths = false;
            _paths = value;
        }
    }

    protected override async Task ProcessRecordAsync(AsyncPipeline pipeline, CancellationToken cancellationToken)
    {
        (string, ProviderInfo)[] paths = await NormalizePathsAsync(pipeline, cancellationToken).ConfigureAwait(false);

        foreach ((string path, ProviderInfo psProvider) in paths)
        {
            try
            {
                using FileStream fileStream = File.Open(path, FileMode.Open, FileAccess.ReadWrite);
                AuthenticodeProviderBase provider;
                if (Provider != null && Provider != AuthenticodeProvider.NotSpecified)
                {
                    provider = ProviderFactory.Create(Provider.Value, fileStream, requireWrite: true);
                }
                else
                {
                    string ext = System.IO.Path.GetExtension(path);
                    provider = ProviderFactory.Create(ext, fileStream, requireWrite: true);
                }

                using (provider)
                {
                    pipeline.WriteVerbose($"Getting file '{path}' signature with provider {provider.Provider}");
                    byte[] existingSignature = provider.Signature;

                    if (existingSignature.Length > 0)
                    {
                        pipeline.WriteVerbose($"Removing signature on file '{path}'");
                        provider.Signature = [];
                        bool shouldProcess = await pipeline.ShouldProcessAsync(
                            path,
                            "ClearSignature",
                            cancellationToken: cancellationToken).ConfigureAwait(false);
                        if (shouldProcess)
                        {
                            provider.Save();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                ErrorRecord err = new(
                    e,
                    "ClearSignatureError",
                    ErrorCategory.NotSpecified,
                    path);
                await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
                continue;
            }
        }
    }
}

[Cmdlet(VerbsCommon.Get, "OpenAuthenticodeSignature", DefaultParameterSetName = "Path")]
[OutputType(typeof(SignedCms))]
public sealed class GetOpenAuthenticodeSignature : OpenAuthenticodeSignatureBase
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "Path"
    )]
    [Alias("FilePath")]
    [SupportsWildcards]
    [ValidateNotNullOrEmpty]
    public string[] Path
    {
        get => _paths;
        set
        {
            _expandWildCardPaths = true;
            _paths = value;
        }
    }

    [Parameter(
        Mandatory = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "LiteralPath"
    )]
    [Alias("PSPath")]
    [ValidateNotNullOrEmpty]
    public string[] LiteralPath
    {
        get => _paths;
        set
        {
            _expandWildCardPaths = false;
            _paths = value;
        }
    }

    [Parameter(
        Mandatory = true,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "Stream"
    )]
    [ValidateNotNull]
    public Stream? Stream { get; set; }

    [Parameter()]
    public SwitchParameter SkipCertificateCheck { get; set; }

    [Parameter()]
    public X509Certificate2Collection? TrustStore { get; set; }

    protected override async Task ProcessRecordAsync(AsyncPipeline pipeline, CancellationToken cancellationToken)
    {
        if (ParameterSetName == "Stream")
        {
            await ProcessStreamAsync(pipeline, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await ProcessPathsAsync(pipeline, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ProcessStreamAsync(AsyncPipeline pipeline, CancellationToken cancellationToken)
    {
        Debug.Assert(Stream != null);

        AuthenticodeProvider selectedProvider = Provider ?? AuthenticodeProvider.NotSpecified;
        if (selectedProvider == AuthenticodeProvider.NotSpecified)
        {
            ErrorRecord err = new(
                new ArgumentException("A -Provider must be specified when using -Stream"),
                "NoAuthenticodeProvider",
                ErrorCategory.InvalidArgument,
                Provider);
            await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
            return;
        }

        try
        {
            // ProviderFactory.Create validates stream capabilities
            // leaveOpen=true since user provided the stream
            using AuthenticodeProviderBase provider = ProviderFactory.Create(
                selectedProvider,
                Stream,
                leaveOpen: true);

            pipeline.WriteVerbose($"Getting stream signature with provider {provider.Provider}");
            SignedCms[] signedData = SignatureHelper.GetFileSignature(provider, SkipCertificateCheck,
                TrustStore).ToArray();

            if (signedData.Length == 0)
            {
                ErrorRecord err = new(
                    new ItemNotFoundException("Stream does not contain an authenticode signature"),
                    "NoSignature",
                    ErrorCategory.ObjectNotFound,
                    null);
                await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
            foreach (SignedCms cms in signedData)
            {
                await pipeline.WriteObjectAsync(SignatureHelper.WrapSignedDataForPS(cms, null), cancellationToken: cancellationToken).ConfigureAwait(false);
            }
        }
        catch (ArgumentException e) when (e.ParamName == "stream")
        {
            // Stream validation errors from ProviderFactory
            ErrorRecord err = new(e, "InvalidStream", ErrorCategory.InvalidArgument, Stream);
            await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            ErrorRecord err = new(e, "GetSignatureError", ErrorCategory.NotSpecified, null);
            await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ProcessPathsAsync(AsyncPipeline pipeline, CancellationToken cancellationToken)
    {
        (string, ProviderInfo)[] paths = await NormalizePathsAsync(pipeline, cancellationToken).ConfigureAwait(false);

        foreach ((string path, ProviderInfo psProvider) in paths)
        {
            if (psProvider.ImplementingType != typeof(FileSystemProvider))
            {
                ErrorRecord err = new(
                    new ArgumentException($"The resolved path '{path}' is not a FileSystem path but {psProvider.Name}"),
                    "PathNotFileSystem",
                    ErrorCategory.InvalidArgument,
                    path);
                await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
                continue;
            }
            else if (!File.Exists(path))
            {
                ErrorRecord err = new(
                    new FileNotFoundException($"Cannot find path '{path}' because it does not exist.", path),
                    "PathNotFound",
                    ErrorCategory.ObjectNotFound,
                    path);
                await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
                continue;
            }

            try
            {
                using FileStream fileStream = File.OpenRead(path);
                AuthenticodeProviderBase provider;
                if (Provider != null && Provider != AuthenticodeProvider.NotSpecified)
                {
                    provider = ProviderFactory.Create(Provider.Value, fileStream);
                }
                else
                {
                    string ext = System.IO.Path.GetExtension(path);
                    provider = ProviderFactory.Create(ext, fileStream);
                }

                using (provider)
                {
                    pipeline.WriteVerbose($"Getting file '{path}' signature with provider {provider.Provider}");
                    SignedCms[] signedData = SignatureHelper.GetFileSignature(
                        provider,
                        SkipCertificateCheck,
                        TrustStore).ToArray();

                    if (signedData.Length == 0)
                    {
                        ErrorRecord err = new(
                            new ItemNotFoundException($"File '{path}' does not contain an authenticode signature"),
                            "NoSignature",
                            ErrorCategory.ObjectNotFound,
                            path);
                        await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
                    }
                    foreach (SignedCms info in signedData)
                    {
                        await pipeline.WriteObjectAsync(
                            SignatureHelper.WrapSignedDataForPS(info, path),
                            cancellationToken: cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            catch (Exception e)
            {
                ErrorRecord err = new(
                    e,
                    "GetSignatureError",
                    ErrorCategory.NotSpecified,
                    path);
                await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
                continue;
            }
        }
    }
}

public abstract class AddSetOpenAuthenticodeSignature : OpenAuthenticodeSignatureBase
{
    private bool _disposeProvider;
    private HashAlgorithmName _hashAlgo = default!;
    private KeyProvider? _key;
    private readonly List<HashOperation> _operations = [];

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "PathCertificate"
    )]
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "PathKey"
    )]
    [Alias("FilePath")]
    [SupportsWildcards]
    [ValidateNotNullOrEmpty]
    public string[] Path
    {
        get => _paths;
        set
        {
            _expandWildCardPaths = true;
            _paths = value;
        }
    }

    [Parameter(
        Mandatory = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "LiteralPathCertificate"
    )]
    [Parameter(
        Mandatory = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "LiteralPathKey"
    )]
    [Alias("PSPath")]
    [ValidateNotNullOrEmpty]
    public string[] LiteralPath
    {
        get => _paths;
        set
        {
            _expandWildCardPaths = false;
            _paths = value;
        }
    }

    [Parameter(
        Mandatory = true,
        ParameterSetName = "PathCertificate"
    )]
    [Parameter(
        Mandatory = true,
        ParameterSetName = "LiteralPathCertificate"
    )]
    public X509Certificate2? Certificate { get; set; }

    [Parameter(
        Mandatory = true,
        ParameterSetName = "PathKey"
    )]
    [Parameter(
        Mandatory = true,
        ParameterSetName = "LiteralPathKey"
    )]
    public KeyProvider? Key { get; set; }

    [Parameter()]
    [ArgumentCompletions("SHA1", "SHA256", "SHA384", "SHA512")]
    public HashAlgorithmName? HashAlgorithm { get; set; }

    [Parameter()]
    public X509IncludeOption IncludeOption { get; set; } = X509IncludeOption.ExcludeRoot;

    [Parameter()]
    public SwitchParameter PassThru { get; set; }

    [Parameter()]
    public HashAlgorithmName? TimeStampHashAlgorithm { get; set; }

    [Parameter()]
    public string? TimeStampServer { get; set; }

    [Parameter()]
    public SwitchParameter Silent { get; set; }

    protected abstract bool Append { get; }

    protected override void BeginProcessing()
    {
        if (ParameterSetName.EndsWith("Certificate"))
        {
            Debug.Assert(Certificate != null);
            _disposeProvider = true;

            KeyType keyType = Certificate.GetOpenAuthenticodeKeyType();
            _key = keyType switch
            {
                KeyType.RSA => new ManagedRSAKeyProvider(Certificate),
                KeyType.ECDsa => new ManagedECDsaKeyProvider(Certificate),
                _ => throw new NotImplementedException(),
            };
        }
        else
        {
            Debug.Assert(Key != null);
            _key = Key;
        }

        _hashAlgo = HashAlgorithm ?? _key.DefaultHashAlgorithm ?? HashAlgorithmName.SHA256;

        HashSet<string> allowedAlgorithms = _key.AllowedAlgorithms;
        if (_hashAlgo.Name is not null && allowedAlgorithms.Count > 0 && !allowedAlgorithms.Contains(_hashAlgo.Name))
        {
            string allowedAlgos = string.Join(", ", allowedAlgorithms.OrderBy(h => h));
            string msg = $"The requested hash algorithm '{_hashAlgo.Name}' is not allowed by the key provider. Allowed algorithms: {allowedAlgos}.";
            ErrorRecord err = new(
                new ArgumentException(msg),
                "SetSignatureInvalidHashAlgorithm",
                ErrorCategory.InvalidArgument,
                _hashAlgo);
            ThrowTerminatingError(err);
            return;
        }
    }

    protected override async Task ProcessRecordAsync(AsyncPipeline pipeline, CancellationToken cancellationToken)
    {
        Debug.Assert(_key is not null);

        (string, ProviderInfo)[] paths = await NormalizePathsAsync(pipeline, cancellationToken).ConfigureAwait(false);

        foreach ((string path, ProviderInfo psProvider) in paths)
        {
            if (psProvider.ImplementingType != typeof(FileSystemProvider))
            {
                ErrorRecord err = new(
                    new ArgumentException($"The resolved path '{path}' is not a FileSystem path but {psProvider.Name}"),
                    "PathNotFileSystem",
                    ErrorCategory.InvalidArgument,
                    path);
                await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
                continue;
            }
            else if (!File.Exists(path))
            {
                ErrorRecord err = new(
                    new FileNotFoundException($"Cannot find path '{path}' because it does not exist.", path),
                    "PathNotFound",
                    ErrorCategory.ObjectNotFound,
                    path);
                await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
                continue;
            }

            try
            {
                FileStream fileStream = File.Open(path, FileMode.Open, FileAccess.ReadWrite);
                AuthenticodeProviderBase provider;
                if (Provider != null && Provider != AuthenticodeProvider.NotSpecified)
                {
                    provider = ProviderFactory.Create(Provider.Value, fileStream, requireWrite: true);
                }
                else
                {
                    string ext = System.IO.Path.GetExtension(path);
                    provider = ProviderFactory.Create(ext, fileStream, requireWrite: true);
                }

                Oid digestOid = SpcIndirectData.OidFromHashAlgorithm(_hashAlgo);
                SpcIndirectData dataContent = provider.HashData(digestOid);
                ContentInfo ci = new(SpcIndirectData.OID, dataContent.GetBytes());
                AsnEncodedData[] attributesToSign = provider.GetAttributesToSign();

                // First call is done with the custom key which captures the
                // hashes to be signed. This is done so the key can be provided
                // with the data needed for it to pre-authenticate the signing
                // operations. The actual hashing is done after all files have
                // been collected.
                try
                {
                    SignatureHelper.CreateSignature(
                        ci,
                        attributesToSign,
                        _hashAlgo,
                        _key.Certificate,
                        IncludeOption,
                        _key.Key,
                        null,
                        null,
                        true);
                }
                catch (CapturedHashException e)
                {
                    _key.RegisterHashAndContext(path, e.Hash);
                    HashOperation operation = new(
                        Path: path,
                        Provider: provider,
                        AuthenticodeDigest: e.Hash,
                        ContentInfo: ci,
                        SignedAttributes: attributesToSign);
                    _operations.Add(operation);
                    continue;
                }

                // This should not occur, the CapturedHashException should have been called.
                Debug.Fail($"Provider {provider.Provider} did not throw CapturedHashException as expected");
            }
            catch (Exception e)
            {
                ErrorRecord err = new(
                    e,
                    "CalculateSignatureError",
                    ErrorCategory.NotSpecified,
                    path);
                await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
                continue;
            }
        }

        await base.ProcessRecordAsync(pipeline, cancellationToken).ConfigureAwait(false);
    }

    protected override async Task EndProcessingAsync(AsyncPipeline pipeline, CancellationToken cancellationToken)
    {
        Debug.Assert(_key is not null);

        // Let the key provider know that we are done with the hashing
        bool res = await _key.FinalizeHashAsync(
            pipeline,
            _hashAlgo,
            cancellationToken).ConfigureAwait(false);
        if (!res)
        {
            return;
        }

        foreach (HashOperation operation in _operations)
        {
            try
            {
                pipeline.WriteVerbose($"Setting file '{operation.Path}' signature with provider {operation.Provider.Provider} with {_hashAlgo} and timestamp server '{TimeStampServer}'");
                SignedCms signInfo = SignatureHelper.CreateSignature(
                    operation.ContentInfo,
                    operation.SignedAttributes,
                    _hashAlgo,
                    _key.Certificate,
                    IncludeOption,
                    _key.Key,
                    TimeStampServer,
                    TimeStampHashAlgorithm,
                    Silent);
                SignatureHelper.SetFileSignature(
                    operation.Provider,
                    signInfo,
                    Append);

                bool shouldProcess = await pipeline.ShouldProcessAsync(operation.Path, "SetSignature", cancellationToken).ConfigureAwait(false);
                if (shouldProcess)
                {
                    operation.Provider.Save();
                }

                if (PassThru)
                {
                    await pipeline.WriteObjectAsync(SignatureHelper.WrapSignedDataForPS(signInfo, operation.Path), cancellationToken: cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception e)
            {
                ErrorRecord err = new(
                    e,
                    "SetSignatureError",
                    ErrorCategory.NotSpecified,
                    operation.Path);
                await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
                continue;
            }
            finally
            {
                // Dispose provider after processing (whether successful or not)
                operation.Provider.Dispose();
            }
        }
    }

    protected override void Dispose(bool isDisposing)
    {
        if (isDisposing)
        {
            _key?.ClearHashOperations();
            if (_disposeProvider)
            {
                _key?.Dispose();
            }

            // Dispose any remaining providers that weren't disposed in EndProcessingAsync
            foreach (HashOperation operation in _operations)
            {
                operation.Provider?.Dispose();
            }
        }

        base.Dispose(isDisposing);
    }
}

internal sealed record HashOperation(
    string Path,
    AuthenticodeProviderBase Provider,
    byte[] AuthenticodeDigest,
    ContentInfo ContentInfo,
    AsnEncodedData[] SignedAttributes
);

[Cmdlet(VerbsCommon.Add, "OpenAuthenticodeSignature",
    DefaultParameterSetName = "PathCertificate",
    SupportsShouldProcess = true)]
[OutputType(typeof(SignedCms))]
public class AddOpenAuthenticodeSignature : AddSetOpenAuthenticodeSignature
{
    protected override bool Append => true;
}

[Cmdlet(VerbsCommon.Set, "OpenAuthenticodeSignature",
    DefaultParameterSetName = "PathCertificate",
    SupportsShouldProcess = true)]
[OutputType(typeof(SignedCms))]
public class SetOpenAuthenticodeSignature : AddSetOpenAuthenticodeSignature
{
    protected override bool Append => false;
}

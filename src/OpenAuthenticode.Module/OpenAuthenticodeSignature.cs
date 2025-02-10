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
using System.Text;
using System.Threading.Tasks;
using Microsoft.PowerShell.Commands;

namespace OpenAuthenticode.Module;

public class OpenAuthenticodeSignatureBase : AsyncPSCmdlet
{
    internal string[] _paths = Array.Empty<string>();
    internal bool _expandWildCardPaths = false;

    [Parameter()]
    public AuthenticodeProvider? Provider { get; set; }

    internal (string, ProviderInfo)[] NormalizePaths()
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
                    WriteError(new(e, "FileNotFound", ErrorCategory.ObjectNotFound, p));
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

        return result.ToArray();
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

    [Parameter()]
    [EncodingTransformation]
    [ArgumentCompletions("Utf8", "ASCII", "ANSI", "OEM", "Unicode", "Utf8Bom", "Utf8NoBom")]
    public Encoding? Encoding { get; set; }

    protected override Task ProcessRecordAsync()
    {
        (string, ProviderInfo)[] paths = NormalizePaths();

        foreach ((string path, ProviderInfo psProvider) in paths)
        {
            try
            {
                byte[] fileData = File.ReadAllBytes(path);
                IAuthenticodeProvider provider;
                if (Provider != null && Provider != AuthenticodeProvider.NotSpecified)
                {
                    provider = ProviderFactory.Create((AuthenticodeProvider)Provider, fileData,
                        fileEncoding: Encoding);
                }
                else
                {
                    string ext = System.IO.Path.GetExtension(path);
                    provider = ProviderFactory.Create(ext, fileData, fileEncoding: Encoding);
                }

                WriteVerbose($"Getting file '{path}' signature with provider {provider.Provider}");
                byte[] existingSignature = provider.Signature;

                if (existingSignature.Length > 0)
                {
                    WriteVerbose($"Removing signature on file '{path}'");
                    provider.Signature = Array.Empty<byte>();
                    if (ShouldProcess(path, "ClearSignature"))
                    {
                        provider.Save(path);
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
                WriteError(err);
                continue;
            }
        }

        return Task.CompletedTask;
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
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "Content"
    )]
    public string Content { get; set; } = "";

    [Parameter(
        Mandatory = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "RawContent"
    )]
    public byte[] RawContent { get; set; } = Array.Empty<byte>();

    [Parameter(ParameterSetName = "Path")]
    [Parameter(ParameterSetName = "LiteralPath")]
    [Parameter(ParameterSetName = "RawContent")]
    [EncodingTransformation]
    [ArgumentCompletions("Utf8", "ASCII", "ANSI", "OEM", "Unicode", "Utf8Bom", "Utf8NoBom")]
    public Encoding? Encoding { get; set; }

    [Parameter()]
    public SwitchParameter SkipCertificateCheck { get; set; }

    [Parameter()]
    public X509Certificate2Collection? TrustStore { get; set; }

    protected override Task ProcessRecordAsync()
    {
        if (ParameterSetName == "Path" || ParameterSetName == "LiteralPath")
        {
            ProcessPaths();
            return Task.CompletedTask;
        }

        AuthenticodeProvider selectedProvider = Provider ?? AuthenticodeProvider.NotSpecified;
        if (selectedProvider == AuthenticodeProvider.NotSpecified)
        {
            ErrorRecord err = new(
                new ArgumentException("A -Provider must be specified when using -Content or -RawContent"),
                "NoAuthenticodeProvider",
                ErrorCategory.InvalidArgument,
                Provider);
            WriteError(err);
            return Task.CompletedTask;
        }

        if (ParameterSetName == "Content")
        {
            // When using a string content the encoding doesn't matter.
            Encoding contentEncoding = new UTF8Encoding();
            byte[] rawContent = contentEncoding.GetBytes(Content);
            ProcessContent(rawContent, selectedProvider, contentEncoding);
        }
        else
        {
            ProcessContent(RawContent, selectedProvider, Encoding);
        }

        return Task.CompletedTask;
    }

    private void ProcessContent(byte[] data, AuthenticodeProvider selectedProvider, Encoding? dataEncoding)
    {
        try
        {
            IAuthenticodeProvider provider = ProviderFactory.Create(selectedProvider, data,
                fileEncoding: dataEncoding);

            WriteVerbose($"Getting content signature with provider {provider.Provider}");
            SignedCms[] signedData = SignatureHelper.GetFileSignature(provider, SkipCertificateCheck,
                TrustStore).ToArray();

            if (signedData.Length == 0)
            {
                ErrorRecord err = new(
                    new ItemNotFoundException("Content provided does not contain an authenticode signature"),
                    "NoSignature",
                    ErrorCategory.ObjectNotFound,
                    null);
                WriteError(err);
            }
            foreach (SignedCms cms in signedData)
            {
                WriteObject(SignatureHelper.WrapSignedDataForPS(cms, null));
            }
        }
        catch (Exception e)
        {
            ErrorRecord err = new(
                e,
                "GetSignatureError",
                ErrorCategory.NotSpecified,
                null);
            WriteError(err);
            return;
        }
    }

    private void ProcessPaths()
    {
        (string, ProviderInfo)[] paths = NormalizePaths();

        foreach ((string path, ProviderInfo psProvider) in paths)
        {
            if (psProvider.ImplementingType != typeof(FileSystemProvider))
            {
                ErrorRecord err = new(
                    new ArgumentException($"The resolved path '{path}' is not a FileSystem path but {psProvider.Name}"),
                    "PathNotFileSystem",
                    ErrorCategory.InvalidArgument,
                    path);
                WriteError(err);
                continue;
            }
            else if (!File.Exists(path))
            {
                ErrorRecord err = new(
                    new FileNotFoundException($"Cannot find path '{path}' because it does not exist.", path),
                    "PathNotFound",
                    ErrorCategory.ObjectNotFound,
                    path);
                WriteError(err);
                continue;
            }

            try
            {
                byte[] fileData = File.ReadAllBytes(path);
                IAuthenticodeProvider provider;
                if (Provider != null && Provider != AuthenticodeProvider.NotSpecified)
                {
                    provider = ProviderFactory.Create((AuthenticodeProvider)Provider, fileData,
                        fileEncoding: Encoding);
                }
                else
                {
                    string ext = System.IO.Path.GetExtension(path);
                    provider = ProviderFactory.Create(ext, fileData, fileEncoding: Encoding);
                }

                WriteVerbose($"Getting file '{path}' signature with provider {provider.Provider}");
                SignedCms[] signedData = SignatureHelper.GetFileSignature(provider, SkipCertificateCheck, TrustStore).ToArray();

                if (signedData.Length == 0)
                {
                    ErrorRecord err = new(
                        new ItemNotFoundException($"File '{path}' does not contain an authenticode signature"),
                        "NoSignature",
                        ErrorCategory.ObjectNotFound,
                        path);
                    WriteError(err);
                }
                foreach (SignedCms info in signedData)
                {
                    WriteObject(SignatureHelper.WrapSignedDataForPS(info, path));
                }
            }
            catch (Exception e)
            {
                ErrorRecord err = new(
                    e,
                    "GetSignatureError",
                    ErrorCategory.NotSpecified,
                    path);
                WriteError(err);
                continue;
            }
        }
    }
}

public abstract class AddSetOpenAuthenticodeSignature : OpenAuthenticodeSignatureBase
{
    private bool _disposeProvider;
    private HashAlgorithmName _hashAlgo = default!;
    private KeyProvider? _provider;
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
    [EncodingTransformation]
    [ArgumentCompletions("Utf8", "ASCII", "ANSI", "OEM", "Unicode", "Utf8Bom", "Utf8NoBom")]
    public Encoding? Encoding { get; set; }

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
            _provider = keyType switch
            {
                KeyType.RSA => new ManagedRSAKeyProvider(Certificate),
                KeyType.ECDsa => new ManagedECDsaKeyProvider(Certificate),
                _ => throw new NotImplementedException(),
            };
        }
        else
        {
            Debug.Assert(Key != null);
            _provider = Key;
        }

        _hashAlgo = HashAlgorithm ?? _provider.DefaultHashAlgorithm ?? HashAlgorithmName.SHA256;

        HashAlgorithmName[]? allowedAlgorithms = _provider.AllowedAlgorithms;
        if (allowedAlgorithms is not null && allowedAlgorithms.Contains(_hashAlgo))
        {
            string msg = $"The requested hash algorithm '{_hashAlgo.Name}' is not allowed by the key provider";
            ErrorRecord err = new(
                new ArgumentException(msg),
                "SetSignatureInvalidHashAlgorithm",
                ErrorCategory.InvalidArgument,
                _hashAlgo);
            ThrowTerminatingError(err);
            return;
        }
    }

    protected override async Task ProcessRecordAsync()
    {
        Debug.Assert(_provider is not null);

        (string, ProviderInfo)[] paths = NormalizePaths();

        foreach ((string path, ProviderInfo psProvider) in paths)
        {
            if (psProvider.ImplementingType != typeof(FileSystemProvider))
            {
                ErrorRecord err = new(
                    new ArgumentException($"The resolved path '{path}' is not a FileSystem path but {psProvider.Name}"),
                    "PathNotFileSystem",
                    ErrorCategory.InvalidArgument,
                    path);
                WriteError(err);
                continue;
            }
            else if (!File.Exists(path))
            {
                ErrorRecord err = new(
                    new FileNotFoundException($"Cannot find path '{path}' because it does not exist.", path),
                    "PathNotFound",
                    ErrorCategory.ObjectNotFound,
                    path);
                WriteError(err);
                continue;
            }

            try
            {
                byte[] fileData = File.ReadAllBytes(path);
                IAuthenticodeProvider provider;
                if (Provider != null && Provider != AuthenticodeProvider.NotSpecified)
                {
                    provider = ProviderFactory.Create(Provider.Value, fileData, fileEncoding: Encoding);
                }
                else
                {
                    string ext = System.IO.Path.GetExtension(path);
                    provider = ProviderFactory.Create(ext, fileData, fileEncoding: Encoding);
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
                        _provider.Certificate,
                        IncludeOption,
                        _provider.Key,
                        null,
                        null,
                        true);
                }
                catch (CapturedHashException e)
                {
                    _provider.RegisterHashAndContext(path, e.Hash);
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
                throw new RuntimeException($"Unknown failure trying to capture data hash for '{path}'");
            }
            catch (Exception e)
            {
                ErrorRecord err = new(
                    e,
                    "CalculateSignatureError",
                    ErrorCategory.NotSpecified,
                    path);
                WriteError(err);
                continue;
            }
        }

        await base.ProcessRecordAsync();
    }

    protected override async Task EndProcessingAsync()
    {
        Debug.Assert(_provider is not null);

        // Let the key provider know that we are done with the hashing
        await _provider.FinalizeHashAsync(
            this,
            _hashAlgo).ConfigureAwait(false);

        foreach (HashOperation operation in _operations)
        {
            try
            {
                WriteVerbose($"Setting file '{operation.Path}' signature with provider {operation.Provider.Provider} with {_hashAlgo} and timestamp server '{TimeStampServer}'");
                SignedCms signInfo = SignatureHelper.CreateSignature(
                    operation.ContentInfo,
                    operation.SignedAttributes,
                    _hashAlgo,
                    _provider.Certificate,
                    IncludeOption,
                    _provider.Key,
                    TimeStampServer,
                    TimeStampHashAlgorithm,
                    Silent);
                SignatureHelper.SetFileSignature(
                    operation.Provider,
                    signInfo,
                    Append);

                if (ShouldProcess(operation.Path, "SetSignature"))
                {
                    operation.Provider.Save(operation.Path);
                }

                if (PassThru)
                {
                    WriteObject(SignatureHelper.WrapSignedDataForPS(signInfo, operation.Path));
                }
            }
            catch (Exception e)
            {
                ErrorRecord err = new(
                    e,
                    "SetSignatureError",
                    ErrorCategory.NotSpecified,
                    operation.Path);
                WriteError(err);
                continue;
            }
        }
    }

    protected override void Dispose(bool isDisposing)
    {
        if (isDisposing)
        {
            _provider?.ClearHashOperations();
            if (_disposeProvider)
            {
                _provider?.Dispose();
            }
        }

        base.Dispose(isDisposing);
    }
}

internal sealed record HashOperation(
    string Path,
    IAuthenticodeProvider Provider,
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

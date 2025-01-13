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

    protected override async Task ProcessRecordAsync()
    {
        X509Certificate2 cert;
        AsymmetricAlgorithm? key = null;
        if (ParameterSetName.EndsWith("Certificate"))
        {
            Debug.Assert(Certificate != null);
            cert = Certificate;
        }
        else
        {
            Debug.Assert(Key != null);
            cert = Key.Certificate;
            key = Key.Key;
        }

        (string, ProviderInfo)[] paths = NormalizePaths();

        // For csc based API they need to provide the hashes to sign before
        // they send the request. To make this more efficient and to avoid
        // prompting for user input per file we get these hashes to provide
        // to the custom key before actually signing the data.
        AsymmetricAlgorithm? captureKey = GetCapturingKey(cert);
        if (captureKey == null)
        {
            string pubKeyOid = cert.PublicKey.Oid.Value ?? "";
            if (!string.IsNullOrWhiteSpace(cert.PublicKey.Oid.FriendlyName))
            {
                pubKeyOid += $" - {cert.PublicKey.Oid.FriendlyName}";
            }

            string msg = $"Unknown certificate algorithm requested '{pubKeyOid}', cannot use this certificate for signing";
            ErrorRecord err = new(
                new ArgumentException(msg),
                "SetSignatureUnknownCertificateAlgorithm",
                ErrorCategory.InvalidArgument,
                cert
            );
            ThrowTerminatingError(err);
            return;
        }

        List<HashOperation> operations = new();
        HashAlgorithmName hashAlgo = HashAlgorithm ?? Key?.DefaultHashAlgorithm ?? HashAlgorithmName.SHA256;

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
                    provider = ProviderFactory.Create((AuthenticodeProvider)Provider, fileData, fileEncoding: Encoding);
                }
                else
                {
                    string ext = System.IO.Path.GetExtension(path);
                    provider = ProviderFactory.Create(ext, fileData, fileEncoding: Encoding);
                }

                Oid digestOid = SpcIndirectData.OidFromHashAlgorithm(hashAlgo);
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
                        hashAlgo,
                        cert,
                        IncludeOption,
                        captureKey,
                        null,
                        null,
                        true);
                }
                catch (CapturedHashException e)
                {
                    Key?.RegisterHashToSign(e.Hash, fileData, hashAlgo);
                    operations.Add(new(path, provider, fileData, e.Hash, ci, digestOid, attributesToSign));
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

        // Let the custom key know there are no more hashes for this cmdlet call
        // and it is free to do any pre-work for calculating the signature.
        if (Key != null)
        {
            await Key.AuthorizeRegisteredHashes(this);
        }

        foreach (HashOperation operation in operations)
        {
            try
            {
                WriteVerbose($"Setting file '{operation.Path}' signature with provider {operation.Provider.Provider} with {hashAlgo.Name} and timestamp server '{TimeStampServer}'");
                SignedCms signInfo = SignatureHelper.CreateSignature(
                    operation.Content,
                    operation.SignedAttributes,
                    hashAlgo,
                    cert,
                    IncludeOption,
                    key,
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

    private static AsymmetricAlgorithm? GetCapturingKey(X509Certificate2 certificate)
    {
        // Dotnet only supports DSA, RSA, and ECDSA right now. DSA isn't used
        // anymore so we only care about RSA and ECDSA.
        if (certificate.PublicKey.GetRSAPublicKey() != null)
        {
            return new RSACaptureHashKey();
        }
        else if (certificate.PublicKey.GetECDsaPublicKey() != null)
        {
            return new ECDsaCaptureHashKey();
        }

        return null;
    }
}

internal sealed record HashOperation(
    string Path,
    IAuthenticodeProvider Provider,
    byte[] FileData,
    byte[] DataHash,
    ContentInfo Content,
    Oid DigestOid,
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

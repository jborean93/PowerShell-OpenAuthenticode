using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.PowerShell.Commands;
using OpenAuthenticode.Shared;

namespace OpenAuthenticode;

[Cmdlet(VerbsCommon.Get, "OpenAuthenticodeSignature", DefaultParameterSetName = "Path")]
[OutputType(typeof(SignedCms))]
public sealed class GetOpenAuthenticodeSignature : PSCmdlet
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
    public string[] Path { get; set; } = Array.Empty<string>();

    [Parameter(
        Mandatory = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "LiteralPath"
    )]
    [Alias("PSPath")]
    [ValidateNotNullOrEmpty]
    public string[] LiteralPath { get; set; } = Array.Empty<string>();

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
    [EncodingTransformAttribute]
    [ArgumentCompletions("Utf8", "ASCII", "ANSI", "OEM", "Unicode", "Utf8Bom", "Utf8NoBom")]
    public Encoding? Encoding { get; set; }

    [Parameter()]
    public AuthenticodeProvider? Provider { get; set; }

    [Parameter()]
    public SwitchParameter SkipCertificateCheck { get; set; }

    [Parameter()]
    public X509Certificate2Collection? TrustStore { get; set; }

    protected override void ProcessRecord()
    {
        if (ParameterSetName == "Path" || ParameterSetName == "LiteralPath")
        {
            ProcessPaths();
            return;
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
            return;
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
    }

    private void ProcessContent(byte[] data, AuthenticodeProvider selectedProvider, Encoding? dataEncoding)
    {
        SignedCms? signedData;
        try
        {
            IAuthenticodeProvider provider = ProviderFactory.Create(selectedProvider, data,
                fileEncoding: dataEncoding);

            WriteVerbose($"Getting content signature with provider {provider.Provider}");
            signedData = SignatureHelper.GetFileSignature(provider, SkipCertificateCheck, TrustStore);
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

        if (signedData == null)
        {
            ErrorRecord err = new(
                new ItemNotFoundException("Content provided does not contain an authenticode signature"),
                "NoSignature",
                ErrorCategory.ObjectNotFound,
                null);
            WriteError(err);
        }
        else
        {
            WriteObject(SignatureHelper.WrapSignedDataForPS(signedData, null));
        }
    }

    private void ProcessPaths()
    {
        List<(string, ProviderInfo)> paths = new();
        if (ParameterSetName == "Path")
        {
            foreach (string p in Path)
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
                    paths.Add((resolvedPath, provider));
                }
            }
        }
        else
        {
            foreach (string p in LiteralPath)
            {
                string resolvedPath = SessionState.Path.GetUnresolvedProviderPathFromPSPath(
                    p, out var provider, out var _);
                paths.Add((resolvedPath, provider));
            }
        }

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
                SignedCms? signedData = SignatureHelper.GetFileSignature(provider, SkipCertificateCheck, TrustStore);

                if (signedData == null)
                {
                    ErrorRecord err = new(
                        new ItemNotFoundException($"File '{path}' does not contain an authenticode signature"),
                        "NoSignature",
                        ErrorCategory.ObjectNotFound,
                        path);
                    WriteError(err);
                }
                else
                {
                    WriteObject(SignatureHelper.WrapSignedDataForPS(signedData, path));
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

[Cmdlet(VerbsCommon.Set, "OpenAuthenticodeSignature",
    DefaultParameterSetName = "PathCertificate",
    SupportsShouldProcess = true)]
[OutputType(typeof(SignedCms))]
public sealed class SetOpenAuthenticodeSignature : PSCmdlet
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
    public string[] Path { get; set; } = Array.Empty<string>();

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
    public string[] LiteralPath { get; set; } = Array.Empty<string>();

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
    [EncodingTransformAttribute]
    [ArgumentCompletions("Utf8", "ASCII", "ANSI", "OEM", "Unicode", "Utf8Bom", "Utf8NoBom")]
    public Encoding? Encoding { get; set; }

    [Parameter()]
    [ArgumentCompletions("SHA1", "SHA256", "SHA384", "SHA512")]
    public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;

    [Parameter()]
    public X509IncludeOption IncludeOption { get; set; } = X509IncludeOption.ExcludeRoot;

    [Parameter()]
    public SwitchParameter PassThru { get; set; }

    [Parameter()]
    public AuthenticodeProvider? Provider { get; set; }

    [Parameter()]
    public HashAlgorithmName? TimeStampHashAlgorithm { get; set; }

    [Parameter()]
    public string? TimeStampServer { get; set; }

    protected override void ProcessRecord()
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

        List<(string, ProviderInfo)> paths = new();
        if (ParameterSetName.StartsWith("LiteralPath"))
        {
            foreach (string p in LiteralPath)
            {
                string resolvedPath = SessionState.Path.GetUnresolvedProviderPathFromPSPath(
                    p, out var provider, out var _);
                paths.Add((resolvedPath, provider));
            }
        }
        else
        {
            foreach (string p in Path)
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
                    paths.Add((resolvedPath, provider));
                }
            }
        }

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
                WriteVerbose($"Setting file '{path}' signature with provider {provider.Provider} with {HashAlgorithm.Name} and timestamp server '{TimeStampServer}'");

                SignedCms signInfo = SignatureHelper.SetFileSignature(
                    provider,
                    cert,
                    HashAlgorithm,
                    IncludeOption,
                    key,
                    TimeStampServer,
                    TimeStampHashAlgorithm);

                if (ShouldProcess(path, "SetSignature"))
                {
                    provider.Save(path);
                }

                if (PassThru)
                {
                    WriteObject(SignatureHelper.WrapSignedDataForPS(signInfo, path));
                }
            }
            catch (Exception e)
            {
                ErrorRecord err = new(
                    e,
                    "SetSignatureError",
                    ErrorCategory.NotSpecified,
                    path);
                WriteError(err);
                continue;
            }
        }
    }
}

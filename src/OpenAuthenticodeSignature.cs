using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OpenAuthenticode;

[Cmdlet(VerbsCommon.Get, "OpenAuthenticodeSignature")]
[OutputType(typeof(SignedCms))]
public sealed class GetOpenAuthenticodeSignature : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    [Alias("FilePath")]
    public string[] Path { get; set; } = Array.Empty<string>();

    protected override void ProcessRecord()
    {
        foreach (string p in Path)
        {
            WriteObject(SignatureHelper.GetFileSignature(p));
        }
    }
}

[Cmdlet(VerbsCommon.Set, "OpenAuthenticodeSignature")]
public sealed class SetOpenAuthenticodeSignature : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    [Alias("FilePath")]
    public string[] Path { get; set; } = Array.Empty<string>();

    [Parameter(
        Mandatory = true
    )]
    public X509Certificate2? Certificate { get; set; }

    [Parameter()]
    public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;

    [Parameter()]
    public X509IncludeOption IncludeOption { get; set; } = X509IncludeOption.ExcludeRoot;

    [Parameter()]
    public string? TimestampServer { get; set; }

    [Parameter()]
    public HashAlgorithmName? TimestampHashAlgorithm { get; set; }

    protected override void ProcessRecord()
    {
        Debug.Assert(Certificate != null);
        foreach (string p in Path)
        {
            SignatureHelper.SetFileSignature(p, Certificate, HashAlgorithm, IncludeOption, TimestampServer,
                TimestampHashAlgorithm);
        }
    }
}

public static class SignatureHelper
{
    public static CounterSignature? GetCounterSignature(PSObject obj)
    {
        SignedCms data = (SignedCms)obj.BaseObject;
        if (data.SignerInfos[0].CounterSignerInfos.Count == 0 ||
            data.SignerInfos[0].CounterSignerInfos[0].Certificate == null)
        {
            return null;
        }

        SignerInfo counterSigner = data.SignerInfos[0].CounterSignerInfos[0];

        DateTime? signingTime = null;
        foreach (CryptographicAttributeObject attr in counterSigner.SignedAttributes)
        {
            if (attr.Oid.FriendlyName == "signingTime" && attr.Values[0] is Pkcs9SigningTime time)
            {
                signingTime = time.SigningTime.ToUniversalTime();
                break;
            }
        }

        return new(counterSigner.Certificate!,
            HashAlgorithmName.FromOid(counterSigner.DigestAlgorithm.Value ?? ""),
            (DateTime)signingTime!);
    }

    internal static SignedCms GetFileSignature(string path)
    {
        string ext = Path.GetExtension(path);
        IAuthenticodeProvider provider = AuthenticodeProvider.GetProvider(ext, File.ReadAllBytes(path));

        byte[] signatureData = provider.Signature;
        if (signatureData.Length == 0)
        {
            throw new Exception($"Object at '{path}' has not been signed");
        }

        SignedCms signInfo = new SignedCms();
        signInfo.Decode(signatureData);
        signInfo.CheckSignature(true);

        if (signInfo.ContentInfo.ContentType.Value != SpcIndirectData.OID.Value)
        {
            throw new ArgumentException($"Unknown ContentType {signInfo.ContentInfo.ContentType.Value}");
        }
        SpcIndirectData dataContent = SpcIndirectData.Parse(signInfo.ContentInfo.Content);
        SpcIndirectData actualContent = provider.HashData(dataContent.DigestAlgorithm);

        if (!Enumerable.SequenceEqual(actualContent.Digest, dataContent.Digest))
        {
            throw new CryptographicException($"File '{path}' signature mismatch");
        }

        PSObject signedPSObject = PSObject.AsPSObject(signInfo);
        signedPSObject.TypeNames.Insert(0, "OpenAuthenticode.AuthenticodeSignature");
        signedPSObject.Properties.Add(new PSNoteProperty("Path", path), true);

        return signInfo;
    }

    internal static void SetFileSignature(string path, X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm, X509IncludeOption includeOption, string? timestampServer,
        HashAlgorithmName? timestampAlgorithm)
    {
        string ext = Path.GetExtension(path);
        IAuthenticodeProvider provider = AuthenticodeProvider.GetProvider(ext, File.ReadAllBytes(path));

        SpcIndirectData dataContent = provider.HashData(
            SpcIndirectData.OidFromHashAlgorithm(hashAlgorithm));

        CmsSigner signer = new(certificate)
        {
            IncludeOption = includeOption,
        };
        provider.AddAttributes(signer);

        ContentInfo ci = new(new Oid(SpcIndirectData.OID), dataContent.GetBytes());
        SignedCms signInfo = new(ci, false);
        signInfo.ComputeSignature(signer, true);

        if (!string.IsNullOrWhiteSpace(timestampServer))
        {
            CounterSign(timestampServer,
                timestampAlgorithm ?? hashAlgorithm,
                signInfo.SignerInfos[0]
            ).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        provider.Signature = signInfo.Encode();
        provider.Save(path);
    }

    private static async Task CounterSign(string timestampUrl, HashAlgorithmName algorithm,
        SignerInfo signerInfo)
    {
        Rfc3161TimestampRequest request = Rfc3161TimestampRequest.CreateFromSignerInfo(
            signerInfo,
            HashAlgorithmName.SHA256,
            requestSignerCertificates: true,
            nonce: RandomNumberGenerator.GetBytes(8));

        HttpClient client = new();
        ReadOnlyMemoryContent content = new(request.Encode());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

        HttpResponseMessage response = await client.PostAsync(timestampUrl, content).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            string msg = $"Problem signing with timestamp authority: {response.StatusCode} {(int)response.StatusCode}: {response.Content}";
            throw new CryptographicException(msg);
        }
        if (response.Content.Headers.ContentType?.MediaType != "application/timestamp-reply")
        {
            string msg = "The reply from the time stamp server was in a invalid format.";
            throw new CryptographicException(msg);
        }

        byte[] data = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        Rfc3161TimestampToken token = request.ProcessResponse(data, out var _);
        signerInfo.AddUnsignedAttribute(new("1.3.6.1.4.1.311.3.3.1", token.AsSignedCms().Encode()));

        return;
    }
}

// public record SignatureInfo(string Path, X509Certificate2 Certificate, HashAlgorithmName HashAlgorithm,
//     CounterSignature? TimeStampInfo);

public record CounterSignature(X509Certificate2 Certificate, HashAlgorithmName HashAlgorithm,
    DateTime TimeStamp);

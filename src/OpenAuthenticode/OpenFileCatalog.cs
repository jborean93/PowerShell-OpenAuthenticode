using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace OpenAuthenticode;

[Cmdlet(
    VerbsCommon.Get, "OpenFileCatalog"
)]
public sealed class GetOpenFileCatalog : OpenAuthenticodeSignatureBase
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

    [Parameter]
    public SwitchParameter Entries { get; set; }

    protected override void ProcessRecord()
    {
        (string, ProviderInfo)[] paths = NormalizePaths();

        foreach ((string path, ProviderInfo psProvider) in paths)
        {
            try
            {
                byte[] fileData = File.ReadAllBytes(path);
                IAuthenticodeProvider provider = ProviderFactory.Create(AuthenticodeProvider.SecurityCatalog,
                    fileData);

                SignedCms signInfo = new();
                signInfo.Decode(provider.Signature);
                signInfo.CheckSignature(true);

                if (signInfo.ContentInfo.ContentType.Value != CertificateTrustList.OID.Value)
                {
                    throw new ArgumentException($"Unknown ContentType {signInfo.ContentInfo.ContentType.Value}");
                }

                CertificateTrustList ctl = CertificateTrustList.Parse(signInfo.ContentInfo.Content);
                foreach (TrustedSubject subject in ctl.TrustedSubjects ?? Array.Empty<TrustedSubject>())
                {
                    string identifier = Convert.ToHexString(subject.SubjectIdentifier);
                    PSObject obj = new();
                    obj.Properties.Add(new PSNoteProperty("Tag", identifier));

                    List<(string, string)> labels = new();
                    foreach (Attribute attr in subject.Attributes ?? Array.Empty<Attribute>())
                    {
                        if (attr.Type.Value == CatalogNameValue.OID.Value)
                        {
                            CatalogNameValue nameValue = CatalogNameValue.Parse(attr.Values[0]);
                            labels.Add((nameValue.Name, nameValue.Value.TrimEnd('\u0000')));
                        }
                        else if (attr.Type.Value == SpcIndirectData.OID.Value)
                        {
                            SpcIndirectData indirectData = SpcIndirectData.Parse(attr.Values[0]);

                            HashAlgorithmName algoName = HashAlgorithmName.FromOid(indirectData.DigestAlgorithm.Value ?? "");
                            string thumbprintAlgo = algoName.Name ?? indirectData.DigestAlgorithm.Value ?? "";
                            obj.Properties.Add(new PSNoteProperty("ThumbprintAlgorithm", thumbprintAlgo));
                            obj.Properties.Add(new PSNoteProperty("Thumbprint", Convert.ToHexString(indirectData.Digest)));
                        }
                        // CAT_MEMBERINFO2_OBJID seems to always be present but not populated, just ignore it
                        else if (attr.Type.Value != "1.3.6.1.4.1.311.12.2.3") // CAT_MEMBERINFO2_OBJID
                        {
                            WriteWarning($"Unknown subject attribute '{attr.Type.Value}'");
                        }
                    }

                    foreach ((string name, string value) in labels)
                    {
                        obj.Properties.Add(new PSNoteProperty(name, value));
                    }

                    if (Entries)
                    {
                        WriteObject(obj);
                    }

                }

                PSObject catalogInfo = new();
                catalogInfo.Properties.Add(new PSNoteProperty("Version", ctl.Version));
                catalogInfo.Properties.Add(new PSNoteProperty("EffectiveDate", ctl.ThisUpdate));

                List<(string, string)> extensionValues = new();
                foreach (X509Extension extension in ctl.Extensions ?? Array.Empty<X509Extension>())
                {
                    string extensionOid = extension.Oid?.Value ?? "";
                    if (extensionOid == CatalogNameValue.OID.Value)
                    {
                        CatalogNameValue nameValue = CatalogNameValue.Parse(extension.RawData);
                        catalogInfo.Properties.Add(new PSNoteProperty(nameValue.Name, nameValue.Value.TrimEnd('\u0000')));
                    }
                    else
                    {
                        WriteWarning($"Unknown extension entry '{extensionOid}'");
                    }
                }

                if (!Entries)
                {
                    WriteObject(catalogInfo);
                }
            }
            catch (Exception e)
            {
                ErrorRecord err = new(
                    e,
                    "GetCatalogError",
                    ErrorCategory.NotSpecified,
                    path);
                WriteError(err);
                continue;
            }
        }
    }
}

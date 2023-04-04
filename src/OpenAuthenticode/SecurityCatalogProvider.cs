using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;

namespace OpenAuthenticode;

internal class SecurityCatalogProvider : IAuthenticodeProvider
{
    public byte[] Signature { get; set; }
    public AuthenticodeProvider Provider => AuthenticodeProvider.SecurityCatalog;

    internal static string[] FileExtensions => new[] { ".cat" };

    public static SecurityCatalogProvider Create(byte[] data, Encoding? fileEncoding)
    {
        return new(data, fileEncoding);
    }

    protected SecurityCatalogProvider(byte[] data, Encoding? fileEncoding)
    {
        Signature = data;
    }

    public ContentInfo CreateContent(Oid digestAlgorithm)
    {
        throw new NotImplementedException();
    }

    public void VerifyContent(ContentInfo content, Oid digestAlgorithm)
    {
        if (content.ContentType.Value != CertificateTrustList.OID.Value)
        {
            throw new CryptographicException(string.Format(
                "Expected {0} content type '{1}' but got '{2}'",
                CertificateTrustList.OID.FriendlyName,
                CertificateTrustList.OID.Value,
                content.ContentType.Value));
        }
    }

    public void Save(string path)
    {
        throw new NotImplementedException();
    }

}

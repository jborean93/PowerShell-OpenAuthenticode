using System.Management.Automation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenAuthenticode;

internal static class CertificateHelper
{

    /// <summary>
    /// The order of cert in the collection is platform specific. We manually
    /// find the Azure Trusted Signing cert by the one with an EKU that is the
    /// Azure Trusted Signing OID prefix '1.3.6.1.4.1.311.97.'.
    /// </summary>
    /// <param name="collection">The collection to search.</param>
    /// <param name="cmdlet">The cmdlet to write verbose messages to.</param>
    /// <returns>The leaf certificate to use for signing.</returns>
    /// <exception cref="ItemNotFoundException">Leaf certificate was not found.</exception>
    public static X509Certificate2 GetAzureTrustedSigningCertificate(
        X509Certificate2Collection collection,
        AsyncPSCmdlet? cmdlet = null)
    {
        foreach (X509Certificate2 cert in collection)
        {
            cmdlet?.WriteVerbose(
                $"Processing Azure Trusted Signing certificate: Subject '{cert.Subject}' - Issuer '{cert.Issuer}'");

            foreach (X509Extension ext in cert.Extensions)
            {
                if (ext is not X509EnhancedKeyUsageExtension eku)
                {
                    continue;
                }

                foreach (Oid oid in eku.EnhancedKeyUsages)
                {
                    if (oid?.Value?.StartsWith("1.3.6.1.4.1.311.97.") == true)
                    {
                        return cert;
                    }
                }
            }
        }

        // This should not happen but just in case.
        throw new ItemNotFoundException("Failed to find leaf certificate in Azure Trusted Signing collection.");
    }
}

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace OpenAuthenticode.Shared;

public static class SignerInfoExtensions
{
    /// <summary>
    /// Verifies the digital signature of the message.
    /// </summary>
    /// <remarks>
    /// The builtin method does not take into account when the signature was
    /// counter signed. This extension method allows the caller to provider the
    /// counter signature timestamp to verify checks were valid when it was
    /// verified by the counter signature rather than now.
    /// https://github.com/dotnet/runtime/issues/83478
    /// </remarks>
    /// <param name="verifySignatureOnly">Check only the digital signature and not the certificate validity</param>
    /// <param name="verificationTime">Time used for validating the cert expiry rather than the system time</param>
    /// <param name="extraStore">Extra certificates to use when validating the chain</param>
    public static void CheckSignature(this SignerInfo info, bool verifySignatureOnly, DateTime? verificationTime,
        X509Certificate2Collection? extraStore)
    {
        info.CheckSignature(true);
        if (verifySignatureOnly)
        {
            return;
        }

        X509Certificate2 certificate = info.Certificate
            ?? throw new CryptographicException("Failed to find signing certificate");

        X509Chain chain = new();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

        if (verificationTime != null)
        {
            chain.ChainPolicy.VerificationTime = (DateTime)verificationTime;
        }

        if (extraStore != null)
        {
            foreach (X509Certificate2 cert in extraStore)
            {
                // Treat a self signed cert as trusted, other certs are just
                // added for intermediary checks.
                if (cert.Subject == cert.Issuer)
                {
                    // Dotnet doesn't seem to like a custom CA root without a
                    // CRL so disable the checks. This isn't ideal but if using
                    // a custom trust store but the average use case will be to
                    // use custom roots for testing.
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(cert);
                }
                else
                {
                    chain.ChainPolicy.ExtraStore.Add(cert);
                }
            }
        }

        if (!chain.Build(certificate))
        {
            X509ChainStatus status = chain.ChainStatus.FirstOrDefault();
            throw new CryptographicException(
                $"Certificate trust could not be established. The first reported error is: {status.StatusInformation}");
        }

        const X509KeyUsageFlags SufficientFlags =
            X509KeyUsageFlags.DigitalSignature |
            X509KeyUsageFlags.NonRepudiation;

        foreach (X509Extension ext in certificate.Extensions)
        {
            if (ext.Oid!.Value != "2.5.29.15") // KeyUsage
            {
                continue;
            }

            if (!(ext is X509KeyUsageExtension keyUsage))
            {
                keyUsage = new X509KeyUsageExtension();
                keyUsage.CopyFrom(ext);
            }

            if ((keyUsage.KeyUsages & SufficientFlags) == 0)
            {
                throw new CryptographicException("The certificate is not valid for the requested usage.");
            }
        }
    }
}

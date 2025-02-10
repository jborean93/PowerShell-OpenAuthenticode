using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OpenAuthenticode;

public static class SignatureHelper
{
    private const string OID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1";
    private const string MS_COUNTERSIGN_OID = "1.3.6.1.4.1.311.3.3.1";

    // This is used by the ETS type
    // OpenAuthenticode.AuthenticodeSignature's code property TimeStampInfo
    public static CounterSignature? GetCounterSignature(PSObject obj)
        => GetCounterSignature((SignedCms)obj.BaseObject);

    internal static CounterSignature? GetCounterSignature(SignedCms data)
    {
        if (data.SignerInfos[0].CounterSignerInfos.Count > 0 && data.SignerInfos[0].CounterSignerInfos[0].Certificate != null)
        {
            // Old Authenticode TimeStamp
            return GetAuthenticodeCounterSignature(data.SignerInfos[0].CounterSignerInfos[0]);
        }

        foreach (CryptographicAttributeObject attr in data.SignerInfos[0].UnsignedAttributes)
        {
            if (attr.Oid.Value == MS_COUNTERSIGN_OID &&
                Rfc3161TimestampToken.TryDecode(attr.Values[0].RawData, out var token, out var _))
            {
                // RFC 3161 counter signature
                return GetRfc3161CounterSignature(token.AsSignedCms(), token.TokenInfo);
            }
        }

        return null;
    }

    private static CounterSignature GetAuthenticodeCounterSignature(SignerInfo counterSigner)
    {
        DateTime? signingTime = null;
        foreach (CryptographicAttributeObject attr in counterSigner.SignedAttributes)
        {
            if (attr.Oid.Value == "1.2.840.113549.1.9.5" && attr.Values[0] is Pkcs9SigningTime time)
            {
                signingTime = time.SigningTime.ToUniversalTime();
                break;
            }
        }

        return new(counterSigner.Certificate!,
            HashAlgorithmName.FromOid(counterSigner.DigestAlgorithm.Value ?? ""),
            (DateTime)signingTime!);
    }

    private static CounterSignature GetRfc3161CounterSignature(SignedCms data, Rfc3161TimestampTokenInfo token)
    {
        return new(data.SignerInfos[0].Certificate!,
            HashAlgorithmName.FromOid(token.HashAlgorithmId.Value ?? ""),
            token.Timestamp.UtcDateTime);
    }

    internal static IEnumerable<SignedCms> GetFileSignature(IAuthenticodeProvider provider, bool skipCertificateCheck,
        X509Certificate2Collection? trustStore)
    {
        byte[] signatureData = provider.Signature;
        if (signatureData.Length == 0)
        {
            yield break;
        }

        Queue<byte[]> signatureQueue = new();
        signatureQueue.Enqueue(signatureData);

        while (signatureQueue.Count > 0)
        {
            byte[] data = signatureQueue.Dequeue();
            SignedCms signInfo = DecodeCms(data, provider, skipCertificateCheck, trustStore);
            yield return signInfo;

            foreach (CryptographicAttributeObject attr in signInfo.SignerInfos[0].UnsignedAttributes)
            {
                if (attr.Oid.Value == OID_NESTED_SIGNATURE)
                {
                    foreach (AsnEncodedData sig in attr.Values)
                    {
                        signatureQueue.Enqueue(sig.RawData);
                    }
                }
            }
        }
    }

    internal static SignedCms CreateSignature(
        ContentInfo dataToSign,
        AsnEncodedData[] attributesToSign,
        HashAlgorithmName hashAlgorithm,
        X509Certificate2 cert,
        X509IncludeOption includeOption,
        AsymmetricAlgorithm? privateKey,
        string? timestampServer,
        HashAlgorithmName? timestampAlgorithm,
        bool silent
    )
    {
        Oid digestOid = SpcIndirectData.OidFromHashAlgorithm(hashAlgorithm);
        CmsSigner signer = new(SubjectIdentifierType.IssuerAndSerialNumber, cert, privateKey)
        {
            DigestAlgorithm = digestOid,
            IncludeOption = includeOption,
        };
        foreach (AsnEncodedData toSign in attributesToSign)
        {
            signer.SignedAttributes.Add(toSign);
        }

        SignedCms signInfo = new(dataToSign, false);
        signInfo.ComputeSignature(signer, silent);

        if (!string.IsNullOrWhiteSpace(timestampServer))
        {
            CounterSign(timestampServer,
                timestampAlgorithm ?? hashAlgorithm,
                signInfo.SignerInfos[0]
            ).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        return signInfo;
    }

    internal static void SetFileSignature(
        IAuthenticodeProvider provider,
        SignedCms signInfo,
        bool append
    )
    {
        if (append && provider.Signature.Length > 0)
        {
            SignedCms existingSignature = new();
            existingSignature.Decode(provider.Signature);
            existingSignature.SignerInfos[0].AddUnsignedAttribute(
                new(new Oid(OID_NESTED_SIGNATURE), signInfo.Encode()));

            provider.Signature = existingSignature.Encode();
        }
        else
        {
            provider.Signature = signInfo.Encode();
        }
    }

    internal static PSObject WrapSignedDataForPS(SignedCms data, string? path)
    {
        PSObject signedPSObject = PSObject.AsPSObject(data);
        signedPSObject.TypeNames.Insert(0, "OpenAuthenticode.AuthenticodeSignature");
        signedPSObject.Properties.Add(new PSNoteProperty("Path", path), true);

        return signedPSObject;
    }

    private static SignedCms DecodeCms(ReadOnlySpan<byte> data, IAuthenticodeProvider provider,
        bool skipCertificateCheck, X509Certificate2Collection? trustStore)
    {
        SignedCms signInfo = new();
        signInfo.Decode(data);

        // The builtin CheckSignature does not allowed expired certs even if
        // they were counter signed during their validity, this uses an
        // extension method to account for this scenario.
        CounterSignature? counterSignature = GetCounterSignature(signInfo);
        CheckSignature(signInfo.SignerInfos, skipCertificateCheck, counterSignature, trustStore);

        if (signInfo.ContentInfo.ContentType.Value != SpcIndirectData.OID.Value)
        {
            throw new ArgumentException($"Unknown ContentType {signInfo.ContentInfo.ContentType.Value}");
        }
        SpcIndirectData dataContent = SpcIndirectData.Parse(signInfo.ContentInfo.Content);
        SpcIndirectData actualContent = provider.HashData(dataContent.DigestAlgorithm);

        if (!Enumerable.SequenceEqual(actualContent.Digest, dataContent.Digest))
        {
            string msg = $"Signature mismatch: {Convert.ToHexString(actualContent.Digest)} != {Convert.ToHexString(dataContent.Digest)}";
            throw new CryptographicException(msg);
        }

        return signInfo;
    }

    private static void CheckSignature(SignerInfoCollection signers, bool verifySignatureOnly,
        CounterSignature? counterSignature, X509Certificate2Collection? trustStore)
    {
        if (signers.Count < 1)
        {
            throw new CryptographicException("The signed cryptographic message does not have a signer.");
        }

        foreach (SignerInfo signer in signers)
        {
            signer.CheckSignature(verifySignatureOnly, counterSignature?.TimeStamp, trustStore);

            SignerInfoCollection counterSigners = signer.CounterSignerInfos;
            if (counterSigners.Count > 0)
            {
                CheckSignature(counterSigners, verifySignatureOnly, counterSignature, trustStore);
            }
        }
    }

    private static async Task CounterSign(string timestampUrl, HashAlgorithmName algorithm,
        SignerInfo signerInfo)
    {
        Rfc3161TimestampRequest request = Rfc3161TimestampRequest.CreateFromSignerInfo(
            signerInfo,
            algorithm,
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
        signerInfo.AddUnsignedAttribute(new(MS_COUNTERSIGN_OID, token.AsSignedCms().Encode()));

        return;
    }
}

public record CounterSignature(X509Certificate2 Certificate, HashAlgorithmName HashAlgorithm,
    DateTime TimeStamp);

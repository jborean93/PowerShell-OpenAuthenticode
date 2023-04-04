using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OpenAuthenticode;

internal sealed record CatalogNameValue(string Name, BigInteger Unknown, string Value)
{
    public static readonly Oid OID = new("1.3.6.1.4.1.311.12.2.1", "CAT_NAMEVALUE_OBJID");

    public static CatalogNameValue Parse(ReadOnlySpan<byte> data)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        AsnDecoder.ReadSequence(data, rules, out var offset, out var length, out var consumed);
        data = data.Slice(offset, length);

        string label = AsnDecoder.ReadCharacterString(data, rules, UniversalTagNumber.BMPString, out consumed);
        data = data[consumed..];

        BigInteger unknown = AsnDecoder.ReadInteger(data, rules, out consumed);
        data = data[consumed..];

        string value = Encoding.Unicode.GetString(AsnDecoder.ReadOctetString(data, rules, out consumed));

        return new(label, unknown, value);
    }
}

internal sealed record CertificateTrustList(int Version, Oid[] SubjectUsage, byte[]? ListIdentifier,
    BigInteger? SequenceNumber, DateTimeOffset ThisUpdate, DateTimeOffset? NextUpdate, Oid SubjectAlgorithm,
    byte[]? SubjectAlgorithmParameters, TrustedSubject[]? TrustedSubjects, X509Extension[]? Extensions)
{
    public static readonly Oid OID = new("1.3.6.1.4.1.311.10.1", "szOID_CTL");

    /*
    // Defined in MS-CAESO 4.4.5.3.3 Initializing Automatic Certificate Request Settings
    // https://download.microsoft.com/download/C/8/8/C8862966-5948-444D-87BD-07B976ADA28C/%5BMS-CAESO%5D.pdf

    CertificateTrustList ::= SEQUENCE {
        version CTLVersion DEFAULT v1,
        subjectUsage SubjectUsage,
        listIdentifier ListIdentifier OPTIONAL,
        sequenceNumber HUGEINTEGER OPTIONAL,
        ctlThisUpdate ChoiceOfTime,
        ctlNextUpdate ChoiceOfTime OPTIONAL,
        subjectAlgorithm AlgorithmIdentifier,
        trustedSubjects TrustedSubjects OPTIONAL,
        ctlExtensions [0] EXPLICIT Extensions OPTIONAL
    }

    CTLVersion ::= INTEGER {v1(0)}

    SubjectUsage ::= EnhancedKeyUsage

    ListIdentifier ::= OCTETSTRING

    TrustedSubjects ::= SEQUENCE OF TrustedSubject

    AlgorithmIdentifier    ::=    SEQUENCE {
        algorithm           ObjectID,
        parameters          [0] EXPLICIT ANY OPTIONAL
    }

    ChoiceOfTime ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionenhancedkeyusage
    EnhancedKeyUsage ::= SEQUENCE OF UsageIdentifier

    UsageIdentifier ::= EncodedObjectID
    */

    public static CertificateTrustList Parse(ReadOnlySpan<byte> data)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        AsnDecoder.ReadSequence(data, rules, out var offset, out var length, out var consumed);
        data = data.Slice(offset, length);

        int version = 1;
        Asn1Tag nextTag = AsnDecoder.ReadEncodedValue(data, rules, out offset, out length, out consumed);
        if (nextTag.TagClass == TagClass.Universal && nextTag.TagValue == (int)UniversalTagNumber.Integer)
        {
            version = (int)AsnDecoder.ReadInteger(data, rules, out consumed);
            data = data[consumed..];
        }

        List<Oid> subjectUsage = new();
        AsnDecoder.ReadSequence(data, rules, out offset, out length, out consumed);
        ReadOnlySpan<byte> subjectUsageRaw = data.Slice(offset, length);
        data = data[consumed..];
        while (subjectUsageRaw.Length > 0)
        {
            string usageOid = AsnDecoder.ReadObjectIdentifier(subjectUsageRaw, rules, out consumed);
            subjectUsageRaw = subjectUsageRaw[consumed..];

            subjectUsage.Add(new Oid(usageOid));
        }

        byte[]? listIdentifier = null;
        nextTag = AsnDecoder.ReadEncodedValue(data, rules, out offset, out length, out consumed);
        if (nextTag.TagClass == TagClass.Universal && nextTag.TagValue == (int)UniversalTagNumber.OctetString)
        {
            listIdentifier = AsnDecoder.ReadOctetString(data, rules, out consumed);
            data = data[consumed..];

            nextTag = AsnDecoder.ReadEncodedValue(data, rules, out offset, out length, out consumed);
        }

        BigInteger? sequenceNumber = null;
        if (nextTag.TagClass == TagClass.Universal && nextTag.TagValue == (int)UniversalTagNumber.Integer)
        {
            sequenceNumber = AsnDecoder.ReadInteger(data, rules, out consumed);
            data = data[consumed..];

            nextTag = AsnDecoder.ReadEncodedValue(data, rules, out offset, out length, out consumed);
        }

        DateTimeOffset thisUpdate = nextTag.TagValue switch
        {
            (int)UniversalTagNumber.UtcTime => AsnDecoder.ReadUtcTime(data, rules, out consumed),
            _ => AsnDecoder.ReadGeneralizedTime(data, rules, out consumed),
        };
        data = data[consumed..];
        nextTag = AsnDecoder.ReadEncodedValue(data, rules, out offset, out length, out consumed);

        DateTimeOffset? nextUpdate = null;
        if (nextTag.TagClass == TagClass.Universal && nextTag.TagValue == (int)UniversalTagNumber.UtcTime)
        {
            nextUpdate = AsnDecoder.ReadUtcTime(data, rules, out consumed);
            data = data[consumed..];

        }
        else if (nextTag.TagClass == TagClass.Universal && nextTag.TagValue == (int)UniversalTagNumber.GeneralizedTime)
        {
            nextUpdate = AsnDecoder.ReadGeneralizedTime(data, rules, out consumed);
            data = data[consumed..];
        }

        AsnDecoder.ReadSequence(data, rules, out offset, out length, out consumed);
        ReadOnlySpan<byte> algorithmIdRaw = data.Slice(offset, length);
        data = data[consumed..];

        Oid subjectAlgorithm = new Oid(AsnDecoder.ReadObjectIdentifier(algorithmIdRaw, rules, out consumed));
        algorithmIdRaw = algorithmIdRaw[consumed..];
        byte[]? subjectAlgorithmParameters = algorithmIdRaw.ToArray();
        if (subjectAlgorithmParameters.Length == 2 && subjectAlgorithmParameters[0] == 5 && subjectAlgorithmParameters[1] == 0)
        {
            subjectAlgorithmParameters = null;
        }

        List<TrustedSubject>? trustedSubjects = null;
        if (data.Length > 0)
        {
            nextTag = AsnDecoder.ReadEncodedValue(data, rules, out offset, out length, out consumed);

            if (nextTag.TagClass == TagClass.Universal && nextTag.TagValue == (int)UniversalTagNumber.SequenceOf)
            {
                trustedSubjects = new();

                AsnDecoder.ReadSequence(data, rules, out offset, out length, out consumed);
                ReadOnlySpan<byte> subjects = data.Slice(offset, length);
                while (subjects.Length > 0)
                {
                    TrustedSubject subj = TrustedSubject.Parse(subjects, out var subjConsumed);
                    subjects = subjects[subjConsumed..];
                    trustedSubjects.Add(subj);
                }

                data = data[consumed..];
            }
        }

        List<X509Extension>? extensions = null;
        if (data.Length > 0)
        {
            nextTag = AsnDecoder.ReadEncodedValue(data, rules, out offset, out length, out consumed);
            if (nextTag.TagClass == TagClass.ContextSpecific && nextTag.TagValue == 0)
            {
                extensions = new();

                AsnDecoder.ReadSequence(data, rules, out offset, out length, out consumed, expectedTag: nextTag);
                ReadOnlySpan<byte> extensionsRaw = data.Slice(offset, length);
                data = data[consumed..];

                AsnDecoder.ReadSequence(extensionsRaw, rules, out offset, out length, out consumed);
                extensionsRaw = extensionsRaw.Slice(offset, length);

                while (extensionsRaw.Length > 0)
                {
                    AsnDecoder.ReadSequence(extensionsRaw, rules, out offset, out length, out consumed);
                    ReadOnlySpan<byte> extensionData = extensionsRaw.Slice(offset, length);
                    extensionsRaw = extensionsRaw[consumed..];

                    string extOid = AsnDecoder.ReadObjectIdentifier(extensionData, rules, out consumed);
                    extensionData = extensionData[consumed..];
                    nextTag = AsnDecoder.ReadEncodedValue(extensionData, rules, out offset, out length, out consumed);

                    bool critical = false;
                    if (nextTag.TagClass == TagClass.Universal && nextTag.TagValue == (int)UniversalTagNumber.Boolean)
                    {
                        critical = AsnDecoder.ReadBoolean(extensionData, rules, out consumed);
                        extensionData = extensionData[consumed..];
                    }
                    byte[] rawExtensionValue = AsnDecoder.ReadOctetString(extensionData, rules, out consumed);

                    X509Extension ext = new(new Oid(extOid), rawExtensionValue, critical);

                    extensions.Add(ext);
                }
            }
        }

        return new(version, subjectUsage.ToArray(), listIdentifier, sequenceNumber, thisUpdate, nextUpdate,
            subjectAlgorithm, subjectAlgorithmParameters, trustedSubjects?.ToArray(), extensions?.ToArray());
    }
}

internal sealed record TrustedSubject(byte[] SubjectIdentifier, Attribute[]? Attributes)
{
    /*
    TrustedSubject ::= SEQUENCE{
        subjectIdentifier SubjectIdentifier,
        subjectAttributes Attributes OPTIONAL
    }

    SubjectIdentifier ::= OCTETSTRING

    Attributes ::= SET OF Attribute
    */

    public static TrustedSubject Parse(ReadOnlySpan<byte> data, out int consumed)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        AsnDecoder.ReadSequence(data, rules, out var offset, out var length, out consumed);
        data = data.Slice(offset, length);

        byte[] subjectIdentifier = AsnDecoder.ReadOctetString(data, rules, out var dataConsumed);
        data = data[dataConsumed..];

        List<Attribute>? attributes = null;
        if (data.Length > 0)
        {
            attributes = new();
            AsnDecoder.ReadSetOf(data, rules, out offset, out length, out dataConsumed);
            ReadOnlySpan<byte> attributesRaw = data.Slice(offset, length);
            data = data[dataConsumed..];

            while (attributesRaw.Length > 0)
            {
                Attribute attr = Attribute.Parse(attributesRaw, out dataConsumed);
                attributesRaw = attributesRaw[dataConsumed..];
                attributes.Add(attr);
            }
        }

        return new(subjectIdentifier, attributes?.ToArray());
    }
}

internal sealed record Attribute(Oid Type, byte[][] Values)
{
    /*
    Attribute               ::= SEQUENCE {
        type             AttributeType,
        values    SET OF AttributeValue }
                -- at least one value is required

    AttributeType           ::= OBJECT IDENTIFIER

    AttributeValue          ::= ANY -- DEFINED BY AttributeType
    */

    public static Attribute Parse(ReadOnlySpan<byte> data, out int consumed)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        AsnDecoder.ReadSequence(data, rules, out var offset, out var length, out consumed);
        data = data.Slice(offset, length);

        string attrType = AsnDecoder.ReadObjectIdentifier(data, rules, out var dataConsumed);
        data = data[dataConsumed..];

        List<byte[]> values = new();
        AsnDecoder.ReadSetOf(data, rules, out offset, out length, out dataConsumed);
        ReadOnlySpan<byte> valuesRaw = data.Slice(offset, length);
        data = data[dataConsumed..];

        while (valuesRaw.Length > 0)
        {
            AsnDecoder.ReadEncodedValue(valuesRaw, rules, out offset, out length, out dataConsumed);
            values.Add(valuesRaw[..dataConsumed].ToArray());
            valuesRaw = valuesRaw[dataConsumed..];
        }

        return new(new Oid(attrType), values.ToArray());
    }
}

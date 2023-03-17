using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;

namespace OpenAuthenticode;

/// <summary>
/// Data used to identify the object being signed. This structure is signed and
/// embedded as part of the PKCS #7 ContentInfo value. The method used to
/// derive the property values of this content is specific to each authenticode
/// provider.
/// </summary>
/// <param name="DataType">The data type identifier</param>
/// <param name="Data">Extra data to add as part of the signature</param>
/// <param name="DigestAlgorithm">The digest algorithm identifier</param>
/// <param name="DigestParameters">Extra parameters supplied to the digest algorithm.</param>
/// <param name="Digest">The digest/hash of the provider data</param>
internal sealed record SpcIndirectData(Oid DataType, byte[]? Data, Oid DigestAlgorithm,
    byte[]? DigestParameters, byte[] Digest)
{
    public static readonly Oid OID = new("1.3.6.1.4.1.311.2.1.4", "SPC_INDIRECT_DATA_OBJID");

    /*
    SpcIndirectDataContent ::= SEQUENCE {
        data                    SpcAttributeTypeAndOptionalValue,
        messageDigest           DigestInfo
    } --#public—

    SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
        type                    ObjectID,
        value                   [0] EXPLICIT ANY OPTIONAL
    }

    DigestInfo ::= SEQUENCE {
        digestAlgorithm     AlgorithmIdentifier,
        digest              OCTETSTRING
    }

    AlgorithmIdentifier    ::=    SEQUENCE {
        algorithm           ObjectID,
        parameters          [0] EXPLICIT ANY OPTIONAL
    }
    */

    public static SpcIndirectData Parse(ReadOnlySpan<byte> data)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        AsnDecoder.ReadSequence(data, rules, out var offset, out var length, out var consumed);
        data = data.Slice(offset, length);

        AsnDecoder.ReadSequence(data, rules, out offset, out length, out consumed);
        ReadOnlySpan<byte> dataSequence = data.Slice(offset, length);
        data = data[consumed..];

        Oid dataType = new Oid(AsnDecoder.ReadObjectIdentifier(dataSequence, rules, out consumed));
        dataSequence = dataSequence[consumed..];

        // Change 0x05, 0x00 to null as that's what ASN.1 DER represents.
        byte[]? typeData = dataSequence.ToArray();
        if (typeData.Length == 2 && typeData[0] == 5 && typeData[1] == 0)
        {
            typeData = null;
        }

        AsnDecoder.ReadSequence(data, rules, out offset, out length, out consumed);
        ReadOnlySpan<byte> digestSequence = data.Slice(offset, length);
        data = data[consumed..];

        AsnDecoder.ReadSequence(digestSequence, rules, out offset, out length, out consumed);
        ReadOnlySpan<byte> algorithmSequence = digestSequence.Slice(offset, length);
        digestSequence = digestSequence[consumed..];

        Oid digestAlgorithm = new Oid(AsnDecoder.ReadObjectIdentifier(algorithmSequence, rules, out consumed));
        algorithmSequence = algorithmSequence[consumed..];

        byte[]? digestParameters = algorithmSequence.ToArray();
        if (digestParameters.Length == 2 && digestParameters[0] == 5 && digestParameters[1] == 0)
        {
            digestParameters = null;
        }

        byte[] digest = AsnDecoder.ReadOctetString(digestSequence, rules, out consumed);
        digestSequence = digestSequence[consumed..];

        return new(dataType, typeData, digestAlgorithm, digestParameters, digest);
    }

    public byte[] GetBytes()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (var dataContent = writer.PushSequence())
        {
            using (var data = writer.PushSequence())
            {
                writer.WriteObjectIdentifier(DataType.Value ?? "");
                if (Data == null)
                {
                    writer.WriteNull();
                }
                else
                {
                    writer.WriteEncodedValue(Data);
                }
            }

            using (var messageDigest = writer.PushSequence())
            {
                using (var digestAlgorithm = writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(DigestAlgorithm.Value ?? "");
                    if (DigestParameters == null)
                    {
                        writer.WriteNull();
                    }
                    else
                    {
                        writer.WriteEncodedValue(DigestParameters);
                    }
                }

                writer.WriteOctetString(Digest);
            }
        }

        return writer.Encode();
    }

    public static HashAlgorithm HashAlgorithmFromOid(Oid oid)
    {
        HashAlgorithmName algo = HashAlgorithmName.FromOid(oid.Value ?? "");
        return algo.Name switch
        {
            "SHA1" => SHA1.Create(),
            "SHA256" => SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            _ => throw new NotImplementedException($"Unknown digest algorithm {algo.Name}"),
        };
    }

    public static Oid OidFromHashAlgorithm(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        "SHA1" => new Oid("1.3.14.3.2.26"),
        "SHA256" => new Oid("2.16.840.1.101.3.4.2.1"),
        "SHA384" => new Oid("2.16.840.1.101.3.4.2.2"),
        "SHA512" => new Oid("2.16.840.1.101.3.4.2.3"),
        _ => throw new NotImplementedException($"Unknown hash algorithm {algorithm.Name}"),
    };
}

/// <summary>
/// Data used to identify a Subject Interface Package (SIP). This structure
/// is not documented publicly and the format is derived from inspecting real
/// world implementation.
/// </summary>
/// <param name="Version">The version of the SIP</param>
/// <param name="Identifier">The SIP identifier</param>
internal sealed record SpcSipInfo(int Version, Guid Identifier)
{
    public static readonly Oid OID = new("1.3.6.1.4.1.311.2.1.30", "SPC_SIPINFO_OBJID");

    public static SpcSipInfo Parse(ReadOnlySpan<byte> data)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        AsnDecoder.ReadSequence(data, rules, out var offset, out var length, out var consumed);
        data = data.Slice(offset, length);

        int version = (int)AsnDecoder.ReadInteger(data, rules, out consumed);
        data = data[consumed..];

        byte[] identifier = AsnDecoder.ReadOctetString(data, rules, out consumed);
        data = data[consumed..];

        // int reserved1 = (int)AsnDecoder.ReadInteger(data, rules, out consumed);
        // data = data[consumed..];

        // int reserved2 = (int)AsnDecoder.ReadInteger(data, rules, out consumed);
        // data = data[consumed..];

        // int reserved3 = (int)AsnDecoder.ReadInteger(data, rules, out consumed);
        // data = data[consumed..];

        // int reserved4 = (int)AsnDecoder.ReadInteger(data, rules, out consumed);
        // data = data[consumed..];

        // int reserved5 = (int)AsnDecoder.ReadInteger(data, rules, out consumed);
        // data = data[consumed..];

        return new(version, new Guid(identifier));
    }

    public byte[] GetBytes()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (var dataContent = writer.PushSequence())
        {
            writer.WriteInteger(Version);
            writer.WriteOctetString(Identifier.ToByteArray());
            writer.WriteInteger(0);
            writer.WriteInteger(0);
            writer.WriteInteger(0);
            writer.WriteInteger(0);
            writer.WriteInteger(0);
        }

        return writer.Encode();
    }
}

/// <summary>
/// Publisher information.
/// </summary>
/// <param name="ProgramName">The program name</param>
/// <param name="MoreInfo">More info/URL of the publisher</param>
internal sealed record SpcSpOpusInfo(string? ProgramName, string? MoreInfo)
{
    public static readonly Oid OID = new("1.3.6.1.4.1.311.2.1.12", "SPC_SP_OPUS_INFO_OBJID");

    /*
        SpcSpOpusInfo ::= SEQUENCE {
            programName             [0] EXPLICIT SpcString OPTIONAL,
            moreInfo                [1] EXPLICIT SpcLink OPTIONAL,
        } --#public--
    */

    public static SpcSpOpusInfo Parse(ReadOnlySpan<byte> data)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        AsnDecoder.ReadSequence(data, rules, out var offset, out var length, out var consumed);
        data = data.Slice(offset, length);

        string? programName = null;
        string? moreInfo = null;
        while (data.Length > 0)
        {
            Asn1Tag tag = AsnDecoder.ReadEncodedValue(data, rules, out offset, out length, out consumed);
            ReadOnlySpan<byte> tagData = data.Slice(offset, length);
            data = data[consumed..];

            if (tag.TagClass == TagClass.ContextSpecific)
            {
                if (tag.TagValue == 0)
                {
                    programName = ParseSpcString(tagData);
                }
                else if (tag.TagValue == 1)
                {
                    moreInfo = ParseSpcLink(tagData);
                }
            }
        }

        return new(programName, moreInfo);
    }

    public byte[] GetBytes()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (var dataContent = writer.PushSequence())
        {
        }

        return writer.Encode();
    }

    private static string ParseSpcString(ReadOnlySpan<byte> data)
    {
        /*
            SpcString ::= CHOICE {
                unicode                 [0] IMPLICIT BMPSTRING,
                ascii                   [1] IMPLICIT IA5STRING
            }
        */
        AsnEncodingRules rules = AsnEncodingRules.DER;
        Asn1Tag tag = AsnDecoder.ReadEncodedValue(data, rules, out var offset, out var length, out var consumed);
        data = data.Slice(offset, length);

        return tag.TagValue switch
        {
            0 => Encoding.Unicode.GetString(data),
            1 => Encoding.ASCII.GetString(data),
            _ => throw new NotImplementedException($"SpcString with unknown choice {tag}"),
        };
    }

    private static string ParseSpcLink(ReadOnlySpan<byte> data)
    {
        /*
            SpcLink ::= CHOICE {
                url                     [0] IMPLICIT IA5STRING,
                moniker                 [1] IMPLICIT SpcSerializedObject,
                file                    [2] EXPLICIT SpcString
            } --#public--
        */
        AsnEncodingRules rules = AsnEncodingRules.DER;
        Asn1Tag tag = AsnDecoder.ReadEncodedValue(data, rules, out var offset, out var length, out var consumed);
        data = data.Slice(offset, length);

        return tag.TagValue switch
        {
            0 => Encoding.ASCII.GetString(data),
            // 1 => NotImplemented
            2 => ParseSpcString(data),
            _ => throw new NotImplementedException($"SpcLink with unknown choice {tag}"),
        };
    }
}

/// <summary>
/// List of key usages.
/// </summary>
/// <param name="Id">The key usages as OIDs</param>
internal sealed record SpcStatementType(Oid[] Id)
{
    public static readonly Oid OID = new("1.3.6.1.4.1.311.2.1.11", "SPC_STATEMENT_TYPE_OBJID");

    public static SpcStatementType Parse(ReadOnlySpan<byte> data)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        AsnDecoder.ReadSequence(data, rules, out var offset, out var length, out var consumed);
        data = data.Slice(offset, length);

        List<Oid> ids = new();
        while (data.Length > 0)
        {
            string id = AsnDecoder.ReadObjectIdentifier(data, rules, out consumed);
            data = data[consumed..];

            ids.Add(new(id));
        }

        return new(ids.ToArray());
    }

    public byte[] GetBytes()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (var dataContent = writer.PushSequence())
        {
            foreach (Oid o in Id)
            {
                writer.WriteObjectIdentifier(o.Value ?? "");
            }
        }

        return writer.Encode();
    }
}

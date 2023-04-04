using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;

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

    public static Oid OidFromHashAlgorithm(HashAlgorithmName algorithm) => algorithm.Name switch
    {
        "SHA1" => new Oid("1.3.14.3.2.26"),
        "SHA256" => new Oid("2.16.840.1.101.3.4.2.1"),
        "SHA384" => new Oid("2.16.840.1.101.3.4.2.2"),
        "SHA512" => new Oid("2.16.840.1.101.3.4.2.3"),
        _ => throw new NotImplementedException($"Unknown hash algorithm {algorithm.Name}"),
    };

    internal void Validate(Oid contentType, ReadOnlySpan<byte> content)
    {
        if (contentType.Value != SpcIndirectData.OID.Value)
        {
            throw new CryptographicException(string.Format(
                "Expected {0} content type '{1}' but got '{2}'",
                SpcIndirectData.OID.FriendlyName,
                SpcIndirectData.OID.Value,
                contentType.Value));
        }
        SpcIndirectData actualContent = SpcIndirectData.Parse(content);

        if (actualContent.DigestAlgorithm != DigestAlgorithm)
        {
            throw new CryptographicException(string.Format(
                "Unexpected digest algorithm '{0}', expecting '{1}'",
                actualContent.DigestAlgorithm,
                DigestAlgorithm));
        }

        if (!Enumerable.SequenceEqual(actualContent.Digest, Digest))
        {
            throw new CryptographicException(string.Format(
                "Signature mismatch: {0} != {1}",
                Convert.ToHexString(actualContent.Digest),
                Convert.ToHexString(Digest)));
        }
    }
}

/// <summary>
/// PE Image Data flags.
/// </summary>
internal enum SpcPeImageFlags
{
    IncludeResources = 0,
    IncludeDebugInfo = 1,
    includeImportAddressTable = 2,
}

/// <summary>
/// PE image metadata.
/// </summary>
/// <param name="Flags">Image data flags</param>
/// <param name="File">Software publisher information.</param>
internal sealed record SpcPeImageData(SpcPeImageFlags Flags, SpcLink File)
{
    public static readonly Oid OID = new("1.3.6.1.4.1.311.2.1.15", "SPC_PE_IMAGE_DATAOBJ");

    /*
    SpcPeImageData ::= SEQUENCE {
        flags                   SpcPeImageFlags DEFAULT { includeResources },
        file                    SpcLink
    } --#public--

    SpcPeImageFlags ::= BIT STRING {
        includeResources            (0),
        includeDebugInfo            (1),
        includeImportAddressTable   (2)
    }
    */

    public static SpcPeImageData Parse(ReadOnlySpan<byte> data)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        AsnDecoder.ReadSequence(data, rules, out var offset, out var length, out var consumed);
        ReadOnlySpan<byte> dataSequence = data.Slice(offset, length);
        data = data[consumed..];

        byte[] rawFlags = AsnDecoder.ReadBitString(dataSequence, rules, out var _, out consumed);
        SpcPeImageFlags flags = SpcPeImageFlags.IncludeResources;
        if (rawFlags.Length > 0)
        {
            flags = rawFlags[0] switch
            {
                0 => SpcPeImageFlags.IncludeResources,
                1 => SpcPeImageFlags.IncludeDebugInfo,
                2 => SpcPeImageFlags.includeImportAddressTable,
                _ => throw new NotImplementedException($"Unknown flags {rawFlags[0]}"),
            };
        }
        dataSequence = dataSequence[consumed..];

        // While the specs do not show this, the SpcLink file entry is tagged
        // as 0. Try and handle both scenarios.
        Asn1Tag fileTag = AsnDecoder.ReadEncodedValue(dataSequence, rules, out offset, out length, out consumed);
        if (fileTag.TagClass == TagClass.ContextSpecific && fileTag.TagValue == 0)
        {
            dataSequence = dataSequence.Slice(offset, length);
        }
        SpcLink file = SpcLink.Parse(dataSequence);

        return new(flags, file);
    }

    public byte[] GetBytes()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (var dataContent = writer.PushSequence())
        {
            byte[] rawFlags = Array.Empty<byte>();
            if (Flags != SpcPeImageFlags.IncludeResources)
            {
                rawFlags = new[] { (byte)Flags };
            }
            writer.WriteBitString(rawFlags);

            Asn1Tag fileTag = new(TagClass.ContextSpecific, 0, true);
            using (var fileSequence = writer.PushSequence(fileTag))
            {
                writer.WriteEncodedValue(File.GetBytes());
            }
        }

        return writer.Encode();
    }
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
internal sealed record SpcSpOpusInfo(SpcString? ProgramName, SpcLink? MoreInfo)
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

        SpcString? programName = null;
        SpcLink? moreInfo = null;
        while (data.Length > 0)
        {
            Asn1Tag tag = AsnDecoder.ReadEncodedValue(data, rules, out offset, out length, out consumed);
            ReadOnlySpan<byte> tagData = data.Slice(offset, length);
            data = data[consumed..];

            if (tag.TagClass == TagClass.ContextSpecific)
            {
                if (tag.TagValue == 0)
                {
                    programName = SpcString.Parse(tagData);
                }
                else if (tag.TagValue == 1)
                {
                    moreInfo = SpcLink.Parse(tagData);
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
            if (ProgramName != null)
            {
                Asn1Tag valueTag = new Asn1Tag(TagClass.ContextSpecific, 0, true);
                using (var valueSeq = writer.PushSequence(valueTag))
                {
                    writer.WriteEncodedValue(ProgramName.GetBytes());
                }
            }
            if (MoreInfo != null)
            {
                Asn1Tag valueTag = new Asn1Tag(TagClass.ContextSpecific, 1, true);
                using (var valueSeq = writer.PushSequence(valueTag))
                {
                    writer.WriteEncodedValue(MoreInfo.GetBytes());
                }
            }
        }

        return writer.Encode();
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

/// <summary>
/// Describes the software publisher. Most modern signers set File to an empty
/// unicode string.
/// </summary>
/// <param name="Url">The publisher URL</param>
/// <param name="Moniker">Specialised data</param>
/// <param name="File">The file name</param>
internal sealed record SpcLink(string? Url = null, SpcSerializedObject? Moniker = null, SpcString? File = null)
{
    /*
    SpcLink ::= CHOICE {
        url                     [0] IMPLICIT IA5STRING,
        moniker                 [1] IMPLICIT SpcSerializedObject,
        file                    [2] EXPLICIT SpcString
    } --#public--
    */

    public static SpcLink Parse(ReadOnlySpan<byte> data)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        string? url = null;
        SpcSerializedObject? moniker = null;
        SpcString? file = null;
        Asn1Tag tag = AsnDecoder.ReadEncodedValue(data, rules, out var offset, out var length, out var consumed);
        if (tag.TagValue == 0)
        {
            url = AsnDecoder.ReadCharacterString(data, rules, UniversalTagNumber.IA5String, out consumed, tag);
        }
        else if (tag.TagValue == 1)
        {
            moniker = SpcSerializedObject.Parse(data.Slice(offset, length), expectedTag: tag);
        }
        else if (tag.TagValue == 2)
        {
            file = SpcString.Parse(data.Slice(offset, length));
        }
        else
        {
            throw new NotImplementedException($"SpcLink with unknown choice {tag}");
        }

        return new(url, moniker, file);
    }

    public byte[] GetBytes()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);

        if (Url != null)
        {
            writer.WriteCharacterString(UniversalTagNumber.IA5String, Url,
                new Asn1Tag(TagClass.ContextSpecific, 0));
        }
        else if (Moniker != null)
        {
            Asn1Tag monikerTag = new Asn1Tag(TagClass.ContextSpecific, 1, true);
            writer.WriteEncodedValue(Moniker.GetBytes(monikerTag));
        }
        else if (File != null)
        {
            Asn1Tag fileTag = new Asn1Tag(TagClass.ContextSpecific, 2, true);
            using (var fileSeq = writer.PushSequence(fileTag))
            {
                writer.WriteEncodedValue(File.GetBytes());
            }
        }

        return writer.Encode();
    }
}

/// <summary>
/// Special serialized info.
/// </summary>
/// <param name="ClassId">An identifier of the serialized object</param>
/// <param name="Data">The raw data.</param>
internal sealed record SpcSerializedObject(Guid ClassId, byte[] Data)
{
    /*
    SpcSerializedObject ::= SEQUENCE {
        classId             SpcUuid,
        serializedData      OCTETSTRING
    }

    SpcUuid ::= OCTETSTRING
    */

    public static SpcSerializedObject Parse(ReadOnlySpan<byte> data, Asn1Tag? expectedTag = null)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        AsnDecoder.ReadSequence(data, rules, out var offset, out var length, out var consumed,
            expectedTag: expectedTag);
        data = data.Slice(offset, length);

        byte[] classId = AsnDecoder.ReadOctetString(data, rules, out consumed);
        data = data[consumed..];

        byte[] rawData = AsnDecoder.ReadOctetString(data, rules, out consumed);
        data = data[consumed..];

        return new(new Guid(classId), rawData);
    }

    public byte[] GetBytes(Asn1Tag? tag = null)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (var dataContent = writer.PushSequence(tag: tag))
        {
            writer.WriteOctetString(ClassId.ToByteArray());
            writer.WriteOctetString(Data);
        }

        return writer.Encode();
    }
}

/// <summary>
/// A unicode or ascii string value.
/// </summary>
/// <param name="Unicode">A Unicode string</param>
/// <param name="Ascii">An ASCII string</param>
internal sealed record SpcString(string? Unicode = null, string? Ascii = null)
{
    /*
    SpcString ::= CHOICE {
        unicode                 [0] IMPLICIT BMPSTRING,
        ascii                   [1] IMPLICIT IA5STRING
    }
    */

    public static SpcString Parse(ReadOnlySpan<byte> data)
    {
        AsnEncodingRules rules = AsnEncodingRules.DER;

        string? unicode = null;
        string? ascii = null;
        Asn1Tag tag = AsnDecoder.ReadEncodedValue(data, rules, out var offset, out var length, out var consumed);
        if (tag.TagValue == 0)
        {
            unicode = AsnDecoder.ReadCharacterString(data, rules, UniversalTagNumber.BMPString, out consumed, tag);
        }
        else if (tag.TagValue == 1)
        {
            ascii = AsnDecoder.ReadCharacterString(data, rules, UniversalTagNumber.IA5String, out consumed, tag);
        }
        else
        {
            throw new NotImplementedException($"SpcString with unknown choice {tag}");
        }

        return new(unicode, ascii);
    }

    public byte[] GetBytes()
    {
        AsnWriter writer = new(AsnEncodingRules.DER);

        if (Unicode != null)
        {
            writer.WriteCharacterString(UniversalTagNumber.BMPString, Unicode,
                new Asn1Tag(TagClass.ContextSpecific, 0));
        }
        else if (Ascii != null)
        {
            writer.WriteCharacterString(UniversalTagNumber.IA5String, Ascii,
                new Asn1Tag(TagClass.ContextSpecific, 1));
        }

        return writer.Encode();
    }
}

using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading.Tasks;
using OpenAuthenticode.Providers;

namespace OpenAuthenticodeTests;

public class SpcStructuresTests
{
    [Test]
    public async Task TestSpcIndirectDataRoundTrip()
    {
        byte[] digest = new byte[] { 1, 2, 3, 4 };
        SpcIndirectData original = new(
            DataType: new Oid("1.2.3.4"),
            Data: null,
            DigestAlgorithm: new Oid("2.16.840.1.101.3.4.2.1"),
            DigestParameters: null,
            Digest: digest);

        byte[] encoded = original.GetBytes();
        SpcIndirectData parsed = SpcIndirectData.Parse(encoded);

        await Assert.That(parsed.DataType.Value).IsEqualTo(original.DataType.Value);
        await Assert.That(parsed.Data).IsNull();
        await Assert.That(parsed.DigestAlgorithm.Value).IsEqualTo(original.DigestAlgorithm.Value);
        await Assert.That(parsed.DigestParameters).IsNull();
        await Assert.That(parsed.Digest).IsEquivalentTo(original.Digest);
    }

    [Test]
    public async Task TestSpcIndirectDataWithNullData()
    {
        byte[] digest = new byte[] { 1, 2, 3, 4 };
        SpcIndirectData original = new(
            DataType: new Oid("1.2.3.4"),
            Data: null,
            DigestAlgorithm: new Oid("2.16.840.1.101.3.4.2.1"),
            DigestParameters: null,
            Digest: digest);

        byte[] encoded = original.GetBytes();
        SpcIndirectData parsed = SpcIndirectData.Parse(encoded);

        await Assert.That(parsed.Data).IsNull();
    }

    [Test]
    public async Task TestSpcIndirectDataWithDigestParameters()
    {
        byte[] digest = new byte[] { 1, 2, 3, 4 };
        byte[] parameters = new byte[] { 0x30, 0x00 };
        SpcIndirectData original = new(
            DataType: new Oid("1.2.3.4"),
            Data: null,
            DigestAlgorithm: new Oid("2.16.840.1.101.3.4.2.1"),
            DigestParameters: parameters,
            Digest: digest);

        byte[] encoded = original.GetBytes();
        SpcIndirectData parsed = SpcIndirectData.Parse(encoded);

        await Assert.That(parsed.DigestParameters).IsEquivalentTo(parameters);
    }

    [Test]
    public async Task TestOidFromHashAlgorithmSHA1()
    {
        Oid result = SpcIndirectData.OidFromHashAlgorithm(HashAlgorithmName.SHA1);
        await Assert.That(result.Value).IsEqualTo("1.3.14.3.2.26");
    }

    [Test]
    public async Task TestOidFromHashAlgorithmSHA256()
    {
        Oid result = SpcIndirectData.OidFromHashAlgorithm(HashAlgorithmName.SHA256);
        await Assert.That(result.Value).IsEqualTo("2.16.840.1.101.3.4.2.1");
    }

    [Test]
    public async Task TestOidFromHashAlgorithmSHA384()
    {
        Oid result = SpcIndirectData.OidFromHashAlgorithm(HashAlgorithmName.SHA384);
        await Assert.That(result.Value).IsEqualTo("2.16.840.1.101.3.4.2.2");
    }

    [Test]
    public async Task TestOidFromHashAlgorithmSHA512()
    {
        Oid result = SpcIndirectData.OidFromHashAlgorithm(HashAlgorithmName.SHA512);
        await Assert.That(result.Value).IsEqualTo("2.16.840.1.101.3.4.2.3");
    }

    [Test]
    public void TestOidFromHashAlgorithmUnknown()
    {
        HashAlgorithmName unknown = new("MD5");
        Assert.Throws<NotImplementedException>(() => SpcIndirectData.OidFromHashAlgorithm(unknown));
    }

    [Test]
    public async Task TestSpcPeImageDataRoundTripDefaultFlags()
    {
        SpcString fileString = new(Unicode: "test.exe");
        SpcLink file = new(File: fileString);
        SpcPeImageData original = new(SpcPeImageFlags.IncludeResources, file);

        byte[] encoded = original.GetBytes();
        SpcPeImageData parsed = SpcPeImageData.Parse(encoded);

        await Assert.That(parsed.Flags).IsEqualTo(SpcPeImageFlags.IncludeResources);
        await Assert.That(parsed.File.File?.Unicode).IsEqualTo("test.exe");
    }

    [Test]
    public async Task TestSpcPeImageDataRoundTripDebugInfoFlags()
    {
        SpcString fileString = new(Unicode: "");
        SpcLink file = new(File: fileString);
        SpcPeImageData original = new(SpcPeImageFlags.IncludeDebugInfo, file);

        byte[] encoded = original.GetBytes();
        SpcPeImageData parsed = SpcPeImageData.Parse(encoded);

        await Assert.That(parsed.Flags).IsEqualTo(SpcPeImageFlags.IncludeDebugInfo);
    }

    [Test]
    public async Task TestSpcPeImageDataRoundTripImportAddressTableFlags()
    {
        SpcString fileString = new(Unicode: "");
        SpcLink file = new(File: fileString);
        SpcPeImageData original = new(SpcPeImageFlags.includeImportAddressTable, file);

        byte[] encoded = original.GetBytes();
        SpcPeImageData parsed = SpcPeImageData.Parse(encoded);

        await Assert.That(parsed.Flags).IsEqualTo(SpcPeImageFlags.includeImportAddressTable);
    }

    [Test]
    public async Task TestSpcSipInfoRoundTrip()
    {
        Guid guid = new("603bcc1f-4b59-4e08-b724-d2c6297ef351");
        SpcSipInfo original = new(0x10000, guid);

        byte[] encoded = original.GetBytes();
        SpcSipInfo parsed = SpcSipInfo.Parse(encoded);

        await Assert.That(parsed.Version).IsEqualTo(0x10000);
        await Assert.That(parsed.Identifier).IsEqualTo(guid);
    }

    [Test]
    public async Task TestSpcSpOpusInfoRoundTripBoth()
    {
        SpcString programName = new(Unicode: "Test Program");
        SpcLink moreInfo = new(Url: "https://example.com");
        SpcSpOpusInfo original = new(programName, moreInfo);

        byte[] encoded = original.GetBytes();
        SpcSpOpusInfo parsed = SpcSpOpusInfo.Parse(encoded);

        await Assert.That(parsed.ProgramName?.Unicode).IsEqualTo("Test Program");
        await Assert.That(parsed.MoreInfo?.Url).IsEqualTo("https://example.com");
    }

    [Test]
    public async Task TestSpcSpOpusInfoRoundTripProgramNameOnly()
    {
        SpcString programName = new(Unicode: "Test Program");
        SpcSpOpusInfo original = new(programName, null);

        byte[] encoded = original.GetBytes();
        SpcSpOpusInfo parsed = SpcSpOpusInfo.Parse(encoded);

        await Assert.That(parsed.ProgramName?.Unicode).IsEqualTo("Test Program");
        await Assert.That(parsed.MoreInfo).IsNull();
    }

    [Test]
    public async Task TestSpcSpOpusInfoRoundTripMoreInfoOnly()
    {
        SpcLink moreInfo = new(Url: "https://example.com");
        SpcSpOpusInfo original = new(null, moreInfo);

        byte[] encoded = original.GetBytes();
        SpcSpOpusInfo parsed = SpcSpOpusInfo.Parse(encoded);

        await Assert.That(parsed.ProgramName).IsNull();
        await Assert.That(parsed.MoreInfo?.Url).IsEqualTo("https://example.com");
    }

    [Test]
    public async Task TestSpcSpOpusInfoEmpty()
    {
        SpcSpOpusInfo original = new(null, null);

        byte[] encoded = original.GetBytes();
        SpcSpOpusInfo parsed = SpcSpOpusInfo.Parse(encoded);

        await Assert.That(parsed.ProgramName).IsNull();
        await Assert.That(parsed.MoreInfo).IsNull();
    }

    [Test]
    public async Task TestSpcStatementTypeRoundTrip()
    {
        Oid[] oids = [
            new Oid("1.3.6.1.4.1.311.2.1.21"),
            new Oid("1.3.6.1.4.1.311.2.1.22")
        ];
        SpcStatementType original = new(oids);

        byte[] encoded = original.GetBytes();
        SpcStatementType parsed = SpcStatementType.Parse(encoded);

        await Assert.That(parsed.Id.Length).IsEqualTo(2);
        await Assert.That(parsed.Id[0].Value).IsEqualTo("1.3.6.1.4.1.311.2.1.21");
        await Assert.That(parsed.Id[1].Value).IsEqualTo("1.3.6.1.4.1.311.2.1.22");
    }

    [Test]
    public async Task TestSpcLinkRoundTripUrl()
    {
        SpcLink original = new(Url: "https://example.com");

        byte[] encoded = original.GetBytes();
        SpcLink parsed = SpcLink.Parse(encoded);

        await Assert.That(parsed.Url).IsEqualTo("https://example.com");
        await Assert.That(parsed.Moniker).IsNull();
        await Assert.That(parsed.File).IsNull();
    }

    [Test]
    public async Task TestSpcSerializedObjectStandalone()
    {
        // Test SpcSerializedObject encoding/decoding separately
        // Explicitly covers: GetBytes line 520 (return), Parse lines 495-509 (all code in method)
        Guid classId = new("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
        byte[] data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        SpcSerializedObject original = new(classId, data);

        // Call GetBytes without tag (hits line 520 directly)
        byte[] encoded = original.GetBytes(null);

        // Call Parse without expectedTag (hits lines 498-509 without the tag parameter)
        SpcSerializedObject parsed = SpcSerializedObject.Parse(encoded, null);

        await Assert.That(parsed.ClassId).IsEqualTo(classId);
        await Assert.That(parsed.Data).IsEquivalentTo(data);
    }

    [Test]
    public async Task TestSpcSerializedObjectWithTag()
    {
        // Test SpcSerializedObject.Parse with expectedTag to cover Parse lines 495-509 and GetBytes lines 512-521
        Guid classId = new("12345678-1234-1234-1234-123456789ABC");
        byte[] data = new byte[] { 0xAA, 0xBB, 0xCC };
        SpcSerializedObject original = new(classId, data);

        // Test without tag (covers GetBytes with null tag)
        byte[] encodedNoTag = original.GetBytes();
        SpcSerializedObject parsedNoTag = SpcSerializedObject.Parse(encodedNoTag);
        await Assert.That(parsedNoTag.ClassId).IsEqualTo(classId);
        await Assert.That(parsedNoTag.Data).IsEquivalentTo(data);

        // Test with tag (covers GetBytes with tag parameter and Parse with expectedTag)
        Asn1Tag contextTag = new(TagClass.ContextSpecific, 5, true);
        byte[] encodedWithTag = original.GetBytes(contextTag);
        SpcSerializedObject parsedWithTag = SpcSerializedObject.Parse(encodedWithTag, contextTag);
        await Assert.That(parsedWithTag.ClassId).IsEqualTo(classId);
        await Assert.That(parsedWithTag.Data).IsEquivalentTo(data);
    }

    [Test]
    public async Task TestSpcLinkRoundTripFile()
    {
        SpcString fileString = new(Unicode: "test.exe");
        SpcLink original = new(File: fileString);

        byte[] encoded = original.GetBytes();
        SpcLink parsed = SpcLink.Parse(encoded);

        await Assert.That(parsed.Url).IsNull();
        await Assert.That(parsed.Moniker).IsNull();
        await Assert.That(parsed.File?.Unicode).IsEqualTo("test.exe");
    }

    [Test]
    public async Task TestSpcSerializedObjectRoundTrip()
    {
        Guid classId = Guid.NewGuid();
        byte[] data = new byte[] { 1, 2, 3, 4, 5 };
        SpcSerializedObject original = new(classId, data);

        byte[] encoded = original.GetBytes();
        SpcSerializedObject parsed = SpcSerializedObject.Parse(encoded);

        await Assert.That(parsed.ClassId).IsEqualTo(classId);
        await Assert.That(parsed.Data).IsEquivalentTo(data);
    }

    [Test]
    public async Task TestSpcStringRoundTripUnicode()
    {
        SpcString original = new(Unicode: "Test String");

        byte[] encoded = original.GetBytes();
        SpcString parsed = SpcString.Parse(encoded);

        await Assert.That(parsed.Unicode).IsEqualTo("Test String");
        await Assert.That(parsed.Ascii).IsNull();
    }

    [Test]
    public async Task TestSpcStringRoundTripAscii()
    {
        SpcString original = new(Ascii: "Test ASCII");

        byte[] encoded = original.GetBytes();
        SpcString parsed = SpcString.Parse(encoded);

        await Assert.That(parsed.Unicode).IsNull();
        await Assert.That(parsed.Ascii).IsEqualTo("Test ASCII");
    }

    [Test]
    public async Task TestSpcPeImageDataParseExplicitIncludeResourcesFlag()
    {
        // Test parsing flag value 0 explicitly (line 186)
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteBitString(new byte[] { 0 }); // IncludeResources explicitly
            Asn1Tag fileTag = new(TagClass.ContextSpecific, 0, true);
            using (writer.PushSequence(fileTag))
            {
                Asn1Tag fileChoiceTag = new(TagClass.ContextSpecific, 2, true);
                using (writer.PushSequence(fileChoiceTag))
                {
                    writer.WriteCharacterString(UniversalTagNumber.BMPString, "", new Asn1Tag(TagClass.ContextSpecific, 0));
                }
            }
        }
        byte[] encoded = writer.Encode();

        SpcPeImageData parsed = SpcPeImageData.Parse(encoded);
        await Assert.That(parsed.Flags).IsEqualTo(SpcPeImageFlags.IncludeResources);
    }

    [Test]
    public async Task TestSpcPeImageDataParseDebugInfoFlags()
    {
        // Manually construct ASN.1 to test parsing flag value 1 (line 187)
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteBitString(new byte[] { 1 }); // IncludeDebugInfo
            Asn1Tag fileTag = new(TagClass.ContextSpecific, 0, true);
            using (writer.PushSequence(fileTag))
            {
                Asn1Tag fileChoiceTag = new(TagClass.ContextSpecific, 2, true);
                using (writer.PushSequence(fileChoiceTag))
                {
                    writer.WriteCharacterString(UniversalTagNumber.BMPString, "", new Asn1Tag(TagClass.ContextSpecific, 0));
                }
            }
        }
        byte[] encoded = writer.Encode();

        SpcPeImageData parsed = SpcPeImageData.Parse(encoded);
        await Assert.That(parsed.Flags).IsEqualTo(SpcPeImageFlags.IncludeDebugInfo);
    }

    [Test]
    public async Task TestSpcPeImageDataParseImportTableFlags()
    {
        // Manually construct ASN.1 to test parsing flag value 2 (line 187)
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteBitString(new byte[] { 2 }); // includeImportAddressTable
            Asn1Tag fileTag = new(TagClass.ContextSpecific, 0, true);
            using (writer.PushSequence(fileTag))
            {
                Asn1Tag fileChoiceTag = new(TagClass.ContextSpecific, 2, true);
                using (writer.PushSequence(fileChoiceTag))
                {
                    writer.WriteCharacterString(UniversalTagNumber.BMPString, "", new Asn1Tag(TagClass.ContextSpecific, 0));
                }
            }
        }
        byte[] encoded = writer.Encode();

        SpcPeImageData parsed = SpcPeImageData.Parse(encoded);
        await Assert.That(parsed.Flags).IsEqualTo(SpcPeImageFlags.includeImportAddressTable);
    }

    [Test]
    public void TestSpcPeImageDataInvalidFlags()
    {
        // Construct ASN.1: SEQUENCE { BIT STRING with invalid flag value 3, ... }
        // This will trigger the "Unknown flags" exception on line 189
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteBitString(new byte[] { 3 }); // Invalid flag
            Asn1Tag fileTag = new(TagClass.ContextSpecific, 0, true);
            using (writer.PushSequence(fileTag))
            {
                Asn1Tag fileChoiceTag = new(TagClass.ContextSpecific, 2, true);
                using (writer.PushSequence(fileChoiceTag))
                {
                    writer.WriteCharacterString(UniversalTagNumber.BMPString, "", new Asn1Tag(TagClass.ContextSpecific, 0));
                }
            }
        }
        byte[] encoded = writer.Encode();

        Assert.Throws<NotImplementedException>(() => SpcPeImageData.Parse(encoded));
    }

    [Test]
    public async Task TestSpcPeImageDataParseWithoutContextWrapper()
    {
        // Test parsing when file is NOT wrapped in ContextSpecific[0] (covers branch 197 false path)
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteBitString(new byte[] { 0 }); // IncludeResources
            // Write SpcLink directly WITHOUT ContextSpecific[0] wrapper
            Asn1Tag fileChoiceTag = new(TagClass.ContextSpecific, 2, true);
            using (writer.PushSequence(fileChoiceTag))
            {
                writer.WriteCharacterString(UniversalTagNumber.BMPString, "file.exe", new Asn1Tag(TagClass.ContextSpecific, 0));
            }
        }
        byte[] encoded = writer.Encode();

        SpcPeImageData parsed = SpcPeImageData.Parse(encoded);
        await Assert.That(parsed.Flags).IsEqualTo(SpcPeImageFlags.IncludeResources);
        await Assert.That(parsed.File.File?.Unicode).IsEqualTo("file.exe");
    }

    [Test]
    public async Task TestSpcLinkParseUrlPath()
    {
        // Manually construct ASN.1 to test parsing URL (line 432)
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.IA5String, "https://test.com", new Asn1Tag(TagClass.ContextSpecific, 0));
        byte[] encoded = writer.Encode();

        SpcLink parsed = SpcLink.Parse(encoded);
        await Assert.That(parsed.Url).IsEqualTo("https://test.com");
        await Assert.That(parsed.Moniker).IsNull();
        await Assert.That(parsed.File).IsNull();
    }

    [Test]
    public async Task TestSpcLinkParseFilePath()
    {
        // Manually construct ASN.1 to test parsing File (line 440)
        AsnWriter writer = new(AsnEncodingRules.DER);
        Asn1Tag fileTag = new(TagClass.ContextSpecific, 2, true);
        using (writer.PushSequence(fileTag))
        {
            writer.WriteCharacterString(UniversalTagNumber.BMPString, "test.exe", new Asn1Tag(TagClass.ContextSpecific, 0));
        }
        byte[] encoded = writer.Encode();

        SpcLink parsed = SpcLink.Parse(encoded);
        await Assert.That(parsed.Url).IsNull();
        await Assert.That(parsed.Moniker).IsNull();
        await Assert.That(parsed.File?.Unicode).IsEqualTo("test.exe");
    }

    [Test]
    public void TestSpcLinkInvalidChoice()
    {
        // Construct ASN.1 with context tag 3 (invalid, only 0, 1, 2 are valid)
        // This will trigger lines 444-446 (else clause and exception throw)
        byte[] invalidAsn1 = new byte[] {
            0xA3, 0x02,           // Context tag 3 (invalid)
            0x04, 0x00            // OCTET STRING empty
        };

        Assert.Throws<NotImplementedException>(() => SpcLink.Parse(invalidAsn1));
    }

    [Test]
    public async Task TestSpcStringParseUnicodePath()
    {
        // Manually construct ASN.1 to explicitly test parsing Unicode string
        // Covers Parse lines 539-559 (entire method), specifically 545-548 for unicode branch
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.BMPString, "TestUnicode", new Asn1Tag(TagClass.ContextSpecific, 0));
        byte[] encoded = writer.Encode();

        SpcString parsed = SpcString.Parse(encoded);
        await Assert.That(parsed.Unicode).IsEqualTo("TestUnicode");
        await Assert.That(parsed.Ascii).IsNull();
    }

    [Test]
    public async Task TestSpcStringParseAsciiPath()
    {
        // Manually construct ASN.1 to test parsing ASCII string (line 550)
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.IA5String, "test", new Asn1Tag(TagClass.ContextSpecific, 1));
        byte[] encoded = writer.Encode();

        SpcString parsed = SpcString.Parse(encoded);
        await Assert.That(parsed.Ascii).IsEqualTo("test");
        await Assert.That(parsed.Unicode).IsNull();
    }

    [Test]
    public void TestSpcStringInvalidChoice()
    {
        // Construct ASN.1 with context tag 2 (invalid, only 0 and 1 are valid)
        // This will trigger lines 554-556 (else clause and exception throw)
        byte[] invalidAsn1 = new byte[] {
            0xA2, 0x04,           // Context tag 2 (invalid), length 4
            0x16, 0x02,           // IA5String, length 2
            0x41, 0x42            // "AB"
        };

        Assert.Throws<NotImplementedException>(() => SpcString.Parse(invalidAsn1));
    }

    [Test]
    public async Task TestSpcStringEmptyValues()
    {
        // Test with empty strings to ensure all parse paths work (covers Parse lines 539-559)
        SpcString unicode = new(Unicode: "");
        byte[] encodedUnicode = unicode.GetBytes();
        SpcString parsedUnicode = SpcString.Parse(encodedUnicode);
        await Assert.That(parsedUnicode.Unicode).IsEqualTo("");
        await Assert.That(parsedUnicode.Ascii).IsNull();

        // Test ASCII path (lines 550-552)
        SpcString ascii = new(Ascii: "");
        byte[] encodedAscii = ascii.GetBytes();
        SpcString parsedAscii = SpcString.Parse(encodedAscii);
        await Assert.That(parsedAscii.Ascii).IsEqualTo("");
        await Assert.That(parsedAscii.Unicode).IsNull();
    }

    [Test]
    public async Task TestSpcStringNonEmptyValues()
    {
        // Additional explicit test to ensure Parse is definitely covered
        SpcString unicode = new(Unicode: "TestValue");
        byte[] encoded = unicode.GetBytes();

        SpcString parsed = SpcString.Parse(encoded);
        await Assert.That(parsed.Unicode).IsEqualTo("TestValue");
        await Assert.That(parsed.Ascii).IsNull();

        // Test ASCII explicitly
        SpcString ascii = new(Ascii: "AsciiValue");
        byte[] encodedAscii = ascii.GetBytes();
        SpcString parsedAscii = SpcString.Parse(encodedAscii);
        await Assert.That(parsedAscii.Ascii).IsEqualTo("AsciiValue");
        await Assert.That(parsedAscii.Unicode).IsNull();
    }

    [Test]
    public async Task TestSpcLinkWithMonikerEncoding()
    {
        // Test the Moniker encoding path (lines 460-463)
        Guid classId = Guid.NewGuid();
        byte[] data = new byte[] { 1, 2, 3 };
        SpcSerializedObject moniker = new(classId, data);
        SpcLink link = new(Moniker: moniker);

        byte[] encoded = link.GetBytes();

        // Verify the encoded bytes start with context tag 1 (constructed)
        // 0xA1 = 10100001 = ContextSpecific (10) + Constructed (1) + tag 1 (00001)
        await Assert.That(encoded[0]).IsEqualTo((byte)0xA1);

        // Verify we can parse it back through SpcLink.Parse
        SpcLink parsed = SpcLink.Parse(encoded);
        await Assert.That(parsed.Url).IsNull();
        await Assert.That(parsed.File).IsNull();
        await Assert.That(parsed.Moniker).IsNotNull();
        await Assert.That(parsed.Moniker?.ClassId).IsEqualTo(classId);
        await Assert.That(parsed.Moniker?.Data).IsEquivalentTo(data);
    }

    [Test]
    public async Task TestSpcLinkParseMonikerPath()
    {
        // Test parsing SpcLink with Moniker (lines 434-438, specifically 436-437 for the Parse call)
        // For IMPLICIT tagging [1], the ContextSpecific tag replaces the SEQUENCE tag
        Guid classId = Guid.NewGuid();
        byte[] monikerData = new byte[] { 0xAA, 0xBB, 0xCC };

        // Build using SpcSerializedObject.GetBytes with the ContextSpecific[1] tag
        SpcSerializedObject moniker = new(classId, monikerData);
        Asn1Tag contextTag = new(TagClass.ContextSpecific, 1, true);
        byte[] encoded = moniker.GetBytes(contextTag);

        // Parse through SpcLink.Parse to hit lines 434-438
        SpcLink parsed = SpcLink.Parse(encoded);

        await Assert.That(parsed.Url).IsNull();
        await Assert.That(parsed.File).IsNull();
        await Assert.That(parsed.Moniker).IsNotNull();
        await Assert.That(parsed.Moniker?.ClassId).IsEqualTo(classId);
        await Assert.That(parsed.Moniker?.Data).IsEquivalentTo(monikerData);
    }

    [Test]
    public async Task TestSpcLinkAllReturnPaths()
    {
        // Ensure all three SpcLink choices return correctly (tests line 449 return statement)

        // URL path
        SpcLink urlLink = new(Url: "http://example.com");
        byte[] urlEncoded = urlLink.GetBytes();
        SpcLink urlParsed = SpcLink.Parse(urlEncoded);
        await Assert.That(urlParsed.Url).IsEqualTo("http://example.com");

        // Moniker path
        Guid guid = Guid.NewGuid();
        SpcSerializedObject moniker = new(guid, new byte[] { 1, 2 });
        SpcLink monikerLink = new(Moniker: moniker);
        byte[] monikerEncoded = monikerLink.GetBytes();
        SpcLink monikerParsed = SpcLink.Parse(monikerEncoded);
        await Assert.That(monikerParsed.Moniker).IsNotNull();

        // File path
        SpcLink fileLink = new(File: new SpcString(Unicode: "test"));
        byte[] fileEncoded = fileLink.GetBytes();
        SpcLink fileParsed = SpcLink.Parse(fileEncoded);
        await Assert.That(fileParsed.File).IsNotNull();
    }
}

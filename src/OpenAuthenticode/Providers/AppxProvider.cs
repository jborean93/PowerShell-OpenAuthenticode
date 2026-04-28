using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace OpenAuthenticode.Providers;

/// <summary>
/// Authenticode provider for APPX/MSIX Windows App Packages.
/// </summary>
/// <remarks>
/// APPX/MSIX packages are ZIP-based archives containing application files,
/// manifests, and metadata. The authenticode signature is stored in
/// AppxSignature.p7x within the package. This provider hashes the required
/// XML files (AppxBlockMap.xml, [Content_Types].xml, and optionally
/// AppxMetadata/CodeIntegrity.cat) to generate the signature content.
/// </remarks>
internal class AppxProvider : AuthenticodeProviderBase
{
    private readonly bool _isBundle;

    // Cached XML content for hashing
    private readonly byte[] _blockMapXml;
    private readonly byte[] _contentTypesXml;
    private readonly byte[]? _codeIntegrityCat;

    public override AuthenticodeProvider Provider => AuthenticodeProvider.Appx;

    internal static string[] FileExtensions => [ ".appx", ".msix", ".appxbundle", ".msixbundle" ];

    private AppxProvider(
        Stream stream,
        bool leaveOpen,
        byte[] signature,
        bool isBundle,
        byte[] blockMapXml,
        byte[] contentTypesXml,
        byte[]? codeIntegrityCat)
        : base(stream, leaveOpen)
    {
        Signature = signature;

        _isBundle = isBundle;
        _blockMapXml = blockMapXml;
        _contentTypesXml = contentTypesXml;
        _codeIntegrityCat = codeIntegrityCat;
    }

    /// <summary>
    /// Creates an AppxProvider instance from APPX/MSIX package stream.
    /// </summary>
    /// <param name="stream">The package stream (ZIP archive)</param>
    /// <param name="leaveOpen">Whether to leave the stream open after disposal</param>
    /// <returns>An initialized AppxProvider instance</returns>
    /// <exception cref="ArgumentException">Thrown if the package is invalid</exception>
    /// <exception cref="InvalidDataException">Thrown if the ZIP structure is corrupted</exception>
    public static AppxProvider Create(Stream stream, bool leaveOpen)
    {
        // Stream validation handled by ProviderFactory
        long originalPosition = stream.Position;
        stream.Position = 0;

        using ZipArchive archive = new(stream, ZipArchiveMode.Read, leaveOpen: true);

        // Detect bundle vs package format
        // Bundle manifests can be at root or in AppxMetadata directory
        bool isBundle = archive.GetEntry("AppxBundleManifest.xml") != null ||
                        archive.GetEntry("AppxMetadata/AppxBundleManifest.xml") != null;

        if (!isBundle && archive.GetEntry("AppxManifest.xml") == null)
        {
            throw new ArgumentException("Invalid APPX/MSIX package: No manifest found (expected AppxManifest.xml, AppxBundleManifest.xml, or AppxMetadata/AppxBundleManifest.xml)");
        }

        // These three files are needed for the signature digest generation.
        // CodeIntegrity.cat is optional and may not be present.
        byte[] blockMapXml = ReadEntry(archive, "AppxBlockMap.xml", required: true)!;
        byte[] contentTypesXml = ReadEntry(archive, "[Content_Types].xml", required: true)!;
        byte[]? codeIntegrityCat = ReadEntry(archive, "AppxMetadata/CodeIntegrity.cat", required: false);

        // Read existing signature if present
        byte[]? signature = ReadEntry(archive, "AppxSignature.p7x", required: false);
        if (signature is not null)
        {
            ReadOnlySpan<byte> sigSpan = signature;
            if (sigSpan.Length < 4 || !sigSpan[..4].SequenceEqual("PKCX"u8))
            {
                throw new ArgumentException("Invalid signature format: Expected P7X file with 'PKCX' magic header");
            }

            signature = sigSpan[4..].ToArray(); // Strip the 4-byte header
        }

        stream.Position = originalPosition;

        return new AppxProvider(stream, leaveOpen, signature ?? [], isBundle, blockMapXml, contentTypesXml, codeIntegrityCat);
    }

    /// <summary>
    /// Generates the hash data for signing the APPX/MSIX package.
    /// </summary>
    /// <param name="digestAlgorithm">The hash algorithm to use</param>
    /// <returns>The SpcIndirectData structure containing the hashes</returns>
    /// <exception cref="CryptographicException">Thrown if an unsupported hash algorithm is specified</exception>
    public SpcIndirectData HashData(Oid digestAlgorithm)
    {
        HashAlgorithmName hashAlgoName = HashAlgorithmName.FromOid(digestAlgorithm.Value ?? "");

        // Hash the XML files
        byte[] contentTypesHash = HashBytes(_contentTypesXml, hashAlgoName);
        byte[] blockMapHash = HashBytes(_blockMapXml, hashAlgoName);
        byte[]? codeIntegrityHash = _codeIntegrityCat != null ? HashBytes(_codeIntegrityCat, hashAlgoName) : null;

        // Compute ZIP structure hashes
        byte[] axpcHash = ComputeAxpcHash(hashAlgoName);
        byte[] axcdHash = ComputeAxcdHash(hashAlgoName);

        // Build the APPX digest blob in the format:
        // [8-byte header "APPXAXPC"][N-byte AXPC hash]
        // [4-byte "AXCD"][N-byte AXCD hash]
        // [4-byte "AXCT"][N-byte AXCT hash]
        // [4-byte "AXBM"][N-byte AXBM hash]
        // [4-byte "AXCI"][N-byte AXCI hash] (if code integrity present)
        using MemoryStream digestBlob = new();
        using BinaryWriter writer = new(digestBlob);

        writer.Write("APPXAXPC"u8);
        writer.Write(axpcHash);
        writer.Write("AXCD"u8);
        writer.Write(axcdHash);
        writer.Write("AXCT"u8);
        writer.Write(contentTypesHash);
        writer.Write("AXBM"u8);
        writer.Write(blockMapHash);

        if (codeIntegrityHash != null)
        {
            writer.Write("AXCI"u8);
            writer.Write(codeIntegrityHash);
        }

        byte[] digestBlobBytes = digestBlob.ToArray();

        // Create SpcSipInfo with appropriate GUID
        // Package GUID: {0ac5df4b-ce07-4de2-b76e-23c839a09fd1}
        // Bundle GUID:  {0f5f58b3-aade-4b9a-a434-95742d92eceb}
        Guid sipGuid = _isBundle
            ? new Guid("0f5f58b3-aade-4b9a-a434-95742d92eceb")
            : new Guid("0ac5df4b-ce07-4de2-b76e-23c839a09fd1");
        SpcSipInfo sipInfo = new(Version: 0x01010000, Identifier: sipGuid);
        byte[] sipInfoBytes = sipInfo.GetBytes();

        return new SpcIndirectData(
            DataType: SpcSipInfo.OID,
            Data: sipInfoBytes,
            DigestAlgorithm: digestAlgorithm,
            DigestParameters: null,
            Digest: digestBlobBytes);
    }

    /// <summary>
    /// Gets the attributes to include in the signature.
    /// </summary>
    /// <returns>The encoded attributes</returns>
    public AsnEncodedData[] GetAttributesToSign()
    {
        // FUTURE: Find a way for the user to specify these values as params
        // but keep empty for now.
        SpcSpOpusInfo opusInfo = new(new SpcString(Unicode: ""), new SpcLink(Url: ""));
        SpcStatementType statementType = new([
            new Oid("1.3.6.1.4.1.311.2.1.21", "SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID"),
        ]);

        return [
            new AsnEncodedData(SpcSpOpusInfo.OID, opusInfo.GetBytes()),
            new AsnEncodedData(SpcStatementType.OID, statementType.GetBytes())
        ];
    }

    /// <summary>
    /// Saves the package with the updated signature to the stream.
    /// </summary>
    /// <exception cref="IOException">Thrown if the stream cannot be written</exception>
    public override void Save()
    {
        // Stream validation happens in ProviderFactory or cmdlet
        // Create a temporary memory stream to build the updated ZIP
        using MemoryStream tempStream = new();

        // Copy current stream contents to temp
        Stream.Position = 0;
        Stream.CopyTo(tempStream);
        tempStream.Position = 0;

        // Update the ZIP archive in the temp stream
        using (ZipArchive archive = new(tempStream, ZipArchiveMode.Update, leaveOpen: true))
        {
            // Remove existing signature
            archive.GetEntry("AppxSignature.p7x")?.Delete();

            // Add new signature if present
            if (Signature.Length > 0)
            {
                ZipArchiveEntry sigEntry = archive.CreateEntry("AppxSignature.p7x", CompressionLevel.Optimal);
                using Stream entryStream = sigEntry.Open();

                entryStream.Write("PKCX"u8);
                entryStream.Write(Signature);
            }
        }

        // Write the updated ZIP back to the original stream
        Stream.SetLength(0);
        Stream.Position = 0;
        tempStream.Position = 0;
        tempStream.CopyTo(Stream);
        Stream.Flush();
    }

    /// <summary>
    /// Reads an entry from the ZIP archive.
    /// </summary>
    /// <param name="archive">The ZIP archive</param>
    /// <param name="name">The entry name</param>
    /// <param name="required">Whether the entry is required</param>
    /// <returns>The entry data, or null if not required and not found</returns>
    /// <exception cref="ArgumentException">Thrown if a required entry is not found</exception>
    private static byte[]? ReadEntry(ZipArchive archive, string name, bool required)
    {
        ZipArchiveEntry? entry = archive.GetEntry(name);
        if (entry == null)
        {
            if (required)
            {
                throw new ArgumentException($"Invalid APPX/MSIX package: Required file '{name}' not found");
            }
            return null;
        }

        // Limit entry size to prevent ZIP bomb attacks
        const long MAX_ENTRY_SIZE = 100 * 1024 * 1024; // 100MB
        if (entry.Length > MAX_ENTRY_SIZE)
        {
            throw new ArgumentException($"Entry '{name}' exceeds maximum size of {MAX_ENTRY_SIZE} bytes");
        }

        using Stream stream = entry.Open();
        using MemoryStream ms = new((int)entry.Length);
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Computes the hash of a byte array using the specified algorithm.
    /// </summary>
    /// <param name="data">The data to hash</param>
    /// <param name="algorithm">The hash algorithm</param>
    /// <returns>The computed hash</returns>
    private static byte[] HashBytes(byte[] data, HashAlgorithmName algorithm)
    {
        using IncrementalHash hasher = IncrementalHash.CreateHash(algorithm);
        hasher.AppendData(data);
        return hasher.GetHashAndReset();
    }

    /// <summary>
    /// Computes the AXPC hash (ZIP local file headers).
    /// </summary>
    /// <param name="algorithm">The hash algorithm</param>
    /// <returns>The hash of all file records up to central directory</returns>
    private byte[] ComputeAxpcHash(HashAlgorithmName algorithm)
    {
        using IncrementalHash hasher = IncrementalHash.CreateHash(algorithm);

        // Read the stream into a byte array for processing
        Stream.Position = 0;
        byte[] zipData = new byte[Stream.Length];
        Stream.Read(zipData, 0, zipData.Length);

        // Find the central directory offset
        long centralDirOffset = ZipStructure.FindCentralDirectoryOffset(zipData);

        // Find the AppxSignature.p7x record offset and size (if it exists)
        long sigOffset = -1;
        long sigRecordSize = 0;

        var (cdOffset, _, localHeaderOffset) = ZipStructure.FindCentralDirectoryEntry(
            zipData,
            "AppxSignature.p7x"u8);

        if (cdOffset >= 0)
        {
            sigOffset = localHeaderOffset;

            // Calculate signature record size: header + data + data descriptor
            using MemoryStream ms = new(zipData);
            using ZipArchive archive = new(ms, ZipArchiveMode.Read, leaveOpen: true);
            ZipArchiveEntry? sigEntry = archive.GetEntry("AppxSignature.p7x");
            if (sigEntry != null)
            {
                ushort fileNameLen = BinaryPrimitives.ReadUInt16LittleEndian(zipData.Slice((int)(sigOffset + 26), 2));
                ushort extraLen = BinaryPrimitives.ReadUInt16LittleEndian(zipData.Slice((int)(sigOffset + 28), 2));
                int headerSize = 30 + fileNameLen + extraLen;
                const int DATA_DESCRIPTOR_SIZE = 24; // ZIP64 format
                sigRecordSize = headerSize + sigEntry.CompressedLength + DATA_DESCRIPTOR_SIZE;
            }
        }

        // Hash file records excluding signature
        if (sigOffset < 0)
        {
            // No signature - hash everything up to central directory
            hasher.AppendData(zipData[..(int)centralDirOffset]);
        }
        else if (sigOffset == 0)
        {
            // Signature at start - hash after it
            hasher.AppendData(zipData[(int)sigRecordSize..(int)centralDirOffset]);
        }
        else
        {
            // Hash before signature
            hasher.AppendData(zipData[..(int)sigOffset]);

            // Hash after signature
            long afterSigOffset = sigOffset + sigRecordSize;
            if (afterSigOffset < centralDirOffset)
            {
                hasher.AppendData(zipData[(int)afterSigOffset..(int)centralDirOffset]);
            }
        }

        return hasher.GetHashAndReset();
    }

    /// <summary>
    /// Computes the AXCD hash (ZIP central directory structures).
    /// </summary>
    /// <remarks>
    /// The AXCD hash includes:
    /// 1. Central directory entries (excluding AppxSignature.p7x)
    /// 2. ZIP64 EOCD with adjusted entry count, CD size, and CD offset
    /// 3. ZIP64 EOCD locator with adjusted EOCD offset
    /// 4. Regular EOCD with disk numbers zeroed
    /// </remarks>
    /// <param name="algorithm">The hash algorithm</param>
    /// <returns>The hash of the central directory structures</returns>
    private byte[] ComputeAxcdHash(HashAlgorithmName algorithm)
    {
        using IncrementalHash hasher = IncrementalHash.CreateHash(algorithm);

        // Read the stream into a byte array for processing
        Stream.Position = 0;
        byte[] zipDataArray = new byte[Stream.Length];
        Stream.Read(zipDataArray, 0, zipDataArray.Length);
        ReadOnlySpan<byte> zipData = zipDataArray;

        // Find the AppxSignature.p7x entry in the central directory
        var (signatureCdOffset, signatureCdSize, signatureLocalHeaderOffset) = ZipStructure.FindCentralDirectoryEntry(
            zipData,
            "AppxSignature.p7x"u8);

        long cdOffset = ZipStructure.FindCentralDirectoryOffset(zipData);
        long cdSize = ZipStructure.FindCentralDirectorySize(zipData);
        long totalEntries = ZipStructure.FindTotalEntries(zipData);
        long cdEnd = cdOffset + cdSize;

        // Step 1: Hash central directory entries (excluding signature entry)
        if (signatureCdOffset >= 0)
        {
            // Hash before signature entry
            if (signatureCdOffset > cdOffset)
            {
                hasher.AppendData(zipData[(int)cdOffset..(int)signatureCdOffset]);
            }

            // Hash after signature entry
            long afterSigEntry = signatureCdOffset + signatureCdSize;
            if (afterSigEntry < cdEnd)
            {
                hasher.AppendData(zipData[(int)afterSigEntry..(int)cdEnd]);
            }
        }
        else
        {
            // No signature entry found, hash entire central directory
            hasher.AppendData(zipData[(int)cdOffset..(int)cdEnd]);
        }

        // Calculate adjusted values for EOCD structures
        long adjustedEntryCount = signatureCdOffset >= 0 ? totalEntries - 1 : totalEntries;
        long adjustedCdSize = signatureCdOffset >= 0 ? cdSize - signatureCdSize : cdSize;
        long calculatedCdOffset = signatureCdOffset >= 0 ? signatureLocalHeaderOffset : cdOffset;

        // Find EOCD position
        long eocdPos = FindEocdPosition(zipData);
        uint cdSize32 = BinaryPrimitives.ReadUInt32LittleEndian(zipData.Slice((int)(eocdPos + 12), 4));

        // Step 2 & 3: Hash ZIP64 structures if present
        if (cdSize32 == 0xFFFFFFFF)
        {
            long zip64EocdOffset = FindZip64EocdOffset(zipData, eocdPos);
            const int ZIP64_EOCD_MIN_SIZE = 56;
            const int ZIP64_EOCD_LOCATOR_SIZE = 20;

            // Hash ZIP64 EOCD with adjusted values
            Span<byte> adjustedZip64Eocd = stackalloc byte[ZIP64_EOCD_MIN_SIZE];
            zipData.Slice((int)zip64EocdOffset, ZIP64_EOCD_MIN_SIZE).CopyTo(adjustedZip64Eocd);

            BinaryPrimitives.WriteInt64LittleEndian(adjustedZip64Eocd[24..], adjustedEntryCount);
            BinaryPrimitives.WriteInt64LittleEndian(adjustedZip64Eocd[32..], adjustedEntryCount);
            BinaryPrimitives.WriteInt64LittleEndian(adjustedZip64Eocd[40..], adjustedCdSize);
            BinaryPrimitives.WriteInt64LittleEndian(adjustedZip64Eocd[48..], calculatedCdOffset);

            hasher.AppendData(adjustedZip64Eocd);

            // Hash ZIP64 EOCD locator with adjusted offset
            Span<byte> adjustedZip64Locator = stackalloc byte[ZIP64_EOCD_LOCATOR_SIZE];
            zipData.Slice((int)(eocdPos - ZIP64_EOCD_LOCATOR_SIZE), ZIP64_EOCD_LOCATOR_SIZE)
                .CopyTo(adjustedZip64Locator);

            long adjustedEocdOffset = calculatedCdOffset + adjustedCdSize;
            BinaryPrimitives.WriteInt64LittleEndian(adjustedZip64Locator[8..], adjustedEocdOffset);

            hasher.AppendData(adjustedZip64Locator);
        }

        // Step 4: Hash regular EOCD with disk numbers zeroed
        ushort commentLen = BinaryPrimitives.ReadUInt16LittleEndian(zipData.Slice((int)(eocdPos + 20), 2));
        const int EOCD_MIN_SIZE = 22;
        int eocdSize = EOCD_MIN_SIZE + commentLen;

        Span<byte> adjustedEocd = stackalloc byte[eocdSize];
        zipData.Slice((int)eocdPos, eocdSize).CopyTo(adjustedEocd);

        // Zero disk numbers
        BinaryPrimitives.WriteUInt16LittleEndian(adjustedEocd[4..], 0);
        BinaryPrimitives.WriteUInt16LittleEndian(adjustedEocd[6..], 0);

        hasher.AppendData(adjustedEocd);

        return hasher.GetHashAndReset();
    }

    /// <summary>
    /// Finds the End of Central Directory position in the ZIP archive.
    /// </summary>
    private static long FindEocdPosition(ReadOnlySpan<byte> zipData)
    {
        const uint EOCD_SIGNATURE = 0x06054b50;
        const int EOCD_MIN_SIZE = 22;

        // Search backwards from end of file for EOCD signature
        for (long i = zipData.Length - EOCD_MIN_SIZE; i >= 0; i--)
        {
            uint sig = BinaryPrimitives.ReadUInt32LittleEndian(zipData.Slice((int)i, 4));
            if (sig == EOCD_SIGNATURE)
                return i;
        }

        throw new InvalidDataException("Could not find End of Central Directory record in ZIP");
    }

    /// <summary>
    /// Finds the ZIP64 End of Central Directory offset.
    /// </summary>
    private static long FindZip64EocdOffset(ReadOnlySpan<byte> zipData, long eocdPos)
    {
        const uint ZIP64_EOCD_LOCATOR_SIGNATURE = 0x07064b50;
        const uint ZIP64_EOCD_SIGNATURE = 0x06064b50;
        const int ZIP64_EOCD_LOCATOR_SIZE = 20;

        long locatorPos = eocdPos - ZIP64_EOCD_LOCATOR_SIZE;
        if (locatorPos < 0)
            throw new InvalidDataException("ZIP64 locator position invalid");

        uint locatorSig = BinaryPrimitives.ReadUInt32LittleEndian(zipData.Slice((int)locatorPos, 4));
        if (locatorSig != ZIP64_EOCD_LOCATOR_SIGNATURE)
            throw new InvalidDataException("ZIP64 End of Central Directory Locator not found");

        long zip64EocdOffset = BinaryPrimitives.ReadInt64LittleEndian(zipData.Slice((int)(locatorPos + 8), 8));

        uint zip64EocdSig = BinaryPrimitives.ReadUInt32LittleEndian(zipData.Slice((int)zip64EocdOffset, 4));
        if (zip64EocdSig != ZIP64_EOCD_SIGNATURE)
            throw new InvalidDataException("ZIP64 End of Central Directory signature invalid");

        return zip64EocdOffset;
    }

}

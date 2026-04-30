using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace OpenAuthenticode.Providers;

/// <summary>
/// Base provider for APPX/MSIX Windows App Packages and Bundles.
/// </summary>
/// <remarks>
/// APPX/MSIX packages are ZIP-based archives containing application files,
/// manifests, and metadata. The authenticode signature is stored in
/// AppxSignature.p7x within the package. This provider hashes the required
/// XML files (AppxBlockMap.xml, [Content_Types].xml, and optionally
/// AppxMetadata/CodeIntegrity.cat) to generate the signature content.
/// </remarks>
internal abstract class AppxProviderBase : AuthenticodeProviderBase
{
    private readonly ZipStructure _zipStructure;
    private readonly ZipEntry? _signatureEntry;

    /// <summary>
    /// Gets the SIP GUID for this provider type (Package or Bundle).
    /// </summary>
    protected abstract Guid SipGuid { get; }

    protected AppxProviderBase(
        Stream stream,
        bool leaveOpen,
        byte[] signature,
        ZipStructure zipStructure,
        ZipEntry? signatureEntry)
        : base(stream, leaveOpen)
    {
        Signature = signature;
        _zipStructure = zipStructure;
        _signatureEntry = signatureEntry;
    }

    /// <summary>
    /// Creates a provider instance from APPX/MSIX stream (common logic).
    /// </summary>
    protected static (byte[] signature, ZipStructure zipStructure, ZipEntry? signatureEntry) CreateCommon(
        Stream stream)
    {
        ZipStructure zipStructure = ZipStructure.Create(stream);
        ZipEntry? signatureEntry = null;

        stream.Position = 0;
        using ZipArchive archive = new(stream, ZipArchiveMode.Read, leaveOpen: true);

        byte[] signature = [];
        if (zipStructure.TryGetEntryByName(stream, "AppxSignature.p7x", out ZipEntry tempSigEntry))
        {
            signatureEntry = tempSigEntry;


            ZipArchiveEntry? entry = archive.GetEntry("AppxSignature.p7x");
            Debug.Assert(entry != null, "Signature entry should exist since TryGetEntryByName succeeded");

            using Stream entryStream = entry.Open();

            // We need to validate the signature starts with PKCX. By reading
            // it we also strip the prefix on the final CopyTo array dest.
            Span<byte> headerBuffer = stackalloc byte[4];
            int bytesRead = entryStream.Read(headerBuffer);
            if (bytesRead != 4 || !headerBuffer.SequenceEqual("PKCX"u8))
            {
                throw new ArgumentException("Invalid signature format: Expected P7X file with 'PKCX' magic header");
            }

            using MemoryStream ms = new((int)entry.Length - 4);
            entryStream.CopyTo(ms);
            signature = ms.GetBuffer();
        }

        return (signature, zipStructure, signatureEntry);
    }

    /// <summary>
    /// Generates the hash data for signing the APPX/MSIX package.
    /// </summary>
    /// <param name="digestAlgorithm">The hash algorithm to use</param>
    /// <returns>The SpcIndirectData structure containing the hashes</returns>
    /// <exception cref="CryptographicException">Thrown if an unsupported hash algorithm is specified</exception>
    public override SpcIndirectData HashData(Oid digestAlgorithm)
    {
        HashAlgorithmName hashAlgoName = HashAlgorithmName.FromOid(digestAlgorithm.Value ?? "");
        using IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgoName);

        // Stream XML files from ZIP and hash on demand
        Stream.Position = 0;
        using ZipArchive archive = new(Stream, ZipArchiveMode.Read, leaveOpen: true);
        ZipArchiveEntry? axciEntry = archive.GetEntry("AppxMetadata/CodeIntegrity.cat");

        int digestCount = axciEntry != null ? 5 : 4; // AXPC, AXCD, AXCT, AXBM, and optionally AXCI
        int digestLength = 4 + (hasher.HashLengthInBytes + 4) * digestCount;
        byte[] digest = new byte[digestLength];
        Span<byte> digestSpan = digest;

        // Build the APPX digest blob in the format:
        // [8-byte header "APPXAXPC"][N-byte AXPC hash]
        // [4-byte "AXCD"][N-byte AXCD hash]
        // [4-byte "AXCT"][N-byte AXCT hash]
        // [4-byte "AXBM"][N-byte AXBM hash]
        // [4-byte "AXCI"][N-byte AXCI hash] (if code integrity present)
        "APPX"u8.CopyTo(digest);
        ComputeAxpcHash(hasher, digestSpan[4..]);
        ComputeAxcdHash(hasher, digestSpan[(8 + hasher.HashLengthInBytes)..]);
        ComputeEntryHash(archive, "[Content_Types].xml", hasher, "AXCT"u8, digestSpan, 2);
        ComputeEntryHash(archive, "AppxBlockMap.xml", hasher, "AXBM"u8, digestSpan, 3);
        if (axciEntry != null)
        {
            ComputeEntryHash(
                archive,
                "AppxMetadata/CodeIntegrity.cat",
                hasher,
                "AXCI"u8,
                digestSpan,
                4,
                entry: axciEntry);
        }

        // Create SpcSipInfo with SIP GUID from derived class
        SpcSipInfo sipInfo = new(Version: 0x01010000, Identifier: SipGuid);
        byte[] sipInfoBytes = sipInfo.GetBytes();

        return new SpcIndirectData(
            DataType: SpcSipInfo.OID,
            Data: sipInfoBytes,
            DigestAlgorithm: digestAlgorithm,
            DigestParameters: null,
            Digest: digest);
    }

    /// <summary>
    /// Gets the attributes to include in the signature.
    /// </summary>
    /// <returns>The encoded attributes</returns>
    public override AsnEncodedData[] GetAttributesToSign()
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
    /// Hashes a ZIP entry by name.
    /// </summary>
    /// <param name="archive">The ZIP archive</param>
    /// <param name="entryName">The entry name to hash</param>
    /// <param name="hasher">The hashing object</param>
    /// <param name="header">The 4-byte header to prefix the hash with</param>
    /// <param name="dest">The destination buffer to write the header and hash to</param>
    /// <param name="hashEntry">The index of the hash entry (0-based)</param>
    /// <param name="entry">The ZIP archive entry to hash, otherwise the entry will be looked up by name</param>
    private static void ComputeEntryHash(
        ZipArchive archive,
        string entryName,
        IncrementalHash hasher,
        ReadOnlySpan<byte> header,
        Span<byte> dest,
        int hashEntry,
        ZipArchiveEntry? entry = null)
    {
        int hashOffset = 4 + (hasher.HashLengthInBytes + 4) * hashEntry;
        Debug.Assert(hashOffset + hasher.HashLengthInBytes <= dest.Length, "Destination buffer is too small for hash output");
        Debug.Assert(header.Length == 4, "Header must be exactly 4 bytes");

        if (entry is null)
        {
            entry = archive.GetEntry(entryName)
                ?? throw new ArgumentException($"Invalid APPX/MSIX package: Required file '{entryName}' not found");
        }

        using Stream entryStream = entry.Open();
        byte[] rentedBuffer = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            int bytesRead;
            while ((bytesRead = entryStream.Read(rentedBuffer, 0, 8192)) > 0)
            {
                hasher.AppendData(rentedBuffer, 0, bytesRead);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentedBuffer);
        }

        header.CopyTo(dest.Slice(hashOffset, 4));
        hasher.GetHashAndReset(dest.Slice(hashOffset + 4, hasher.HashLengthInBytes));
    }

    /// <summary>
    /// Computes the AXPC hash (ZIP local file headers).
    /// </summary>
    /// <param name="hasher">The hashing object</param>
    /// <param name="dest">The destination buffer for the hash output</param>
    private void ComputeAxpcHash(IncrementalHash hasher, Span<byte> dest)
    {
        Debug.Assert(dest.Length >= 4 + hasher.HashLengthInBytes, "Destination buffer is too small for AXPC hash output");

        long cdOffset = _zipStructure.CentralDirectoryOffset;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            Span<byte> bufferSpan = buffer.AsSpan();

            if (!_signatureEntry.HasValue)
            {
                // No signature - hash everything up to central directory
                HashStreamRange(hasher, 0, cdOffset, bufferSpan);
            }
            else
            {
                // If the AppxSignature.p7x entry is present we need to exclude
                // the local file header, compressed data, and descriptor from
                // the hash.
                long sigOffset = _signatureEntry.Value.LocalHeaderOffset;
                long sigRecordSize = _signatureEntry.Value.LocalHeaderLength +
                    _signatureEntry.Value.CompressedLength +
                    _signatureEntry.Value.DescriptorLength;

                HashStreamRangeWithExclusion(hasher, 0, cdOffset, sigOffset, sigRecordSize, bufferSpan);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        "AXPC"u8.CopyTo(dest);
        hasher.GetHashAndReset(dest[4..]);
    }

    /// <summary>
    /// Computes the AXCD hash (ZIP central directory structures).
    /// </summary>
    /// <remarks>
    /// The AXCD hash includes:
    /// 1. Central directory entries (excluding AppxSignature.p7x if present)
    /// 2. ZIP64 EOCD with zeroed disk numbers and adjusted entry count, CD size, and CD offset (if ZIP64)
    /// 3. ZIP64 EOCD locator with adjusted EOCD offset (if ZIP64)
    /// 4. Regular EOCD with:
    ///    - Disk numbers zeroed (always)
    ///    - Adjusted entry count, CD size, and CD offset (non-ZIP64 only)
    ///    - For ZIP64 packages, these fields contain placeholder values (0xFFFF/0xFFFFFFFF)
    ///      that point to the ZIP64 EOCD and don't need adjustment
    /// </remarks>
    /// <param name="hasher">The hashing object</param>
    /// <param name="dest">The destination buffer for the hash output</param>
    private void ComputeAxcdHash(
        IncrementalHash hasher,
        Span<byte> dest)
    {
        Debug.Assert(dest.Length >= 4 + hasher.HashLengthInBytes, "Destination buffer is too small for AXCD hash output");

        long cdOffset = _zipStructure.CentralDirectoryOffset;
        long cdSize = _zipStructure.CentralDirectoryLength;
        long totalEntries = _zipStructure.CentralDirectoryCount;

        byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            Span<byte> bufferSpan = buffer.AsSpan();

            // Step 1: Hash central directory entries excluding signature
            // entry if present.
            if (_signatureEntry.HasValue)
            {
                long signatureCdOffset = _signatureEntry.Value.CentralDirectoryOffset;
                long signatureCdSize = _signatureEntry.Value.CentralDirectoryLength;

                // Hash CD while excluding the signature's central directory record
                HashStreamRangeWithExclusion(
                    hasher,
                    cdOffset,
                    cdSize,
                    signatureCdOffset,
                    signatureCdSize,
                    bufferSpan);

                // Calculate adjusted values for EOCD structures with the signature entry excluded.
                // - CD offset: signature's local header offset as the CD would have started here.
                // - CD size: smaller (exclude signature's CD record)
                // - Entry count: one less (exclude signature entry)
                cdOffset = _signatureEntry.Value.LocalHeaderOffset;
                cdSize -= signatureCdSize;
                totalEntries -= 1;
            }
            else
            {
                HashStreamRange(hasher, cdOffset, cdSize, bufferSpan);
            }

            // Step 2 & 3: Hash ZIP64 structures if present
            if (_zipStructure.Zip64.HasValue)
            {
                Zip64Eocd zip64 = _zipStructure.Zip64.Value;

                // Step 2: Read and adjust ZIP64 EOCD (including extensible data if present)
                // FIXME: Test with extensible data set - verify this logic is correct
                // ZIP64 EOCD = 56 byte fixed header + optional extensible data sector
                // Zero disk numbers and adjust entry counts, CD size, and CD offset in the fixed header
                Stream.Position = zip64.Offset;
                Stream.Read(bufferSpan[..Zip64Eocd.MinLength]);

                Span<byte> eocd64 = bufferSpan[..Zip64Eocd.MinLength];
                BinaryPrimitives.WriteUInt32LittleEndian(eocd64[16..], 0);           // Zero disk number
                BinaryPrimitives.WriteUInt32LittleEndian(eocd64[20..], 0);           // Zero disk number with CD
                BinaryPrimitives.WriteInt64LittleEndian(eocd64[24..], totalEntries); // Entries on disk
                BinaryPrimitives.WriteInt64LittleEndian(eocd64[32..], totalEntries); // Total entries
                BinaryPrimitives.WriteInt64LittleEndian(eocd64[40..], cdSize);       // CD size
                BinaryPrimitives.WriteInt64LittleEndian(eocd64[48..], cdOffset);     // CD offset
                hasher.AppendData(eocd64);

                // Hash any extensible data sector (if present)
                long extensibleDataLength = zip64.Length - Zip64Eocd.MinLength;
                if (extensibleDataLength > 0)
                {
                    HashStreamRange(
                        hasher,
                        zip64.Offset + Zip64Eocd.MinLength,
                        extensibleDataLength,
                        bufferSpan);
                }

                // Step 3: Hash ZIP64 EOCD locator with adjusted offset
                // The EOCD offset needs to account for the adjusted CD offset and size
                Stream.Position = zip64.LocatorOffset;
                Stream.Read(bufferSpan[..Zip64Eocd.LocatorLength]);

                Span<byte> eocd64Locator = bufferSpan[..Zip64Eocd.LocatorLength];
                long adjustedEocdOffset = cdOffset + cdSize;
                BinaryPrimitives.WriteInt32LittleEndian(eocd64Locator[4..], 0); // Zero disk number with EOCD
                BinaryPrimitives.WriteInt64LittleEndian(eocd64Locator[8..], adjustedEocdOffset);
                hasher.AppendData(eocd64Locator);
            }

            // Step 4: Hash regular EOCD with zero'd disk numbers and if not
            // ZIP64 then also adjust entry count, CD size, and CD offset.
            Span<byte> eocd = bufferSpan[..ZipStructure.EocdMinLength];
            Stream.Position = _zipStructure.EndOfCentralDirectoryOffset;
            Stream.Read(bufferSpan);

            // Always zero disk numbers (offsets 4 and 6)
            BinaryPrimitives.WriteUInt16LittleEndian(eocd[4..], 0);
            BinaryPrimitives.WriteUInt16LittleEndian(eocd[6..], 0);
            if (!_zipStructure.Zip64.HasValue)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(eocd[8..], (ushort)totalEntries);
                BinaryPrimitives.WriteUInt16LittleEndian(eocd[10..], (ushort)totalEntries);
                BinaryPrimitives.WriteUInt32LittleEndian(eocd[12..], (uint)cdSize);
                BinaryPrimitives.WriteUInt32LittleEndian(eocd[16..], (uint)cdOffset);
            }

            // Need to hash the adjusted EOCD and the (optional) comment after.
            hasher.AppendData(eocd);

            int commentLength = _zipStructure.EndOfCentralDirectoryLength - ZipStructure.EocdMinLength;
            if (commentLength > 0)
            {
                HashStreamRange(
                    hasher,
                    _zipStructure.EndOfCentralDirectoryOffset + ZipStructure.EocdMinLength,
                    commentLength,
                    bufferSpan);
            }

            "AXCD"u8.CopyTo(dest);
            hasher.GetHashAndReset(dest[4..]);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}

/// <summary>
/// Authenticode provider for APPX/MSIX Windows App Packages.
/// </summary>
internal class AppxProvider : AppxProviderBase
{
    protected override Guid SipGuid => new("0ac5df4b-ce07-4de2-b76e-23c839a09fd1");

    public override AuthenticodeProvider Provider => AuthenticodeProvider.Appx;

    internal static string[] FileExtensions => [ ".appx", ".msix" ];

    private AppxProvider(
        Stream stream,
        bool leaveOpen,
        byte[] signature,
        ZipStructure zipStructure,
        ZipEntry? signatureEntry)
        : base(stream, leaveOpen, signature, zipStructure, signatureEntry)
    {
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
        var (signature, zipStructure, signatureEntry) = CreateCommon(stream);
        return new AppxProvider(stream, leaveOpen, signature, zipStructure, signatureEntry);
    }
}

/// <summary>
/// Authenticode provider for APPX/MSIX Bundle packages.
/// </summary>
internal class AppxBundleProvider : AppxProviderBase
{
    protected override Guid SipGuid => new("0f5f58b3-aade-4b9a-a434-95742d92eceb");

    public override AuthenticodeProvider Provider => AuthenticodeProvider.AppxBundle;

    internal static string[] FileExtensions => [ ".appxbundle", ".msixbundle" ];

    private AppxBundleProvider(
        Stream stream,
        bool leaveOpen,
        byte[] signature,
        ZipStructure zipStructure,
        ZipEntry? signatureEntry)
        : base(stream, leaveOpen, signature, zipStructure, signatureEntry)
    {
    }

    /// <summary>
    /// Creates an AppxBundleProvider instance from APPX/MSIX bundle stream.
    /// </summary>
    /// <param name="stream">The bundle stream (ZIP archive)</param>
    /// <param name="leaveOpen">Whether to leave the stream open after disposal</param>
    /// <returns>An initialized AppxBundleProvider instance</returns>
    /// <exception cref="ArgumentException">Thrown if the bundle is invalid</exception>
    /// <exception cref="InvalidDataException">Thrown if the ZIP structure is corrupted</exception>
    public static AppxBundleProvider Create(Stream stream, bool leaveOpen)
    {
        var (signature, zipStructure, signatureEntry) = CreateCommon(stream);
        return new AppxBundleProvider(stream, leaveOpen, signature, zipStructure, signatureEntry);
    }
}

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenAuthenticode.Zip;

/// <summary>
/// Represents a ZIP entry with information about the central directory record and local file header for the entry.
/// </summary>
/// <param name="CentralDirectoryOffset">The offset of the central directory record for this entry in the ZIP archive.</param>
/// <param name="CentralDirectoryLength">The length of the central directory record for this entry.</param>
/// <param name="LocalHeaderOffset">The offset of the local file header for this entry in the ZIP archive.</param>
/// <param name="LocalHeaderLength">The length of the local file header for this entry.</param>
/// <param name="CompressedLength">The length of the compressed data for this entry.</param>
/// <param name="DescriptorLength">The length of the data descriptor for this entry, if present.</param>
internal readonly record struct ZipEntry(
    long CentralDirectoryOffset,
    long CentralDirectoryLength,
    long LocalHeaderOffset,
    long LocalHeaderLength,
    long CompressedLength,
    int DescriptorLength);

/// <summary>
/// Represents the central directory information for a ZIP archive.
/// </summary>
/// <param name="Offset">The offset of the central directory in the ZIP archive.</param>
/// <param name="Length">The length of the central directory in bytes.</param>
/// <param name="Count">The total number of central directory records at the offset.</param>
internal readonly record struct ZipCentralDirectoryInfo(
    long Offset,
    long Length,
    long Count);

/// <summary>
/// Represents the End of Central Directory (EOCD) record information for a ZIP archive.
/// </summary>
/// <param name="Offset">The offset of the EOCD record in the ZIP archive.</param>
/// <param name="Length">The length of the EOCD record, including the variable-length comment.</param>
internal readonly record struct ZipEocdInfo(
    long Offset,
    int Length);

/// <summary>
/// Represents ZIP64 structures (EOCD64, EOCD64 Locator).
/// Only present for ZIP64 archives.
/// </summary>
/// <param name="Offset">The offset of the EOCD64 record in the ZIP archive.</param>
/// <param name="Length">The length of the EOCD64 record, including the variable-length extensible data sector.</param>
/// <param name="LocatorOffset">The offset of the EOCD64 Locator record in the ZIP archive.</param>
internal readonly record struct ZipEocd64Info(
    long Offset,
    long Length,
    long LocatorOffset);

/// <summary>
/// Represents the structure of a ZIP archive, including the location and size
/// of the central directory and local file headers. Provides functionality to
/// parse the ZIP structure from a stream and retrieve information about
/// individual entries in the archive. This data is not exposed in the BCL
/// .NET ZipArchive implementation and is required to support Authenticode
/// APPX signing.
/// </summary>
internal class ZipStructure
{
    private readonly Dictionary<string, ZipEntry> _entriesByName = [];
    private long _cdReadOffset = 0;

    private ZipStructure(
        ZipEocdInfo eocd,
        ZipEocd64Info? eocd64,
        ZipCentralDirectoryInfo cd)
    {
        EOCD = eocd;
        EOCD64 = eocd64;
        CD = cd;
    }

    public ZipEocdInfo EOCD { get; }
    public ZipEocd64Info? EOCD64 { get; }
    public ZipCentralDirectoryInfo CD { get; }

    public void AddEntry(
        Stream zipStream,
        string entryName,
        ReadOnlySpan<byte> entryData)
    {
        string tempPath = Path.GetTempFileName();
        using FileStream tempStream = new(
            tempPath,
            FileMode.Create,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize: 8192,
            FileOptions.DeleteOnClose);

        long cdStart = CD.Offset;
        long truncateFrom = cdStart;

        zipStream.Seek(cdStart, SeekOrigin.Begin);
        if (TryGetEntryByName(zipStream, entryName, out ZipEntry entry))
        {
            truncateFrom = entry.LocalHeaderOffset;

        }
        else
        {
            zipStream.CopyTo(tempStream);
        }

        // Copy

        zipStream.SetLength(truncateFrom);
        zipStream.Position = truncateFrom;

        // Write new entry local header
        // Write new entry compressed data
        // Write original CD records from temp stream.
        // Write new CD record for the new entry
        // (ZIP64) Update EOCD64 record offsets
        // (ZIP64) Update EOCD64 locator
        // Update EOCD record with new CD offset and length

        return;
    }

    /// <summary>
    /// Tries to get the ZIP entry information for the given entry name. If the
    /// entry does not exist in the ZIP structure, returns false.
    /// </summary>
    /// <param name="zipStream">The stream containing the ZIP archive.</param>
    /// <param name="name">The name of the entry to retrieve.</param>
    /// <param name="entry">When this method returns true, contains the
    ///     ZIP entry information.</param>
    /// <returns>true if the entry is found; otherwise, false.</returns>
    /// <exception cref="InvalidDataException">The ZIP data is invalid.</exception>
    public bool TryGetEntryByName(
        Stream zipStream,
        string name,
        [NotNullWhen(true)] out ZipEntry entry)
    {
        entry = default;
        if (_entriesByName.TryGetValue(name, out entry))
        {
            return true;
        }

        if (zipStream.Length < CD.Offset + CD.Length)
        {
            throw new InvalidDataException(
                "Provided stream is not valid for the ZIP structure recorded, central directory extends beyond end of stream");
        }

        if (_cdReadOffset >= CD.Length)
        {
            // We've already read all the CD records and haven't found the entry.
            return false;
        }

        Span<byte> buffer = stackalloc byte[CentralDirectory.MinLength];

        long offset = CD.Offset + _cdReadOffset;
        while (offset < CD.Offset + CD.Length)
        {
            long cdOffset = offset;
            zipStream.Seek(offset, SeekOrigin.Begin);
            zipStream.ReadExactly(buffer);

            ref readonly CentralDirectory cd = ref MemoryMarshal.AsRef<CentralDirectory>(buffer);

            // Read field values immediately before the buffer can be reused
            ushort fileNameLen = cd.FileNameLength;
            ushort extraFieldLen = cd.ExtraFieldLength;
            ushort fileCommentLen = cd.FileCommentLength;
            ZipFlags flags = cd.Flags;
            long compressedLength = cd.CompressedLength;
            long uncompressedLength = cd.UncompressedLength;
            long localHeaderOffset = cd.LocalHeaderOffset;

            Encoding fileNameEncoding = flags.HasFlag(ZipFlags.UTF8Encoding)
                ? Encoding.UTF8
                : Encoding.GetEncoding(437);

            string fileName = ReadString(zipStream, buffer, fileNameLen, fileNameEncoding);

            bool isZip64 = false;
            if (compressedLength == uint.MaxValue || uncompressedLength == uint.MaxValue || localHeaderOffset == uint.MaxValue)
            {
                // If any of these fields are set to 0xFFFFFFFF then the actual value
                // is stored in the extra fields.
                isZip64 = true;
                (compressedLength, uncompressedLength, localHeaderOffset) = GetCentralDirectoryZip64ExtraFields(
                    zipStream,
                    buffer,
                    extraFieldLen,
                    compressedLength,
                    uncompressedLength,
                    localHeaderOffset);
            }

            // While the CD is the source of truth for the entry details, the
            // local file header may contain incomplete data that changes the
            // length of some variable fields. We need to read that to
            // determine the local header length as well as the descriptor
            // length if present.
            (long localHeaderLength, int descriptorLength) = GetLocalHeaderLengths(
                zipStream,
                buffer,
                compressedLength,
                localHeaderOffset,
                flags.HasFlag(ZipFlags.DataDescriptor),
                isZip64);

            int cdLength = CentralDirectory.MinLength + fileNameLen + extraFieldLen + fileCommentLen;
            offset += cdLength;
            _cdReadOffset += cdLength;

            ZipEntry currentEntry = new(
                CentralDirectoryOffset: cdOffset,
                CentralDirectoryLength: cdLength,
                LocalHeaderOffset: localHeaderOffset,
                LocalHeaderLength: localHeaderLength,
                CompressedLength: compressedLength,
                DescriptorLength: descriptorLength);
            _entriesByName[fileName] = currentEntry;

            if (fileName == name)
            {
                entry = currentEntry;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Parses the ZIP structure from the given stream and returns a
    /// ZipStructure instance containing the zip metadata.
    /// </summary>
    /// <param name="zipStream">The stream containing the ZIP archive.</param>
    /// <returns>A ZipStructure instance with the parsed ZIP metadata.</returns>
    public static ZipStructure Create(Stream zipStream)
    {
        // We need to search backwards from the end of the stream for the EOCD
        // signature. The EOCD record is at least 22 bytes long and can be
        // followed by a variable length comment up to 65536 bytes, so we need
        // to read at least 22 + 65536 bytes from the end of the stream to find
        // the EOCD record. We also use the same buffer to read the EOCD64
        // and CD records and this size will fit all that data.
        const int MaxCommentSize = ushort.MaxValue;

        if (zipStream.Length < EndOfCentralDirectory.MinLength)
        {
            throw new InvalidDataException(
                "Stream is not a valid zip, it is too small to contain End of Central Directory record");
        }

        // This buffer should cover the EOCD, EOCD64 locator, EOCD64, and CD
        // records needed to parse the ZIP structure.
        int bufferSize = EndOfCentralDirectory.MinLength + MaxCommentSize;
        if (zipStream.Length < bufferSize)
        {
            bufferSize = (int)zipStream.Length;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            Span<byte> bufferSpan = buffer.AsSpan();

            zipStream.Seek(-bufferSize, SeekOrigin.End);
            zipStream.ReadExactly(buffer, 0, bufferSize);

            ReadOnlySpan<byte> view = buffer.AsSpan(0, bufferSize);
            ReadOnlySpan<byte> eocdSignature = MemoryMarshal.AsBytes([EndOfCentralDirectory.Signature]);

            int pos;
            while ((pos = view.LastIndexOf(eocdSignature)) != -1)
            {
                if (view.Length - pos < EndOfCentralDirectory.MinLength)
                {
                    // Checks the signature isn't in the comment field which
                    // can contain arbitrary data. If the signature is found
                    // but there's not enough space for a valid EOCD record we
                    // should continue to search for the next occurrence of the
                    // signature.
                    view = view[..pos];
                    continue;
                }

                // As we could still be in a comment we do some basic checks to
                // verify that we have a valid EOCD record and the values in
                // record point to valid locations in the file.
                if (TryGetCentralDirectoryInformation(
                    zipStream,
                    bufferSpan,
                    bufferSpan.Slice(pos, EndOfCentralDirectory.MinLength),
                    zipStream.Length - bufferSize + pos,
                    out ZipStructure? zipInfo))
                {
                    return zipInfo;
                }

                view = view[..pos];
            }

            throw new InvalidDataException(
                "Could not find End of Central Directory record in ZIP archive");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool TryGetCentralDirectoryInformation(
        Stream stream,
        Span<byte> buffer,
        ReadOnlySpan<byte> eocdRecord,
        long eocdOffset,
        [NotNullWhen(true)] out ZipStructure? zipInfo)
    {
        Debug.Assert(buffer.Length >= 4, "Buffer is expected to fit the CD signature for validation.");

        zipInfo = null;

        ref readonly EndOfCentralDirectory eocd = ref MemoryMarshal.AsRef<EndOfCentralDirectory>(eocdRecord);
        long cdCount = eocd.CentralDirectoryTotalRecords;
        long cdLength = eocd.CentralDirectoryLength;
        long cdOffset = eocd.CentralDirectoryOffset;
        ushort commentLength = eocd.CommentLength;

        // We validate the comment length doesn't exceed the remaining data
        // after the EOCD record.
        if (eocdOffset + EndOfCentralDirectory.MinLength + commentLength > stream.Length)
        {
            // Comment length exceeds remaining data after EOCD record.
            return false;
        }

        // If any of the CD information is set to 0xFFFF/0xFFFFFFFF sentinel values,
        // we need to validate the ZIP64 EOCD locator and record are present and valid.
        long? eocd64LocatorOffset = null;
        long? eocd64Offset = null;
        long? eocd64Length = null;
        if (cdCount == -1 || cdLength == uint.MaxValue || cdOffset == uint.MaxValue)
        {
            if (TryGetEndOfCentralDirectory64(
                stream,
                buffer,
                eocdOffset,
                out long eocd64LocatorOffsetValue,
                out long eocd64OffsetValue,
                out long eocd64LengthValue,
                out cdOffset,
                out cdLength,
                out cdCount))
            {
                eocd64LocatorOffset = eocd64LocatorOffsetValue;
                eocd64Offset = eocd64OffsetValue;
                eocd64Length = eocd64LengthValue;
            }
            else
            {
                // Invalid ZIP64 EOCD information, continue searching for the next EOCD signature.
                return false;
            }
        }

        if (cdCount < 0 || cdLength < 0 || cdOffset < 0 || cdOffset + cdLength > stream.Length)
        {
            // CD information cannot be negative or exceed stream length.
            return false;
        }

        stream.Seek(cdOffset, SeekOrigin.Begin);
        stream.ReadExactly(buffer[..4]);

        int cdSignature = MemoryMarshal.Read<int>(buffer[..4]);
        if (cdSignature != CentralDirectory.Signature)
        {
            // CD signature not found at expected offset.
            return false;
        }

        ZipEocd64Info? zip64 = eocd64Offset.HasValue
            ? new ZipEocd64Info(eocd64Offset.Value, eocd64Length!.Value, eocd64LocatorOffset!.Value)
            : null;

        zipInfo = new ZipStructure(
            new ZipEocdInfo(eocdOffset, EndOfCentralDirectory.MinLength + commentLength),
            zip64,
            new ZipCentralDirectoryInfo(cdOffset, cdLength, cdCount));

        return true;
    }

    private static bool TryGetEndOfCentralDirectory64(
        Stream zipStream,
        Span<byte> buffer,
        long eocdOffset,
        out long locatorOffset,
        out long eocd64Offset,
        out long eocd64Length,
        out long cdOffset,
        out long cdLength,
        out long cdCount)
    {
        Debug.Assert(buffer.Length >= EndOfCentralDirectory64.MinLength, "Buffer is expected to fit the ZIP64 EOCD record.");

        locatorOffset = eocdOffset - EndOfCentralDirectory64Locator.MinLength;
        eocd64Offset = 0;
        eocd64Length = 0;
        cdOffset = 0;
        cdLength = 0;
        cdCount = 0;

        if (locatorOffset - EndOfCentralDirectory64.MinLength < 0)
        {
            // Not enough data to contain the locator and ZIP64 EOCD so this is
            // not a valid record.
            return false;
        }

        zipStream.Seek(locatorOffset, SeekOrigin.Begin);
        zipStream.ReadExactly(buffer[..EndOfCentralDirectory64Locator.MinLength]);

        ref readonly EndOfCentralDirectory64Locator locator = ref MemoryMarshal.AsRef<EndOfCentralDirectory64Locator>(buffer);
        if (locator.EOCD64LocatorSignature != EndOfCentralDirectory64Locator.Signature)
        {
            return false;
        }

        eocd64Offset = locator.EndOfCentralDirectoryOffset;
        if (eocd64Offset < 0 || eocd64Offset > zipStream.Length - EndOfCentralDirectory64.MinLength)
        {
            return false;
        }

        zipStream.Seek(eocd64Offset, SeekOrigin.Begin);
        zipStream.ReadExactly(buffer[..EndOfCentralDirectory64.MinLength]);

        ref readonly EndOfCentralDirectory64 eocd64 = ref MemoryMarshal.AsRef<EndOfCentralDirectory64>(buffer);
        if (eocd64.EOCDSignature != EndOfCentralDirectory64.Signature)
        {
            return false;
        }

        // The size omits the signature and the size record so we add it back
        // in for easier calculation.
        eocd64Length = eocd64.SizeOfRecord + 12;
        if (eocd64Offset + eocd64Length > locatorOffset)
        {
            // The ZIP64 EOCD record goes beyond the locator offset which is
            // invalid.
            return false;
        }

        cdCount = eocd64.CentralDirectoryTotalRecords;
        cdLength = eocd64.CentralDirectoryLength;
        cdOffset = eocd64.CentralDirectoryOffset;

        return true;
    }

    private static string ReadString(
        Stream stream,
        Span<byte> buffer,
        int length,
        Encoding encoding)
    {
        byte[]? rentedArray = null;
        try
        {
            if (buffer.Length < length)
            {
                rentedArray = ArrayPool<byte>.Shared.Rent(length);
                buffer = rentedArray.AsSpan(0, length);
            }
            else
            {
                buffer = buffer[..length];
            }

            stream.ReadExactly(buffer);
            return encoding.GetString(buffer);
        }
        finally
        {
            if (rentedArray != null)
            {
                ArrayPool<byte>.Shared.Return(rentedArray);
            }
        }
    }

    private static (long compressedLength, long uncompressedLength, long lfhOffset) GetCentralDirectoryZip64ExtraFields(
        Stream zipStream,
        Span<byte> buffer,
        int extraFieldLen,
        long compressedSize,
        long uncompressedSize,
        long localHeaderOffset)
    {
        Debug.Assert(buffer.Length >= 8, "Buffer should be at least 8 bytes to read the ZIP64 extra field header");

        // The ZIP64 extra field contains the actual values for the compressed,
        // uncompressed size, and local header offset fields if they are set to
        // 0xFFFFFFFF (uint.MaxValue). The fields are stored under the header ID
        // 0x0001 and the order is dependent on which fields are set to the
        // sentinel value in the CD record.
        int read = 0;
        while (read < extraFieldLen && (compressedSize == uint.MaxValue || uncompressedSize == uint.MaxValue || localHeaderOffset == uint.MaxValue))
        {
            zipStream.ReadExactly(buffer[..4]);

            ref readonly ExtraField extraField = ref MemoryMarshal.AsRef<ExtraField>(buffer);
            short headerId = extraField.HeaderId;
            ushort dataLength = extraField.DataLength;

            if (headerId == ExtraField.Zip64ExtendedInformation)
            {
                // ZIP64 extended information extra field.
                if (dataLength < 8)
                {
                    throw new InvalidDataException("Invalid ZIP64 extra field, data size is too small to contain required fields");
                }

                zipStream.ReadExactly(buffer[..8]);
                long zip64Value = MemoryMarshal.Read<long>(buffer[..8]);
                if (compressedSize == uint.MaxValue)
                {
                    compressedSize = zip64Value;
                }
                else if (uncompressedSize == uint.MaxValue)
                {
                    uncompressedSize = zip64Value;
                }
                else
                {
                    localHeaderOffset = zip64Value;
                }
            }
            else
            {
                zipStream.Seek(dataLength, SeekOrigin.Current);
            }

            read += 4 + dataLength;
        }

        if (compressedSize == uint.MaxValue || uncompressedSize == uint.MaxValue || localHeaderOffset == uint.MaxValue)
        {
            // We didn't find the ZIP64 extra field or it didn't contain all the required fields.
            throw new InvalidDataException("ZIP64 extra field not found or missing required fields");
        }

        return (compressedSize, uncompressedSize, localHeaderOffset);
    }

    private static (long lfhLength, int descriptorLength) GetLocalHeaderLengths(
        Stream zipStream,
        Span<byte> buffer,
        long compressedLength,
        long localHeaderOffset,
        bool hasDataDescriptor,
        bool isZip64)
    {
        Debug.Assert(buffer.Length >= LocalFileHeader.MinLength, "Buffer is expected to fit the local header fixed fields for validation.");

        if (localHeaderOffset + LocalFileHeader.MinLength + compressedLength > zipStream.Length)
        {
            throw new InvalidDataException(
                "Provided stream is not valid for the ZIP structure recorded, local header extends beyond end of stream");
        }

        zipStream.Seek(localHeaderOffset, SeekOrigin.Begin);
        zipStream.ReadExactly(buffer[..LocalFileHeader.MinLength]);

        ref readonly LocalFileHeader lfh = ref MemoryMarshal.AsRef<LocalFileHeader>(buffer);

        long finalHeaderLength = LocalFileHeader.MinLength + lfh.FileNameLength + lfh.ExtraFieldLength;

        int descriptorLength = 0;
        if (hasDataDescriptor)
        {
            // As the data descriptor may or may not contain a signature we
            // need to read the first 4 bytes to determine the length based
            // on whether the signature is present or not.
            descriptorLength = isZip64 ? 24 : 16;

            zipStream.Seek(localHeaderOffset + finalHeaderLength + compressedLength, SeekOrigin.Begin);
            zipStream.ReadExactly(buffer[..4]);
            int signature = MemoryMarshal.Read<int>(buffer[..4]);
            if (signature != LocalFileHeader.DataDescriptorSignature)
            {
                descriptorLength -= 4;
            }
        }

        return (finalHeaderLength, descriptorLength);
    }
}

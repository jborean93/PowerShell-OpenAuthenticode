using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;

namespace OpenAuthenticode;

internal readonly record struct ZipEntry(
    long CentralDirectoryOffset,
    long CentralDirectoryLength,
    long LocalHeaderOffset,
    long LocalHeaderLength,
    long CompressedLength,
    int DescriptorLength);

/// <summary>
/// Represents ZIP64 structures (EOCD64, EOCD64 Locator).
/// Only present for ZIP64 archives.
/// </summary>
internal readonly record struct Zip64Eocd(
    long Offset,
    long Length,
    long LocatorOffset)
{
    /// <summary>
    /// The fixed length of the ZIP64 EOCD record header (always 56 bytes).
    /// Does not include the optional extensible data sector.
    /// </summary>
    public const int MinLength = 56;

    /// <summary>
    /// The fixed length of the ZIP64 EOCD Locator structure (always 20 bytes).
    /// </summary>
    public const int LocatorLength = 20;
}

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
    /// <summary>
    /// The minimum size of the End of Central Directory record (22 bytes).
    /// Does not include the optional comment field.
    /// </summary>
    public const int EocdMinLength = 22;

    private const int CentralDirectoryMinSize = 46;
    private const int LocalFileHeaderMinSize = 30;

    private readonly Dictionary<string, ZipEntry> _entriesByName = [];
    private long _cdReadOffset = 0;

    private ZipStructure(
        long endOfCentralDirectoryOffset,
        int endOfCentralDirectoryLength,
        Zip64Eocd? zip64,
        long centralDirectoryOffset,
        long centralDirectoryLength,
        long centralDirectoryCount)
    {
        EndOfCentralDirectoryOffset = endOfCentralDirectoryOffset;
        EndOfCentralDirectoryLength = endOfCentralDirectoryLength;
        Zip64 = zip64;
        CentralDirectoryOffset = centralDirectoryOffset;
        CentralDirectoryLength = centralDirectoryLength;
        CentralDirectoryCount = centralDirectoryCount;
    }

    public long EndOfCentralDirectoryOffset { get; }
    public int EndOfCentralDirectoryLength { get; }

    /// <summary>
    /// ZIP64 structures (EOCD64 and EOCD64 Locator).
    /// Only set for ZIP64 archives.
    /// </summary>
    public Zip64Eocd? Zip64 { get; }

    public long CentralDirectoryOffset { get; }
    public long CentralDirectoryCount { get; }
    public long CentralDirectoryLength { get; }

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
        const short FlagHasDataDescriptor = 0x0008;
        const short FlagIsUTF8 = 0x0800;

        entry = default;
        if (_entriesByName.TryGetValue(name, out entry))
        {
            return true;
        }

        if (zipStream.Length < CentralDirectoryOffset + CentralDirectoryLength)
        {
            throw new InvalidDataException(
                "Provided stream is not valid for the ZIP structure recorded, central directory extends beyond end of stream");
        }

        if (_cdReadOffset >= CentralDirectoryLength)
        {
            // We've already read all the CD records and haven't found the entry.
            return false;
        }

        Span<byte> buffer = stackalloc byte[CentralDirectoryMinSize];

        long offset = CentralDirectoryOffset + _cdReadOffset;
        while (offset < CentralDirectoryOffset + CentralDirectoryLength)
        {
            long cdOffset = offset;
            zipStream.Seek(offset, SeekOrigin.Begin);
            zipStream.Read(buffer);

            short flags = BinaryPrimitives.ReadInt16LittleEndian(buffer[8..10]);
            long compressedLength = BinaryPrimitives.ReadInt32LittleEndian(buffer[20..24]);
            long uncompressedLength = BinaryPrimitives.ReadInt32LittleEndian(buffer[24..28]);
            short fileNameLen = BinaryPrimitives.ReadInt16LittleEndian(buffer[28..30]);
            short extraFieldLen = BinaryPrimitives.ReadInt16LittleEndian(buffer[30..32]);
            short fileCommentLen = BinaryPrimitives.ReadInt16LittleEndian(buffer[32..34]);
            long localHeaderOffset = BinaryPrimitives.ReadInt32LittleEndian(buffer[42..46]);

            Encoding fileNameEncoding = (flags & FlagIsUTF8) != 0 ? Encoding.UTF8 : Encoding.GetEncoding(437);

            string fileName = ReadString(zipStream, buffer, fileNameLen, fileNameEncoding);

            bool isZip64 = false;
            if (compressedLength == -1 || uncompressedLength == -1 || localHeaderOffset == -1)
            {
                // If any of these fields are set to -1 then the actual value
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
                (flags & FlagHasDataDescriptor) != 0,
                isZip64);

            int cdLength = CentralDirectoryMinSize + fileNameLen + extraFieldLen + fileCommentLen;
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
        const int MaxCommentSize = ushort.MaxValue; // 65535

        if (zipStream.Length < EocdMinLength)
        {
            throw new InvalidDataException(
                "Stream is not a valid zip, it is too small to contain End of Central Directory record");
        }

        int bufferSize = EocdMinLength + MaxCommentSize;
        if (zipStream.Length < bufferSize)
        {
            bufferSize = (int)zipStream.Length;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            ReadOnlySpan<byte> eocdSig = [0x50, 0x4b, 0x05, 0x06];
            Span<byte> bufferSpan = buffer.AsSpan();

            zipStream.Seek(-bufferSize, SeekOrigin.End);
            zipStream.Read(buffer, 0, bufferSize);

            ReadOnlySpan<byte> view = buffer.AsSpan(0, bufferSize);

            int pos;
            while ((pos = view.LastIndexOf(eocdSig)) != -1)
            {
                if (view.Length - pos < EocdMinLength)
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
                    bufferSpan.Slice(pos, EocdMinLength),
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

        long cdCount = BinaryPrimitives.ReadInt16LittleEndian(eocdRecord[10..12]);
        long cdLength = BinaryPrimitives.ReadInt32LittleEndian(eocdRecord[12..16]);
        long cdOffset = BinaryPrimitives.ReadInt32LittleEndian(eocdRecord[16..20]);

        // We validate the comment length doesn't exceed the remaining data
        // after the EOCD record.
        ushort commentLen = BinaryPrimitives.ReadUInt16LittleEndian(eocdRecord[20..22]);
        if (eocdOffset + EocdMinLength + commentLen > stream.Length)
        {
            // Comment length exceeds remaining data after EOCD record.
            return false;
        }

        // If any of the CD information is set to -1 then we need to validate
        // the ZIP64 EOCD locator and record are present and valid.
        long? eocd64LocatorOffset = null;
        long? eocd64Offset = null;
        long? eocd64Length = null;
        if (cdCount == -1 || cdLength == -1 || cdOffset == -1)
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

        ReadOnlySpan<byte> cdSig = [0x50, 0x4b, 0x01, 0x02];
        stream.Seek(cdOffset, SeekOrigin.Begin);
        stream.Read(buffer[..4]);

        if (!buffer[..4].SequenceEqual(cdSig))
        {
            // CD signature not found at expected offset.
            return false;
        }

        Zip64Eocd? zip64 = eocd64Offset.HasValue
            ? new Zip64Eocd(eocd64Offset.Value, eocd64Length!.Value, eocd64LocatorOffset!.Value)
            : null;

        zipInfo = new ZipStructure(
            eocdOffset,
            EocdMinLength + commentLen,
            zip64,
            cdOffset,
            cdLength,
            cdCount);

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
        // The ZIP64 EOCD record is located by searching backwards from the
        // EOCD record for the ZIP64 EOCD locator signature. The locator is
        // 20 bytes long and contains the offset of the ZIP64 EOCD record,
        // which is at least 56 bytes long.
        ReadOnlySpan<byte> locatorSig = [0x50, 0x4b, 0x06, 0x07];
        ReadOnlySpan<byte> eocd64Sig = [0x50, 0x4b, 0x06, 0x06];

        Debug.Assert(buffer.Length >= Zip64Eocd.MinLength, "Buffer is expected to fit the ZIP64 EOCD record.");

        locatorOffset = eocdOffset - Zip64Eocd.LocatorLength;;
        eocd64Offset = 0;
        eocd64Length = 0;
        cdOffset = 0;
        cdLength = 0;
        cdCount = 0;

        if (locatorOffset - Zip64Eocd.MinLength < 0)
        {
            // Not enough data to contain the locator and ZIP64 EOCD so this is
            // not a valid record.
            return false;
        }
        zipStream.Seek(locatorOffset, SeekOrigin.Begin);
        zipStream.Read(buffer[..Zip64Eocd.LocatorLength]);

        if (!buffer[..4].SequenceEqual(locatorSig))
        {
            return false;
        }

        eocd64Offset = BinaryPrimitives.ReadInt64LittleEndian(buffer[8..16]);
        if (eocd64Offset < 0 || eocd64Offset > zipStream.Length - Zip64Eocd.MinLength)
        {
            return false;
        }

        zipStream.Seek(eocd64Offset, SeekOrigin.Begin);
        zipStream.Read(buffer[..Zip64Eocd.MinLength]);

        if (!buffer[..4].SequenceEqual(eocd64Sig))
        {
            return false;
        }

        // The size omits the signature and the size record so we add it back
        // in for easier calculation.
        eocd64Length = BinaryPrimitives.ReadInt64LittleEndian(buffer[4..12]) + 12;

        if (eocd64Offset + eocd64Length > locatorOffset)
        {
            // The ZIP64 EOCD record goes beyond the locator offset which is
            // invalid.
            return false;
        }

        cdCount = BinaryPrimitives.ReadInt64LittleEndian(buffer[32..40]);
        cdLength = BinaryPrimitives.ReadInt64LittleEndian(buffer[40..48]);
        cdOffset = BinaryPrimitives.ReadInt64LittleEndian(buffer[48..56]);

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

            stream.Read(buffer);
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

    private static (long, long, long) GetCentralDirectoryZip64ExtraFields(
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
        // -1. The fields are stored under the header ID 0x0001 and the order
        // is dependent on which fields are set to -1 in the CD record.
        int read = 0;
        while (read < extraFieldLen && (compressedSize == -1 || uncompressedSize == -1 || localHeaderOffset == -1))
        {
            zipStream.Read(buffer[..4]);
            short headerId = BinaryPrimitives.ReadInt16LittleEndian(buffer[..2]);
            short dataSize = BinaryPrimitives.ReadInt16LittleEndian(buffer[2..4]);

            if (headerId == 0x0001)
            {
                // ZIP64 extended information extra field.
                if (dataSize < 8)
                {
                    // At minimum the compressed size field must be present which is 8 bytes, so the data size must be at least 8 bytes.
                    throw new InvalidDataException("Invalid ZIP64 extra field, data size is too small to contain required fields");
                }

                zipStream.Read(buffer[..8]);
                long zip64Value = BinaryPrimitives.ReadInt64LittleEndian(buffer[..8]);
                if (compressedSize == -1)
                {
                    compressedSize = zip64Value;
                }
                else if (uncompressedSize == -1)
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
                zipStream.Seek(dataSize, SeekOrigin.Current);
            }

            read += 4 + dataSize;
        }

        if (compressedSize == -1 || uncompressedSize == -1 || localHeaderOffset == -1)
        {
            // We didn't find the ZIP64 extra field or it didn't contain all the required fields.
            throw new InvalidDataException("ZIP64 extra field not found or missing required fields");
        }

        return (compressedSize, uncompressedSize, localHeaderOffset);
    }

    private static (long, int) GetLocalHeaderLengths(
        Stream zipStream,
        Span<byte> buffer,
        long compressedLength,
        long localHeaderOffset,
        bool hasDataDescriptor,
        bool isZip64)
    {
        Debug.Assert(buffer.Length >= 30, "Buffer is expected to fit the local header fixed fields for validation.");

        if (localHeaderOffset + LocalFileHeaderMinSize + compressedLength > zipStream.Length)
        {
            throw new InvalidDataException(
                "Provided stream is not valid for the ZIP structure recorded, local header extends beyond end of stream");
        }

        zipStream.Seek(localHeaderOffset, SeekOrigin.Begin);
        zipStream.Read(buffer[..LocalFileHeaderMinSize]);

        short fileNameLen = BinaryPrimitives.ReadInt16LittleEndian(buffer[26..28]);
        short extraFieldLen = BinaryPrimitives.ReadInt16LittleEndian(buffer[28..30]);

        long finalHeaderLength = LocalFileHeaderMinSize + fileNameLen + extraFieldLen;

        int descriptorLength = 0;
        if (hasDataDescriptor)
        {
            // As the data descriptor may or may not contain a signature we
            // need to read the first 4 bytes to determine the length based
            // on whether the signature is present or not.
            descriptorLength = isZip64 ? 24 : 16;

            ReadOnlySpan<byte> descriptorSig = [0x50, 0x4b, 0x07, 0x08];
            zipStream.Seek(localHeaderOffset + finalHeaderLength + compressedLength, SeekOrigin.Begin);
            zipStream.Read(buffer[..4]);
            if (!buffer[..4].SequenceEqual(descriptorSig))
            {
                descriptorLength -= 4;
            }
        }

        return (finalHeaderLength, descriptorLength);
    }
}

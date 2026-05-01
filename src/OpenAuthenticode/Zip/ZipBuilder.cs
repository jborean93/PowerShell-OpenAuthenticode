using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenAuthenticode.Zip;

/// <summary>
/// Class used for appending or removing files of an existing zip.
/// </summary>
internal static class ZipBuilder
{
    /// <summary>
    /// Adds a file to the ZIP archive.
    /// </summary>
    /// <param name="entryName">The name of the zip entry to add/replace.</param>
    /// <param name="entryData">The data to add to the zip entry.</param>
    public static void AddEntry(
        Stream stream,
        ZipStructure zipStructure,
        string entryName,
        Stream newEntry)
    {
        Debug.Assert(stream.CanRead, "The stream must be readable to be able to append to the zip.");
        Debug.Assert(stream.CanWrite, "The stream must be writable to be able to append to the zip.");
        Debug.Assert(stream.CanSeek, "The stream must support seeking to be able to append to the zip.");
        Debug.Assert(newEntry.CanRead, "The new entry stream must be readable.");

        long truncateAt = zipStructure.CD.Offset;
        long oldCdLength = zipStructure.CD.Length;
        long newCdCount = zipStructure.CD.Count + 1;

        if (zipStructure.TryGetEntryByName(stream, entryName, out ZipEntry existingEntry))
        {
            // If the entry already exists we need to truncate the zip after
            // the LFH for that entry.
            truncateAt = existingEntry.LocalHeaderOffset;
            oldCdLength -= existingEntry.CentralDirectoryLength;
            newCdCount--;
        }

        int bufferSize = (int)Math.Min(81920, stream.Length - truncateAt);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            // We use the temp zip path to build the remaining zip data added
            // after the last entry. We can't use an in memory buffer as the
            // remaining zip data is potentially large. We cannot use File.Move
            // on the final operation because we don't know if the stream
            // provides delete share access.
            string tempZipPath = Path.GetTempFileName();
            using FileStream tempStream = new(
                tempZipPath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 4096,
                options: FileOptions.DeleteOnClose);

            // The new zip structure needs to contain the following after
            // the truncate offset:
            //   1. The LFH for the new entry
            //   2. The compressed data for the new entry
            //   3. The existing CDs but not the old CD for this entry
            //   4. A new CD for the new entry
            //   5. The existing data after the CD
            // It also needs to update the EOCD offsets for the new CD
            // offset, length, and count.

            // Add new LFH and compressed data for the provided entry.
            long newEntryLocalHeaderOffset = truncateAt;
            WriteZipEntry(
                tempStream,
                entryName,
                newEntry,
                buffer,
                out short compressionMethod,
                out ushort lastModFileTime,
                out ushort lastModFileDate,
                out uint crc32,
                out long compressedLength,
                out ushort fileNameLength);

            // Copy the existing CD but exclude the entry CD if it exists.
            stream.Seek(zipStructure.CD.Offset, SeekOrigin.Begin);
            CopyStreamTo(
                stream,
                tempStream,
                oldCdLength,
                buffer);

            // Add new CD for our new entry.
            long newCdOffset = truncateAt + tempStream.Position;
            long cdEntryLength = WriteZipCentralDirectory(
                tempStream,
                entryName,
                buffer,
                compressionMethod,
                lastModFileTime,
                lastModFileDate,
                crc32,
                compressedLength,
                newEntry.Length,
                fileNameLength,
                newEntryLocalHeaderOffset);
            long newCdLength = oldCdLength + cdEntryLength;

            // Add any data after the source CD and before the EOCD.
            long endOfCd = zipStructure.CD.Offset + zipStructure.CD.Length;
            long eocdOffset = zipStructure.EOCD64.HasValue
                ? zipStructure.EOCD64.Value.Offset
                : zipStructure.EOCD.Offset;
            long extraData = eocdOffset - endOfCd;

            stream.Seek(endOfCd, SeekOrigin.Begin);
            if (extraData > 0)
            {
                CopyStreamTo(stream, tempStream, extraData, buffer);
            }

            // Fix up the offsets in the EOCD for our new CD position,
            // length, and count.
            if (zipStructure.EOCD64.HasValue)
            {
                ZipEocd64Info z64 = zipStructure.EOCD64.Value;
                long eocd64Offset = tempStream.Position + truncateAt;
                long eocd64Length = z64.LocatorOffset - z64.Offset;

                CopyEocd64(
                    stream,
                    tempStream,
                    eocd64Length,
                    newCdOffset,
                    newCdLength,
                    newCdCount,
                    buffer);
                CopyEocd64Locator(
                    stream,
                    tempStream,
                    eocd64Offset,
                    buffer);
                CopyEocd(
                    stream,
                    tempStream,
                    uint.MaxValue,
                    uint.MaxValue,
                    ushort.MaxValue,
                    buffer);
            }
            else
            {
                CopyEocd(
                    stream,
                    tempStream,
                    (uint)newCdOffset,
                    (uint)newCdLength,
                    (ushort)newCdCount,
                    buffer);
            }

            // Once we have successfully built the new zip data we truncate
            // the existing stream and copy the new data back to it.
            stream.SetLength(truncateAt);
            stream.Seek(0, SeekOrigin.End);
            tempStream.Seek(0, SeekOrigin.Begin);
            tempStream.CopyTo(stream);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static long WriteZipEntry(
        Stream stream,
        string entryName,
        Stream entryData,
        Span<byte> buffer,
        out short compressionMethod,
        out ushort lastModFileTime,
        out ushort lastModFileDate,
        out uint crc32,
        out long compressedLength,
        out ushort fileNameLength)
    {
        Debug.Assert(
            buffer.Length >= LocalFileHeader.MinLength,
            "The buffer must be large enough to hold the local file header.");

        compressionMethod = 8;  // Deflated

        // MS-DOS time format (2 bytes):
        // Bits 0-4:   Seconds / 2 (0-29)
        // Bits 5-10:  Minutes (0-59)
        // Bits 11-15: Hours (0-23)
        DateTime now = DateTime.UtcNow;
        lastModFileTime = (ushort)(
            ((now.Second / 2) & 0x1F) |
            ((now.Minute << 5) & 0x7E0) |
            ((now.Hour << 11) & 0xF800));

        // MS-DOS date format (2 bytes):
        // Bits 0-4:   Day (1-31)
        // Bits 5-8:   Month (1-12)
        // Bits 9-15:  Year - 1980 (0-127)
        lastModFileDate = (ushort)(
            (now.Day & 0x1F) |
            ((now.Month << 5) & 0x1E0) |
            (((now.Year - 1980) << 9) & 0xFE00));

        crc32 = Crc32.Compute(entryData, buffer);
        entryData.Position = 0;

        fileNameLength = (ushort)entryName.Length;  // We assume ASCII so char == byte

        Span<long> extraFields = stackalloc long[2];
        int extraFieldCount = 0;

        // Worst case deflate expansion
        long maxCompressedLength = entryData.Length + (entryData.Length + 65534) / 65535 * 5;
        uint compressedLengthVal;
        if (maxCompressedLength < uint.MaxValue)
        {
            compressedLengthVal = 0;  // This is written after when we know the compressed length.
        }
        else
        {
            compressedLengthVal = uint.MaxValue;
            extraFields[extraFieldCount++] = 0;
        }

        uint uncompressedLengthVal;
        if (entryData.Length < uint.MaxValue)
        {
            uncompressedLengthVal = (uint)entryData.Length;
        }
        else
        {
            extraFields[extraFieldCount++] = entryData.Length;
            uncompressedLengthVal = uint.MaxValue;
        }

        short versionNeeded = extraFieldCount > 0
            ? (short)45  // Version 4.5 is needed for ZIP64 extra fields
            : (short)20; // Version 2.0 as a baseline.

        {
            ref LocalFileHeader lfh = ref MemoryMarshal.AsRef<LocalFileHeader>(buffer);
            lfh.LFHSignature = LocalFileHeader.Signature;
            lfh.VersionNeededToExtract = versionNeeded;
            lfh.Flags = ZipFlags.DataDescriptor;
            lfh.CompressionMethod = compressionMethod;
            lfh.LastModFileTime = lastModFileTime;
            lfh.LastModFileDate = lastModFileDate;
            lfh.Crc32 = crc32;
            lfh.CompressedLength = compressedLengthVal;
            lfh.UncompressedLength = uncompressedLengthVal;
            lfh.FileNameLength = (ushort)entryName.Length;
            lfh.ExtraFieldLength = (ushort)(extraFieldCount * 12);
        }

        stream.Write(buffer[..LocalFileHeader.MinLength]);
        Encoding.ASCII.GetBytes(entryName, buffer);
        stream.Write(buffer[..fileNameLength]);
        long extraFieldLength = WriteZip64ExtraFields(stream, extraFields[..extraFieldCount], buffer);

        long compressedDataStart = stream.Position;
        using (DeflateStream deflateStream = new(stream, CompressionLevel.Fastest, leaveOpen: true))
        {
            entryData.CopyTo(deflateStream);
        }
        compressedLength = compressedDataStart - stream.Position;

        long endPos = stream.Position;
        if (maxCompressedLength < uint.MaxValue)
        {
            // Patch the compressed length in the LFH.
            long compressedLengthOffset = LocalFileHeader.MinLength - Marshal.OffsetOf<LocalFileHeader>(
                nameof(LocalFileHeader.CompressedLength)).ToInt64();
            stream.Seek(compressedLengthOffset, SeekOrigin.Begin);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, (uint)compressedLength);
            stream.Write(buffer[..4]);
        }
        else
        {
            // Patch the compressed length in the ZIP64 extra field.
            long compressedLengthOffset = LocalFileHeader.MinLength + fileNameLength + 4; // 4 bytes for the header of the ZIP64 extra field
            stream.Seek(compressedLengthOffset, SeekOrigin.Begin);
            BinaryPrimitives.WriteInt64LittleEndian(buffer, compressedLength);
            stream.Write(buffer[..8]);
        }
        stream.Position = endPos;

        return LocalFileHeader.MinLength + fileNameLength + extraFieldLength + compressedLength;
    }

    private static long WriteZipCentralDirectory(
        Stream stream,
        string entryName,
        Span<byte> buffer,
        short compressionMethod,
        ushort lastModFileTime,
        ushort lastModFileDate,
        uint crc32,
        long compressedSize,
        long uncompressedSize,
        ushort fileNameLength,
        long localHeaderOffset)
    {
        Debug.Assert(
            buffer.Length >= CentralDirectory.MinLength,
            "The buffer must be large enough to hold the central directory header.");

        Span<long> extraFields = stackalloc long[3];
        int extraFieldCount = 0;
        uint compressedLengthVal;
        if (compressedSize < uint.MaxValue)
        {
            compressedLengthVal = (uint)compressedSize;
        }
        else
        {
            extraFields[extraFieldCount++] = compressedSize;
            compressedLengthVal = uint.MaxValue;
        }

        uint uncompressedLengthVal;
        if (uncompressedSize < uint.MaxValue)
        {
            uncompressedLengthVal = (uint)uncompressedSize;
        }
        else
        {
            extraFields[extraFieldCount++] = uncompressedSize;
            uncompressedLengthVal = uint.MaxValue;
        }

        uint localHeaderOffsetVal;
        if (localHeaderOffset < uint.MaxValue)
        {
            localHeaderOffsetVal = (uint)localHeaderOffset;
        }
        else
        {
            extraFields[extraFieldCount++] = localHeaderOffset;
            localHeaderOffsetVal = uint.MaxValue;
        }

        short versionNeeded = extraFieldCount > 0
            ? (short)45  // Version 4.5 is needed for ZIP64 extra fields
            : (short)20; // Version 2.0 as a baseline.

        {
            ref CentralDirectory cd = ref MemoryMarshal.AsRef<CentralDirectory>(buffer);
            cd.CDSignature = CentralDirectory.Signature;
            cd.VersionMadeBy = 45; // v4.5
            cd.VersionNeededToExtract = versionNeeded;
            cd.Flags = ZipFlags.None;
            cd.CompressionMethod = compressionMethod;
            cd.LastModFileTime = lastModFileTime;
            cd.LastModFileDate = lastModFileDate;
            cd.Crc32 = crc32;
            cd.CompressedLength = compressedLengthVal;
            cd.UncompressedLength = uncompressedLengthVal;
            cd.FileNameLength = fileNameLength;
            cd.ExtraFieldLength = (ushort)(extraFieldCount * 12);
            cd.FileCommentLength = 0;
            cd.DiskNumberStart = 0;
            cd.InternalFileAttributes = 0;
            cd.ExternalFileAttributes = 0;
            cd.LocalHeaderOffset = localHeaderOffsetVal;
        }

        stream.Write(buffer[..CentralDirectory.MinLength]);
        Encoding.ASCII.GetBytes(entryName, buffer);
        stream.Write(buffer[..fileNameLength]);
        long extraFieldLength = WriteZip64ExtraFields(stream, extraFields[..extraFieldCount], buffer);

        return CentralDirectory.MinLength + fileNameLength + extraFieldLength;
    }

    private static long WriteZip64ExtraFields(
        Stream stream,
        ReadOnlySpan<long> values,
        Span<byte> buffer)
    {
        Debug.Assert(
            buffer.Length >= 12,
            "The buffer must be large enough to hold the ZIP64 extra field header and one value.");

        foreach (long v in values)
        {
            // ZIP64 extra field format:
            //   2 bytes: Header ID (0x0001 for ZIP64)
            //   2 bytes: Data Size (8 for each 64-bit value)
            //   8 bytes: Value
            {
                ref ExtraField extraField = ref MemoryMarshal.AsRef<ExtraField>(buffer);
                extraField.HeaderId = ExtraField.Zip64ExtendedInformation;
                extraField.DataLength = 8;
            }
            BinaryPrimitives.WriteInt64LittleEndian(buffer[4..12], v);

            stream.Write(buffer[..12]);
        }

        return 12 * values.Length;
    }

    private static void CopyEocd64(
        Stream srcStream,
        Stream dstStream,
        long eocd64Length,
        long cdOffset,
        long cdLength,
        long cdCount,
        Span<byte> buffer)
    {
        Span<byte> eocd64Buffer = buffer[..EndOfCentralDirectory64.MinLength];
        srcStream.ReadExactly(eocd64Buffer);
        {
            ref EndOfCentralDirectory64 eocd64 = ref MemoryMarshal.AsRef<EndOfCentralDirectory64>(eocd64Buffer);
            eocd64.CentralDirectoryRecordsOnDisk = cdCount;
            eocd64.CentralDirectoryTotalRecords = cdCount;
            eocd64.CentralDirectoryLength = cdLength;
            eocd64.CentralDirectoryOffset = cdOffset;
        }
        dstStream.Write(eocd64Buffer);

        CopyStreamTo(srcStream, dstStream, eocd64Length - EndOfCentralDirectory64.MinLength, buffer);
    }

    private static void CopyEocd64Locator(
        Stream srcStream,
        Stream dstStream,
        long eocd64Offset,
        Span<byte> buffer)
    {
        Span<byte> eocd64LocatorBuffer = buffer[..EndOfCentralDirectory64Locator.MinLength];
        srcStream.ReadExactly(eocd64LocatorBuffer);
        {
            ref EndOfCentralDirectory64Locator eocd64Locator = ref MemoryMarshal.AsRef<EndOfCentralDirectory64Locator>(
                eocd64LocatorBuffer);
            eocd64Locator.EndOfCentralDirectoryOffset = eocd64Offset;
        }
        dstStream.Write(eocd64LocatorBuffer);
    }

    private static void CopyEocd(
        Stream srcStream,
        Stream dstStream,
        uint cdOffset,
        uint cdLength,
        ushort cdCount,
        Span<byte> buffer)
    {
        Span<byte> eocdBuffer = buffer[..EndOfCentralDirectory.MinLength];
        srcStream.ReadExactly(eocdBuffer);
        {
            ref EndOfCentralDirectory eocd = ref MemoryMarshal.AsRef<EndOfCentralDirectory>(eocdBuffer);
            eocd.CentralDirectoryOffset = cdOffset;
            eocd.CentralDirectoryLength = cdLength;
            eocd.CentralDirectoryTotalRecords = cdCount;
            eocd.CentralDirectoryRecordsOnDisk = cdCount;
        }

        dstStream.Write(eocdBuffer);
        srcStream.CopyTo(dstStream);
    }

    private static void CopyStreamTo(
        Stream src,
        Stream dst,
        long bytesToCopy,
        Span<byte> buffer)
    {
        while (bytesToCopy > 0)
        {
            int read = src.Read(buffer);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected end of stream while copying.");
            }

            dst.Write(buffer[..read]);
            bytesToCopy -= read;
        }
    }
}

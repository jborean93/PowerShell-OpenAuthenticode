using System;
using System.Buffers.Binary;
using System.IO;

namespace OpenAuthenticode;

/// <summary>
/// Provides low-level ZIP structure parsing operations.
/// </summary>
internal static class ZipStructure
{
    private const uint EOCD_SIGNATURE = 0x06054b50;
    private const uint ZIP64_EOCD_LOCATOR_SIGNATURE = 0x07064b50;
    private const uint ZIP64_EOCD_SIGNATURE = 0x06064b50;
    private const uint CENTRAL_DIR_SIGNATURE = 0x02014b50;

    private const int EOCD_MIN_SIZE = 22;
    private const int ZIP64_EOCD_LOCATOR_SIZE = 20;
    private const int ZIP64_EOCD_MIN_SIZE = 56;
    private const int CENTRAL_DIR_HEADER_SIZE = 46;

    /// <summary>
    /// Finds the offset of the central directory in the ZIP archive.
    /// </summary>
    public static long FindCentralDirectoryOffset(ReadOnlySpan<byte> zipData)
    {
        long eocdPos = FindEocdPosition(zipData);
        if (eocdPos == -1)
            throw new InvalidDataException("Could not find End of Central Directory record in ZIP");

        // Read CD offset from EOCD
        uint cdOffset32 = BinaryPrimitives.ReadUInt32LittleEndian(zipData.Slice((int)(eocdPos + 16), 4));

        // Check for ZIP64
        if (cdOffset32 == 0xFFFFFFFF)
        {
            long zip64EocdOffset = FindZip64EocdOffset(zipData, eocdPos);
            return BinaryPrimitives.ReadInt64LittleEndian(zipData.Slice((int)(zip64EocdOffset + 48), 8));
        }

        return cdOffset32;
    }

    /// <summary>
    /// Finds the size of the central directory in the ZIP archive.
    /// </summary>
    public static long FindCentralDirectorySize(ReadOnlySpan<byte> zipData)
    {
        long eocdPos = FindEocdPosition(zipData);
        if (eocdPos == -1)
            throw new InvalidDataException("Could not find End of Central Directory record in ZIP");

        uint cdSize32 = BinaryPrimitives.ReadUInt32LittleEndian(zipData.Slice((int)(eocdPos + 12), 4));

        // Check for ZIP64
        if (cdSize32 == 0xFFFFFFFF)
        {
            long zip64EocdOffset = FindZip64EocdOffset(zipData, eocdPos);
            return BinaryPrimitives.ReadInt64LittleEndian(zipData.Slice((int)(zip64EocdOffset + 40), 8));
        }

        return cdSize32;
    }

    /// <summary>
    /// Finds the total number of entries in the ZIP archive.
    /// </summary>
    public static long FindTotalEntries(ReadOnlySpan<byte> zipData)
    {
        long eocdPos = FindEocdPosition(zipData);
        if (eocdPos == -1)
            throw new InvalidDataException("Could not find End of Central Directory record");

        ushort totalEntries16 = BinaryPrimitives.ReadUInt16LittleEndian(zipData.Slice((int)(eocdPos + 10), 2));

        if (totalEntries16 != 0xFFFF)
            return totalEntries16;

        // ZIP64 format
        long zip64EocdOffset = FindZip64EocdOffset(zipData, eocdPos);
        return BinaryPrimitives.ReadInt64LittleEndian(zipData.Slice((int)(zip64EocdOffset + 32), 8));
    }

    /// <summary>
    /// Finds a central directory entry by file name.
    /// </summary>
    /// <returns>The offset and size of the CD entry, and the local header offset. Returns (-1, -1, 0) if not found.</returns>
    public static (long cdOffset, long cdSize, uint localHeaderOffset) FindCentralDirectoryEntry(
        ReadOnlySpan<byte> zipData,
        ReadOnlySpan<byte> fileName)
    {
        long cdOffset = FindCentralDirectoryOffset(zipData);
        long cdSize = FindCentralDirectorySize(zipData);
        long cdEnd = cdOffset + cdSize;

        long position = cdOffset;
        while (position < cdEnd && position + CENTRAL_DIR_HEADER_SIZE <= zipData.Length)
        {
            uint sig = BinaryPrimitives.ReadUInt32LittleEndian(zipData.Slice((int)position, 4));
            if (sig != CENTRAL_DIR_SIGNATURE)
                break;

            ushort fileNameLen = BinaryPrimitives.ReadUInt16LittleEndian(zipData.Slice((int)(position + 28), 2));
            ushort extraLen = BinaryPrimitives.ReadUInt16LittleEndian(zipData.Slice((int)(position + 30), 2));
            ushort commentLen = BinaryPrimitives.ReadUInt16LittleEndian(zipData.Slice((int)(position + 32), 2));
            uint localHeaderOffset = BinaryPrimitives.ReadUInt32LittleEndian(zipData.Slice((int)(position + 42), 4));

            int entrySize = CENTRAL_DIR_HEADER_SIZE + fileNameLen + extraLen + commentLen;
            if (position + entrySize > zipData.Length)
                break;

            ReadOnlySpan<byte> entryFileName = zipData.Slice((int)(position + CENTRAL_DIR_HEADER_SIZE), fileNameLen);
            if (entryFileName.SequenceEqual(fileName))
            {
                return (position, entrySize, localHeaderOffset);
            }

            position += entrySize;
        }

        return (-1, -1, 0);
    }

    private static long FindEocdPosition(ReadOnlySpan<byte> zipData)
    {
        // Search backwards from end of file for EOCD signature
        for (long i = zipData.Length - EOCD_MIN_SIZE; i >= 0; i--)
        {
            uint sig = BinaryPrimitives.ReadUInt32LittleEndian(zipData.Slice((int)i, 4));
            if (sig == EOCD_SIGNATURE)
                return i;
        }

        return -1;
    }

    private static long FindZip64EocdOffset(ReadOnlySpan<byte> zipData, long eocdPos)
    {
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

    private static int FindEndOfCentralDirectoryOffset(ReadOnlySpan<byte> data)
    {
        const int EOCD_MIN_SIZE = 22;
        ReadOnlySpan<byte> signature = [0x50, 0x4b, 0x05, 0x06]; // EOCD signature

        while (true)
        {
            int pos = data.LastIndexOf(signature);
            if (pos == -1)
            {
                return -1;
            }

            if (data.Length - pos < EOCD_MIN_SIZE)
            {
                // Checks the signature isn't in the comment field which can
                // contain arbitrary data. If the signature is found but
                // there's not enough space for a valid EOCD record we should
                // continue to search for the next occurrence of the signature.
                data = data[..pos];
                continue;
            }

            // We need to also verify that we aren't in the comment field of
            // the EOCD record. This verifies that the offset at 20 shows the
            // comment length and that it fits into the remaining data.
            ushort commentLen = BinaryPrimitives.ReadUInt16LittleEndian(
                data.Slice(pos + 20, 2));

            if (pos + EOCD_MIN_SIZE + commentLen <= data.Length)
            {
                // FIXME: We need to verify that the previous data is part of a
                // valid ZIP structure or just accept that we cannot handle a
                // comment containing a valid EOCD record to ignore.
                return pos;
            }

            data = data[..pos];
        }
    }
}

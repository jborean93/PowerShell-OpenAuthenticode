using System.Runtime.InteropServices;

namespace OpenAuthenticode.Zip;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct LocalFileHeader
{
    public const int Signature = 0x04034b50;
    public const int DataDescriptorSignature = 0x08074b50;
    public const int MinLength = 30;

    public int LFHSignature;
    public short VersionNeededToExtract;
    public ZipFlags Flags;
    public short CompressionMethod;
    public ushort LastModFileTime;
    public ushort LastModFileDate;
    public uint Crc32;
    public uint CompressedLength;
    public uint UncompressedLength;
    public ushort FileNameLength;
    public ushort ExtraFieldLength;

    // Followed by:
    // FileName (variable size)
    // ExtraField (variable size)
    // DataDescriptor (optional if DataDescriptorFlag is set in Flags here or in the CD)
}

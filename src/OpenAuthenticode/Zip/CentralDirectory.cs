using System.Runtime.InteropServices;

namespace OpenAuthenticode.Zip;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct CentralDirectory
{
    public const int Signature = 0x02014b50;
    public const int MinLength = 46;

    public int CDSignature;
    public short VersionMadeBy;
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
    public ushort FileCommentLength;
    public short DiskNumberStart;
    public short InternalFileAttributes;
    public int ExternalFileAttributes;
    public uint LocalHeaderOffset;

    // Followed by:
    // FileName (variable size)
    // ExtraField (variable size)
    // FileComment (variable size)
}

using System.Runtime.InteropServices;

namespace OpenAuthenticode.Zip;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct EndOfCentralDirectory
{
    public const int Signature = 0x06054b50;
    public const int MinLength = 22;

    public int EOCDSignature;
    public ushort DiskNumber;
    public short CentralDirectoryStartDisk;
    public ushort CentralDirectoryRecordsOnDisk;
    public ushort CentralDirectoryTotalRecords;
    public uint CentralDirectoryLength;
    public uint CentralDirectoryOffset;
    public ushort CommentLength;

    // Followed by:
    // Comment (variable size)
}

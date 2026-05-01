using System.Runtime.InteropServices;

namespace OpenAuthenticode.Zip;

// While int values are meant to be unsigned, long.MaxValue is beyond most
// practical limits and makes our interop with .NET easier to deal with.

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct EndOfCentralDirectory64
{
    public const int Signature = 0x06064b50;
    public const int MinLength = 56;

    public int EOCDSignature;
    public long SizeOfRecord;
    public short VersionMadeBy;
    public short VersionNeededToExtract;
    public int DiskNumber;
    public int CentralDirectoryStartDisk;
    public long CentralDirectoryRecordsOnDisk;
    public long CentralDirectoryTotalRecords;
    public long CentralDirectoryLength;
    public long CentralDirectoryOffset;

    // Followed by:
    // Zip64 extensible data sector (variable size)
}

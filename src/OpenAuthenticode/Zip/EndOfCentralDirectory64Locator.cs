using System.Runtime.InteropServices;

namespace OpenAuthenticode.Zip;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct EndOfCentralDirectory64Locator
{
    public const int Signature = 0x07064b50;
    public const int MinLength = 20;

    public int EOCD64LocatorSignature;
    public int DiskNumber;
    public long EndOfCentralDirectoryOffset;  // While unsigned .NET uses long for file offsets.
    public int TotalNumberOfDisks;
}

using System;

namespace OpenAuthenticode.Zip;

[Flags]
internal enum ZipFlags : short
{
    None = 0x0000,
    Encrypted = 0x0001,
    Compression1 = 0x0002,
    Compression2 = 0x0004,
    DataDescriptor = 0x0008,
    EnhancedDeflation = 0x0010,
    CompressedPatchedData = 0x0020,
    StrongEncryption = 0x0040,
    Reserved7 = 0x0080,
    Reserved8 = 0x0100,
    Reserved9 = 0x0200,
    Reserved10 = 0x0400,
    UTF8Encoding = 0x0800,
    Reserved12 = 0x1000,
    CentralDirectoryEncrypted = 0x2000,
    Reserved14 = 0x4000,
    Reserved15 = unchecked((short)0x8000),
}

using System.Runtime.InteropServices;

namespace OpenAuthenticode.Zip;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct ExtraField
{
    public const short Zip64ExtendedInformation = 0x0001;

    public short HeaderId;
    public ushort DataLength;

    // Followed by:
    // Data (variable size)
}

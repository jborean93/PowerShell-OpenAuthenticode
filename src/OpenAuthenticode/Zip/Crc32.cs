using System;
using System.IO;

namespace OpenAuthenticode.Zip;

internal static class Crc32
{
    private const uint Polynomial = 0xEDB88320;

    private static readonly uint[] Table = CreateTable();

    public static uint Compute(
        Stream stream,
        Span<byte> buffer)
    {
        uint crc = 0xFFFFFFFF;

        int bytesRead;
        while ((bytesRead = stream.Read(buffer)) > 0)
        {
            foreach (byte b in buffer[..bytesRead])
            {
                crc = (crc >> 8) ^ Table[(crc ^ b) & 0xFF];
            }
        }


        return ~crc;
    }

    private static uint[] CreateTable()
    {
        var table = new uint[256];

        for (uint i = 0; i < table.Length; i++)
        {
            uint crc = i;

            for (int j = 0; j < 8; j++)
            {
                if ((crc & 1) != 0)
                {
                    crc = (crc >> 1) ^ Polynomial;
                }
                else
                {
                    crc >>= 1;
                }
            }

            table[i] = crc;
        }

        return table;
    }
}

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace OpenAuthenticode.Providers;

internal ref struct WIN_CERTIFICATE
{
    public const short WIN_CERT_REVISION_1_0 = 0x0100;
    public const short WIN_CERT_REVISION_2_0 = 0x0200;
    public const short WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002;

    /*
    typedef struct _WIN_CERTIFICATE
    {
        DWORD       dwLength;
        WORD        wRevision;
        WORD        wCertificateType;
        BYTE        bCertificate[ANYSIZE_ARRAY];
    } WIN_CERTIFICATE, *LPWIN_CERTIFICATE;
    */

    public int Length;
    public short Revision;
    public short CertificateType;
    public ReadOnlySpan<byte> Certificate;

    public WIN_CERTIFICATE(ReadOnlySpan<byte> data)
    {
        Length = BinaryPrimitives.ReadInt32LittleEndian(data);
        Revision = BinaryPrimitives.ReadInt16LittleEndian(data[4..]);
        CertificateType = BinaryPrimitives.ReadInt16LittleEndian(data[6..]);
        Certificate = data.Slice(8, Length - 8);
    }
}

internal sealed record PEMetadata(
    int ChecksumOffset,
    int CertificateTableOffset,
    int CertificateOffset,
    int CertificateLength,
    int SizeOfHeaders,
    int CertificateTableSize,
    SectionHeader[] SectionHeaders);

/// <summary>
/// Authenticode providers for PE binary file <c>.dll></c> and <c>.exe</c>.
/// </summary>
internal class PEBinaryProvider : AuthenticodeProviderBase
{
    private readonly PEMetadata _metadata;

    public override AuthenticodeProvider Provider => AuthenticodeProvider.PEBinary;

    internal static string[] FileExtensions => [".dll", ".exe"];

    /// <summary>
    /// Factory to create the PEBinaryProvider.
    /// </summary>
    /// <param name="stream">The Stream containing PE binary data. Must be readable and seekable.
    /// Stream position is expected to be at 0 (handled by ProviderFactory).</param>
    /// <param name="leaveOpen">Whether to leave the Stream open when the provider is disposed</param>
    /// <returns>The PEBinaryProvider</returns>
    public static PEBinaryProvider Create(Stream stream, bool leaveOpen)
    {
        // Stream validation and position reset handled by ProviderFactory
        // Use LeaveOpen and PrefetchMetadata to only read metadata, not entire file
        using PEReader reader = new(stream, PEStreamOptions.LeaveOpen | PEStreamOptions.PrefetchMetadata);
        PEHeader header = reader.PEHeaders.PEHeader
            ?? throw new ArgumentException("PE data supplied is not an expected PE file");
        int headerOffset = reader.PEHeaders.PEHeaderStartOffset;
        int checksumOffset = headerOffset + 64;
        int certTableOffset = headerOffset + (header.Magic == PEMagic.PE32 ? 128 : 144);

        // Get Stream length for certificate offset
        long streamLength = stream.Length;
        int certificateOffset = (int)streamLength;
        int certificateLength = 0;

        DirectoryEntry certTable = header.CertificateTableDirectory;
        byte[] signature = [];
        if (certTable.RelativeVirtualAddress > 0 &&
            certTable.Size > 12 &&
            (streamLength - certTable.RelativeVirtualAddress) >= certTable.Size)
        {
            // Read only the certificate table data
            stream.Position = certTable.RelativeVirtualAddress;
            byte[] certificateTableData = new byte[certTable.Size];
            stream.ReadExactly(certificateTableData);

            WIN_CERTIFICATE info = new(certificateTableData);
            if (
                (
                    info.Revision != WIN_CERTIFICATE.WIN_CERT_REVISION_1_0 &&
                    info.Revision != WIN_CERTIFICATE.WIN_CERT_REVISION_2_0
                ) ||
                info.CertificateType != WIN_CERTIFICATE.WIN_CERT_TYPE_PKCS_SIGNED_DATA)
            {
                string msg = string.Format("Unknown PE certificate revision 0x{0:X4} or type 0x{1:X4}",
                    info.Revision, info.CertificateType);
                throw new ArgumentException(msg);
            }

            certificateOffset = header.CertificateTableDirectory.RelativeVirtualAddress;
            certificateLength = info.Length - 8;
            signature = info.Certificate.ToArray();
        }

        // Extract needed metadata from PEReader before disposing
        PEMetadata extraMetadata = new(
            ChecksumOffset: checksumOffset,
            CertificateTableOffset: certTableOffset,
            CertificateOffset: certificateOffset,
            CertificateLength: certificateLength,
            SizeOfHeaders: header.SizeOfHeaders,
            CertificateTableSize: certTable.Size,
            SectionHeaders: [.. reader.PEHeaders.SectionHeaders]);

        return new PEBinaryProvider(stream, leaveOpen, signature, extraMetadata);
    }

    private PEBinaryProvider(Stream stream, bool leaveOpen, byte[] signature, PEMetadata metadata)
        : base(stream, leaveOpen)
    {
        Signature = signature;
        _metadata = metadata;
    }

    public override SpcIndirectData HashData(Oid digestAlgorithm)
    {
        HashAlgorithmName algoName = HashAlgorithmName.FromOid(digestAlgorithm.Value ?? "");

        byte[] fileHash;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            using IncrementalHash algo = IncrementalHash.CreateHash(algoName);

            // Hash up to certificate table offset, excluding checksum (4 bytes) and certificate table entry (8 bytes)
            // First exclude the checksum
            HashStreamRangeWithExclusion(algo, 0, _metadata.CertificateTableOffset, _metadata.ChecksumOffset, sizeof(uint), buffer);

            // Hash the remaining data in the headers excluding the Certificate Table entry.
            int offset = _metadata.CertificateTableOffset + 8;
            int length = _metadata.SizeOfHeaders - offset;
            HashStreamRange(algo, offset, length, buffer);

            // Process each section where the SizeOfRawData is greater than 1 and order by the data offset.
            int sumOfBytesHashed = _metadata.SizeOfHeaders;
            foreach (SectionHeader section in _metadata.SectionHeaders
                .Where(h => h.SizeOfRawData > 0)
                .OrderBy(h => h.PointerToRawData))
            {
                HashStreamRange(algo, section.PointerToRawData, section.SizeOfRawData, buffer);
                sumOfBytesHashed += section.SizeOfRawData;
            }

            // Hash the remaining data beyond the Attribute Certificate Table
            int remainingLength = (int)Stream.Length - (_metadata.CertificateTableSize + sumOfBytesHashed);
            if (remainingLength > 0)
            {
                HashStreamRange(algo, sumOfBytesHashed, remainingLength, buffer);
            }

            // If the file hasn't been signed yet, check to see if padding will
            // be needed on the final file and include it in the hash.
            int paddingLength = (8 - ((sumOfBytesHashed + remainingLength) & 7)) & 7;
            if (_metadata.CertificateLength == 0 && paddingLength > 0)
            {
                byte[] padding = new byte[paddingLength];
                algo.AppendData(padding);
            }

            fileHash = algo.GetCurrentHash();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        SpcPeImageData imageData = new SpcPeImageData(
            SpcPeImageFlags.IncludeResources,
            new SpcLink(File: new SpcString(Unicode: "")));

        return new(
            DataType: SpcPeImageData.OID,
            Data: imageData.GetBytes(),
            DigestAlgorithm: digestAlgorithm,
            DigestParameters: null,
            Digest: fileHash);
    }

    public override AsnEncodedData[] GetAttributesToSign()
    {
        SpcSpOpusInfo opusInfo = new(new SpcString(Unicode: ""), new SpcLink(Url: ""));
        SpcStatementType statementType = new([
            new Oid("1.3.6.1.4.1.311.2.1.21", "SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID"),
        ]);

        return [
            new AsnEncodedData(SpcSpOpusInfo.OID, opusInfo.GetBytes()),
            new AsnEncodedData(SpcStatementType.OID, statementType.GetBytes())
        ];
    }

    [SkipLocalsInit]
    public override void Save()
    {
        Stream.SetLength(_metadata.CertificateOffset);

        Span<byte> buffer = stackalloc byte[8];
        buffer.Clear();

        if (Signature.Length == 0)
        {
            Stream.Seek(_metadata.CertificateTableOffset, SeekOrigin.Begin);
            Stream.Write(buffer);
        }
        else
        {
            // Calculate padding to align to 8-byte boundary
            int padding = (8 - (_metadata.CertificateOffset & 7)) & 7;
            int signaturePadding = (8 - (Signature.Length & 7)) & 7;

            // Write padding at end if needed
            Stream.Seek(0, SeekOrigin.End);
            if (padding > 0)
            {
                Stream.Write(buffer[..padding]);
            }

            // Write WIN_CERTIFICATE structure
            BinaryPrimitives.WriteInt32LittleEndian(buffer[..4], Signature.Length + signaturePadding + 8);
            BinaryPrimitives.WriteInt16LittleEndian(buffer[4..6], WIN_CERTIFICATE.WIN_CERT_REVISION_2_0);
            BinaryPrimitives.WriteInt16LittleEndian(buffer[6..8], WIN_CERTIFICATE.WIN_CERT_TYPE_PKCS_SIGNED_DATA);
            Stream.Write(buffer);
            Stream.Write(Signature);

            if (signaturePadding > 0)
            {
                Span<byte> paddingBuffer = buffer[..signaturePadding];
                paddingBuffer.Clear();
                Stream.Write(paddingBuffer);
            }

            // Update certificate table entry at the specified offset
            Stream.Seek(_metadata.CertificateTableOffset, SeekOrigin.Begin);
            BinaryPrimitives.WriteInt32LittleEndian(buffer[..4], _metadata.CertificateOffset + padding);
            BinaryPrimitives.WriteInt32LittleEndian(buffer[4..8], Signature.Length + signaturePadding + 8);
            Stream.Write(buffer);
        }
    }
}

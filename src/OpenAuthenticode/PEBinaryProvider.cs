using System;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;

namespace OpenAuthenticode;

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
        Length = BitConverter.ToInt32(data);
        Revision = BitConverter.ToInt16(data[4..]);
        CertificateType = BitConverter.ToInt16(data[6..]);
        Certificate = data.Slice(8, Length - 8);
    }
}

internal sealed record PEMetadata(int ChecksumOffset, int CertificateTableOffset, int CertificateOffset, int CertificateLength);

/// <summary>
/// Authenticode providers for PE binary file <c>.dll></c> and <c>.exe</c>.
/// </summary>
internal class PEBinaryProvider : IAuthenticodeProvider
{
    private readonly byte[] _content;
    private readonly PEReader _reader;
    private readonly PEHeader _header;
    private readonly PEMetadata _metadata;

    public AuthenticodeProvider Provider => AuthenticodeProvider.PEBinary;

    internal static string[] FileExtensions => new[] { ".dll", ".exe" };

    /// <summary>
    /// Factory to create the PEBinaryProvider.
    /// </summary>
    /// <param name="data">The raw script bytes to manage</param>
    /// <param name="fileEncoding">Encoding hint of the data provided</param>
    /// <returns>The PEBinaryProvider></returns>
    public static PEBinaryProvider Create(byte[] data, Encoding? fileEncoding)
    {
        using MemoryStream ms = new(data);
        PEReader reader = new(ms, PEStreamOptions.PrefetchEntireImage);
        PEHeader? header = reader.PEHeaders.PEHeader;
        if (header == null)
        {
            throw new ArgumentException("PE data supplied is not an expected PE file");
        }

        int headerOffset = reader.PEHeaders.PEHeaderStartOffset;
        int checksumOffset = headerOffset + 64;
        int certTableOffset = headerOffset + (header.Magic == PEMagic.PE32 ? 128 : 144);
        int certificateOffset = data.Length;
        int certificateLength = 0;

        DirectoryEntry certTable = header.CertificateTableDirectory;
        byte[] signature = Array.Empty<byte>();
        if (certTable.RelativeVirtualAddress > 0 &&
            certTable.Size > 12 &&
            (data.Length - certTable.RelativeVirtualAddress) >= certTable.Size)
        {
            ReadOnlySpan<byte> certificateTable = data.AsSpan(
                certTable.RelativeVirtualAddress,
                certTable.Size);
            WIN_CERTIFICATE info = new(certificateTable);
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

        PEMetadata extraMetadata = new(
            ChecksumOffset: checksumOffset,
            CertificateTableOffset: certTableOffset,
            CertificateOffset: certificateOffset,
            CertificateLength: certificateLength);
        return new PEBinaryProvider(data, signature, reader, header, extraMetadata);
    }

    public byte[] Signature { get; set; }

    private PEBinaryProvider(byte[] content, byte[] signature, PEReader peReader, PEHeader header,
        PEMetadata certificateTable)
    {
        Signature = signature;
        _content = content;
        _reader = peReader;
        _header = header;
        _metadata = certificateTable;
    }

    public ContentInfo CreateContent(Oid digestAlgorithm)
    {
        SpcIndirectData data = HashData(digestAlgorithm);

        return new(SpcIndirectData.OID, data.GetBytes());
    }

    public void VerifyContent(ContentInfo content, Oid digestAlgorithm)
    {
        SpcIndirectData expectedContent = HashData(digestAlgorithm);
        expectedContent.Validate(content.ContentType, content.Content);
    }

    public void Save(string path)
    {
        using FileStream fs = File.OpenWrite(path);
        fs.SetLength(_metadata.CertificateOffset);

        // Ensure we clear out the existing signature by trimming the end of
        // the file.
        fs.Seek(_metadata.CertificateTableOffset, SeekOrigin.Begin);

        if (Signature.Length == 0)
        {
            fs.Write(new byte[8]);
        }
        else
        {
            // Ensure the PE binary is padded to a quadword offset before
            // adding the certificate info.
            int padding = (8 - ((int)fs.Length & 7)) & 7;
            int signaturePadding = (8 - ((int)Signature.Length & 7)) & 7;

            fs.Write(BitConverter.GetBytes((int)fs.Length + padding));
            fs.Write(BitConverter.GetBytes(Signature.Length + signaturePadding + 8));

            fs.Seek(0, SeekOrigin.End);
            if (padding > 0)
            {
                fs.Write(new byte[padding]);
            }

            fs.Write(BitConverter.GetBytes(Signature.Length + signaturePadding + 8));
            fs.Write(BitConverter.GetBytes((short)WIN_CERTIFICATE.WIN_CERT_REVISION_2_0));
            fs.Write(BitConverter.GetBytes((short)WIN_CERTIFICATE.WIN_CERT_TYPE_PKCS_SIGNED_DATA));
            fs.Write(Signature);
            if (signaturePadding > 0)
            {
                fs.Write(new byte[signaturePadding]);
            }
        }
    }

    private SpcIndirectData HashData(Oid digestAlgorithm)
    {
        byte[] fileHash;
        HashAlgorithmName algoName = HashAlgorithmName.FromOid(digestAlgorithm.Value ?? "");
        using (IncrementalHash algo = IncrementalHash.CreateHash(algoName))
        {
            // First hash up to the checksum field and skip the checksum
            algo.AppendData(_content, 0, _metadata.ChecksumOffset);
            int offset = _metadata.ChecksumOffset + sizeof(uint);

            // Hash everything from the end of the checksum to the start of the Certificate Table entry.
            algo.AppendData(_content, offset, _metadata.CertificateTableOffset - offset);
            offset = _metadata.CertificateTableOffset + 8;

            // Hash the remaining data in the headers excluding the Certificate Table entry.
            algo.AppendData(_content, offset, _header.SizeOfHeaders - offset);

            // Process each section where the SizeOfRawData is greater than 1 and order by the data offset.
            int sumOfBytesHashed = _header.SizeOfHeaders;
            foreach (SectionHeader section in _reader.PEHeaders.SectionHeaders
                .Where(h => h.SizeOfRawData > 0)
                .OrderBy(h => h.PointerToRawData))
            {
                algo.AppendData(_content, section.PointerToRawData, section.SizeOfRawData);
                sumOfBytesHashed += section.SizeOfRawData;
            }

            // Hash the remaining data beyond the Attribute Certificate Table
            int remainingLength = _content.Length - ((_header.CertificateTableDirectory.Size) + sumOfBytesHashed);
            if (remainingLength > 0)
            {
                algo.AppendData(_content, sumOfBytesHashed, remainingLength);
            }

            // If the file hasn't been singed yet, check to see if padding will
            // be needed on the final file and include it in the hash.
            int paddingLength = (8 - ((sumOfBytesHashed + remainingLength) & 7)) & 7;
            if (_metadata.CertificateLength == 0 && paddingLength > 0)
            {
                byte[] padding = new byte[paddingLength];
                algo.AppendData(padding);
            }

            fileHash = algo.GetCurrentHash();
        }

        SpcPeImageData imageData = new SpcPeImageData(
            SpcPeImageFlags.IncludeResources,
            new SpcLink(File: new SpcString(Unicode: "")));

        return new(
            DataType: SpcPeImageData.OID,
            Data: imageData.GetBytes(),
            DigestAlgorithm: digestAlgorithm,
            DigestParameters: null,
            Digest: fileHash
        );
    }
}

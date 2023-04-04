using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;

namespace OpenAuthenticode;

internal abstract class PowerShellProvider : IAuthenticodeProvider
{
    private readonly Guid _pwshSip = new("603bcc1f-4b59-4e08-b724-d2c6297ef351");
    protected const string _startSig = "SIG # Begin signature block";
    protected const string _endSig = "SIG # End signature block";

    private byte[] _content;
    private Encoding _fileEncoding;

    public byte[] Signature { get; set; }

    protected abstract string StartComment { get; }

    protected abstract string EndComment { get; }

    public abstract AuthenticodeProvider Provider { get; }

    protected PowerShellProvider(byte[] data, Encoding? fileEncoding)
    {
        if (fileEncoding == null)
        {
            using (MemoryStream dataMs = new(data, 0, Math.Max(data.Length, 8)))
            using (StreamReader reader = new(dataMs, true))
            {
                reader.Read();
                fileEncoding = reader.CurrentEncoding;
            }
        }

        // We need to use GetString as StreamReader will remove the BOM if
        // present. GetString preserves the BOM in the string which is
        // important as it's part of the data to be hashed.
        string scriptText = fileEncoding.GetString(data);
        ReadOnlySpan<char> scriptData = new(scriptText.ToCharArray());

        string startSig = $"{StartComment}{_startSig}{EndComment}";
        string endSig = $"{StartComment}{_endSig}{EndComment}";

        int signatureIdx = scriptData.IndexOf(new ReadOnlySpan<char>($"\r\n{startSig}".ToCharArray()));

        byte[] hashableData;
        Signature = Array.Empty<byte>();
        if (signatureIdx != -1)
        {
            ReadOnlySpan<char> scriptContents = scriptData[..signatureIdx];
            hashableData = Encoding.Unicode.GetBytes(scriptContents.ToArray());

            ReadOnlySpan<char> signatureBlock = scriptData[(signatureIdx + startSig.Length + 4)..];
            int endSignatureIdx = signatureBlock.IndexOf(new ReadOnlySpan<char>($"\r\n{endSig}".ToCharArray()));
            if (IsValidEndBlock(signatureBlock, endSignatureIdx, endSig.Length))
            {
                signatureBlock = signatureBlock[..endSignatureIdx];

                StringBuilder base64Signature = new();
                foreach (ReadOnlySpan<char> line in signatureBlock.EnumerateLines())
                {
                    ReadOnlySpan<char> b64Line = line[StartComment.Length..(line.Length - EndComment.Length)];
                    base64Signature.Append(b64Line);
                }

                Signature = Convert.FromBase64String(base64Signature.ToString());
            }
        }
        else
        {
            hashableData = Encoding.Unicode.GetBytes(scriptText);
        }

        _content = hashableData;
        _fileEncoding = fileEncoding;
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
        string content = Encoding.Unicode.GetString(_content); ;
        if (Signature.Length > 0)
        {
            StringBuilder signatureContent = new();
            signatureContent.Append($"\r\n{StartComment}{_startSig}{EndComment}\r\n");
            ReadOnlySpan<char> b64Sig = new(Convert.ToBase64String(Signature).ToCharArray());
            while (b64Sig.Length > 0)
            {
                int lineLength = Math.Min(b64Sig.Length, 64);
                signatureContent.AppendFormat("{0}{1}{2}\r\n", StartComment, b64Sig[..lineLength].ToString(),
                    EndComment);
                b64Sig = b64Sig[lineLength..];
            }

            signatureContent.Append($"{StartComment}{_endSig}{EndComment}\r\n");
            content += signatureContent.ToString();
        }

        // The content already contains the original BOM chars so ensure that
        // the _fileEncoding doesn't add another one breaking the signature.
        File.WriteAllText(path, content, new BOMLessEncoding(_fileEncoding));
    }

    private SpcIndirectData HashData(Oid digestAlgorithm)
    {
        byte[] fileHash;
        HashAlgorithmName algoName = HashAlgorithmName.FromOid(digestAlgorithm.Value ?? "");
        using (IncrementalHash algo = IncrementalHash.CreateHash(algoName))
        {
            algo.AppendData(_content);
            fileHash = algo.GetCurrentHash();
        }

        return new(
            DataType: SpcSipInfo.OID,
            Data: new SpcSipInfo(0x10000, _pwshSip).GetBytes(),
            DigestAlgorithm: digestAlgorithm,
            DigestParameters: null,
            Digest: fileHash
        );
    }

    private static bool IsValidEndBlock(ReadOnlySpan<char> block, int endIdx, int endBlockLength)
    {
        // Ensures the end signature block is valid and that it is at the end
        // of the file with 1 or 2 newline chars (\r or \n). Authenticode on
        // Win doesn't seem to care whether it ends on a proper newline, just
        // that it's some combination of 1 or 2 \r, \n chars.
        if (endIdx == -1)
        {
            return false;
        }

        string[] validEndlineCandidates = new[] { "\r", "\n", "\r\n", "\n\r", "\r\r", "\n\n" };
        string remaining = block.Slice(endIdx + endBlockLength + 2).ToString();
        return Array.Exists(validEndlineCandidates, c => c == remaining);
    }
}

/// <summary>
/// Authenticode providers for PowerShell script files. This includes files
/// with the extensions <c>.ps1</c>, <c>.psd1</c>, and <c>.psm1</c>.
/// </summary>
internal class PowerShellScriptProvider : PowerShellProvider
{
    public override AuthenticodeProvider Provider => AuthenticodeProvider.PowerShell;

    internal static string[] FileExtensions => new[] { ".ps1", ".psd1", ".psm1" };

    protected override string StartComment => "# ";

    protected override string EndComment => "";

    public static PowerShellScriptProvider Create(byte[] data, Encoding? fileEncoding)
        => new PowerShellScriptProvider(data, fileEncoding);

    private PowerShellScriptProvider(byte[] data, Encoding? fileEncoding) : base(data, fileEncoding)
    {}
}

/// <summary>
/// Authenticode providers for PowerShell XML files. This includes files
/// with the extensions <c>.psc1</c> and <c>.psm1xml</c>.
/// </summary>
internal class PowerShellXmlProvider : PowerShellProvider
{
    public override AuthenticodeProvider Provider => AuthenticodeProvider.PowerShellXml;

    internal static string[] FileExtensions => new[] { ".psc1", ".ps1xml" };

    protected override string StartComment => "<!-- ";

    protected override string EndComment => " -->";

    public static PowerShellXmlProvider Create(byte[] data, Encoding? fileEncoding)
        => new PowerShellXmlProvider(data, fileEncoding);

    private PowerShellXmlProvider(byte[] data, Encoding? fileEncoding) : base(data, fileEncoding)
    {}
}

public class BOMLessEncoding : Encoding
{
    private readonly Encoding _encoding;

    public BOMLessEncoding(Encoding encoding)
    {
        _encoding = encoding;
    }

    public override byte[] GetPreamble() => Array.Empty<byte>();

    public override int GetByteCount(char[] chars, int index, int count)
        => _encoding.GetByteCount(chars, index, count);

    public override int GetBytes(char[] chars, int charIndex, int charCount, byte[] bytes, int byteIndex)
        => _encoding.GetBytes(chars, charIndex, charCount, bytes, byteIndex);

    public override int GetCharCount(byte[] bytes, int index, int count)
        => _encoding.GetCharCount(bytes, index, count);

    public override int GetChars(byte[] bytes, int byteIndex, int byteCount, char[] chars, int charIndex)
        => _encoding.GetChars(bytes, byteIndex, byteCount, chars, charIndex);

    public override int GetMaxByteCount(int charCount)
        => _encoding.GetMaxByteCount(charCount);
    public override int GetMaxCharCount(int byteCount)
        => _encoding.GetMaxCharCount(byteCount);
}

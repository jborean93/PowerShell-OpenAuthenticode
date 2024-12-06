using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
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

    protected PowerShellProvider(byte[] data, Encoding fileEncoding)
    {
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

    public SpcIndirectData HashData(Oid digestAlgorithm)
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

    public AsnEncodedData[] GetAttributesToSign()
    {
        SpcSpOpusInfo opusInfo = new(null, null);
        SpcStatementType statementType = new(new[]
        {
            new Oid("1.3.6.1.4.1.311.2.1.21", "SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID"),
        });

        return new[]
        {
            new AsnEncodedData(SpcSpOpusInfo.OID, opusInfo.GetBytes()),
            new AsnEncodedData(SpcStatementType.OID, statementType.GetBytes())
        };
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

    internal static Encoding GetScriptEncoding(ReadOnlySpan<byte> data)
    {
        // See this thread for some background info here.
        // https://infosec.exchange/@Lee_Holmes/113601497325792033

        // Check if there is a BOM present and use that to determine the
        // encoding. Only UTF-16-LE, UTF-16-BE, and UTF-8 are checked in the
        // PowerShell SIP implementation.
        if (data.Length > 1)
        {
            if (data[0] == 0xFF && data[1] == 0xFE)
            {
                return new UnicodeEncoding(false, true);
            }
            else if (data[0] == 0xFE && data[1] == 0xFF)
            {
                return new UnicodeEncoding(true, true);
            }
            else if (data.Length > 2 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
            {
                return new UTF8Encoding(true);
            }
        }

        // If no BOM is present the SIP then checks if the text is
        // Unicode/UTF-16 without a BOM but as PowerShell won't even load such
        // a script we ignore that check. The next check is to see if the first
        // 32 bytes contains valid multibyte UTF-8 sequences.
        if (data.Length > 32)
        {
            data = data[..32];
        }

        if (IsTextUTF8(data))
        {
            return new UTF8Encoding(false);
        }
        else
        {
            return Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.ANSICodePage);
        }
    }

    internal static bool IsTextUTF8(ReadOnlySpan<byte> data)
    {
        bool containsExtendedChar = false;
        int remainingOctets = 0;

        foreach (byte b in data)
        {
            if (remainingOctets == 0)
            {
                if ((b & 0b10000000) == 0)
                {
                    // 7-bit ASCII character.
                    continue;
                }

                containsExtendedChar = true;

                // Get the octet count, the number of set leading bits is the
                // count of octets for the sequence.
                byte currentByte = b;
                do
                {
                    currentByte <<= 1;
                    remainingOctets++;
                }
                while ((currentByte & 0b10000000) != 0);

                // The count includes this octet and must have at least 1 extra
                // octet.
                remainingOctets--;
                if (remainingOctets == 0)
                {
                    return false;
                }
            }
            else
            {
                // Non-leading octets must start with 10000000
                if ((b & 0b11000000) != 0b10000000)
                {
                    return false;
                }
                remainingOctets--;
            }
        }

        // If we have completed all active sequences and there is at least 1
        // extended character the bytes are considered to be UTF-8.
        return remainingOctets == 0 && containsExtendedChar;
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
        => new PowerShellScriptProvider(data, fileEncoding ?? GetScriptEncoding(data));

    private PowerShellScriptProvider(byte[] data, Encoding fileEncoding) : base(data, fileEncoding)
    { }
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
        => new PowerShellXmlProvider(data, fileEncoding ?? GetScriptEncoding(data));

    private PowerShellXmlProvider(byte[] data, Encoding fileEncoding) : base(data, fileEncoding)
    { }
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

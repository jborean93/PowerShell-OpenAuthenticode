using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;

namespace OpenAuthenticode;

/// <summary>
/// Authenticode providers for PowerShell script files. This includes files
/// with the extensions <c>.ps1</c>, <c>.psc1</c>, <c>.psd1</c>, <c>.psm1</c>,
/// and <c>.ps1</c>.
/// </summary>
internal class PowerShellScriptProvider : IAuthenticodeProvider
{
    private readonly Guid _pwshSip = new("603bcc1f-4b59-4e08-b724-d2c6297ef351");
    private const string _startBlock = "# SIG # Begin signature block";
    private const string _endBlock = "# SIG # End signature block";

    private byte[] _content;
    private Encoding _fileEncoding;

    public AuthenticodeProvider Provider => AuthenticodeProvider.PowerShell;

    internal static string[] FileExtensions => new[] { ".ps1", ".psc1", ".psd1", ".psm1", ".ps1xml" };

    /// <summary>
    /// Factory to create the PowerShellScriptProvider.
    /// </summary>
    /// <param name="data">The raw script bytes to manage</param>
    /// <param name="fileEncoding">Encoding hint of the data provided</param>
    /// <returns>The PowerShellScriptProvider></returns>
    public static PowerShellScriptProvider Create(byte[] data, Encoding? fileEncoding)
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

        int signatureIdx = scriptData.IndexOf(new ReadOnlySpan<char>($"\r\n{_startBlock}".ToCharArray()));

        byte[] hashableData;
        byte[] signature = Array.Empty<byte>();
        if (signatureIdx != -1)
        {
            ReadOnlySpan<char> scriptContents = scriptData[..signatureIdx];
            hashableData = Encoding.Unicode.GetBytes(scriptContents.ToArray());

            ReadOnlySpan<char> signatureBlock = scriptData[(signatureIdx + _startBlock.Length + 4)..];
            int endSignatureIdx = signatureBlock.IndexOf(new ReadOnlySpan<char>($"\r\n{_endBlock}".ToCharArray()));
            if (IsValidEndBlock(signatureBlock, endSignatureIdx))
            {
                signatureBlock = signatureBlock[..endSignatureIdx];

                StringBuilder base64Signature = new();
                foreach (ReadOnlySpan<char> line in signatureBlock.EnumerateLines())
                {
                    base64Signature.Append(line[2..]);
                }

                signature = Convert.FromBase64String(base64Signature.ToString());
            }
        }
        else
        {
            hashableData = Encoding.Unicode.GetBytes(scriptText);
        }

        return new PowerShellScriptProvider(hashableData, signature, fileEncoding);
    }

    public byte[] Signature { get; set; }

    private PowerShellScriptProvider(byte[] content, byte[] signature, Encoding fileEncoding)
    {
        Signature = signature;
        _content = content;
        _fileEncoding = fileEncoding;
    }

    public SpcIndirectData HashData(Oid digestAlgorithm)
    {
        byte[] fileHash;
        using (HashAlgorithm algo = SpcIndirectData.HashAlgorithmFromOid(digestAlgorithm))
        {
            fileHash = algo.ComputeHash(_content);
        }

        return new(
            DataType: SpcSipInfo.OID,
            Data: new SpcSipInfo(0x10000, _pwshSip).GetBytes(),
            DigestAlgorithm: digestAlgorithm,
            DigestParameters: null,
            Digest: fileHash
        );
    }

    public void AddAttributes(CmsSigner signer)
    {
        SpcSpOpusInfo opusInfo = new(null, null);
        signer.SignedAttributes.Add(new AsnEncodedData(SpcSpOpusInfo.OID, opusInfo.GetBytes()));

        SpcStatementType statementType = new(new[]
        {
            new Oid("1.3.6.1.4.1.311.2.1.21", "SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID"),
        });
        signer.SignedAttributes.Add(new AsnEncodedData(SpcStatementType.OID, statementType.GetBytes()));
    }

    public void Save(string path)
    {
        string content = Encoding.Unicode.GetString(_content); ;
        if (Signature.Length > 0)
        {
            StringBuilder signatureContent = new();
            signatureContent.Append($"\r\n{_startBlock}\r\n");
            ReadOnlySpan<char> b64Sig = new(Convert.ToBase64String(Signature).ToCharArray());
            while (b64Sig.Length > 0)
            {
                int lineLength = Math.Min(b64Sig.Length, 64);
                signatureContent.AppendFormat("# {0}\r\n", b64Sig[..lineLength].ToString());
                b64Sig = b64Sig[lineLength..];
            }

            signatureContent.Append($"{_endBlock}\r\n");
            content += signatureContent.ToString();
        }

        // The content already contains the original BOM chars so ensure that
        // the _fileEncoding doesn't add another one breaking the signature.
        File.WriteAllText(path, content, new BOMLessEncoding(_fileEncoding));
    }

    private static bool IsValidEndBlock(ReadOnlySpan<char> block, int endIdx)
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
        string remaining = block.Slice(endIdx + _endBlock.Length + 2).ToString();
        return Array.Exists(validEndlineCandidates, c => c == remaining);
    }
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

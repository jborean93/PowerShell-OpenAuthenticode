using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation.Host;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using OtpNet;

namespace OpenAuthenticode.Shared;

public sealed class SslDotComKey : KeyProvider
{
    private const string _sha256WithRSAEncryptionOid = "1.2.840.113549.1.1.11";

    private SslDotComCscApi _api;
    private string[] _availableAlgorithms;
    private string _credId;
    private X509Certificate2[] _certChain;
    private bool _malwareScanRequired;
    private bool _onlineOtp;
    private byte[]? _totpSeed;
    private Dictionary<string, PendingOperation> _operations = new();
    private Dictionary<string, byte[]> _results = new();

    public override X509Certificate2 Certificate { get => _certChain[0]; }

    internal override AsymmetricAlgorithm Key { get; }

    internal SslDotComKey(
        SslDotComCscApi api,
        string credentialId,
        X509Certificate2[] certificates,
        bool onlineOtp,
        string[] availableAlgorithms,
        bool malwareScanRequired,
        byte[]? totpSeed)
    {
        _api = api;
        _availableAlgorithms = availableAlgorithms;
        _credId = credentialId;
        _certChain = certificates;
        _malwareScanRequired = malwareScanRequired;
        _onlineOtp = onlineOtp;
        _totpSeed = totpSeed;

        if (!_availableAlgorithms.Contains(_sha256WithRSAEncryptionOid))
        {
            throw new ArgumentException($"Provided SSL.com key does not support sha256WithRSAEncryption");
        }

        Key = new SslDotComRSAKey(this);
    }

    internal byte[] Sign(byte[] hash, HashAlgorithmName hashAlgorithm)
        => _results[Convert.ToBase64String(hash)];

    internal override void RegisterHashToSign(Span<byte> hash, Span<byte> content, HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm.Name != "SHA256")
        {
            throw new CryptographicException($"Unsupported SSL.com hash algorithm {hashAlgorithm.Name}, only SHA256 is supported");
        }

        string contentHash = Convert.ToBase64String(SHA256.HashData(content));
        _operations[Convert.ToBase64String(hash)] = new(contentHash, _sha256WithRSAEncryptionOid);
    }

    internal override async Task AuthorizeRegisteredHashes(AsyncPSCmdlet cmdlet)
    {
        if (_operations.Count < 1)
        {
            return;
        }

        await PerformMalwareScans(cmdlet);

        string[] hashes = _operations.Keys.ToArray();
        string algorithmId = _operations[hashes[0]].Algorithm;
        _results = new();
        _operations = new();

        string otp = await GetOTP(cmdlet);
        CscV0Api.AuthorizedCredentials authCred = await _api.CredentialsAuthorizeAsync(
            _credId,
            hashes.Length,
            hashes,
            otp: otp,
            cancelToken: cmdlet.CancelToken,
            cmdlet: cmdlet);

        CscV0Api.SignedHash signedResult = await _api.SignaturesSignHashAsync(
            _credId,
            authCred.SignatureActivationData,
            hashes,
            algorithmId,
            cancelToken: cmdlet.CancelToken,
            cmdlet: cmdlet);

        for (int i = 0; i < hashes.Length; i++)
        {
            _results.Add(hashes[i], Convert.FromBase64String(signedResult.Signatures[i]));
        }
    }

    private async Task PerformMalwareScans(AsyncPSCmdlet cmdlet)
    {
        if (!_malwareScanRequired)
        {
            return;
        }

        bool[] results = await Task.WhenAll(
            _operations.Select(kvp => _api.ScanHash(_credId, kvp.Value.Content, kvp.Key, cmdlet.CancelToken, cmdlet)));
        if (results.Contains(true))
        {
            throw new ArgumentException("Malware scanning is required by SSL.com and one of the files being scanned was detected as malware");
        }
    }

    private async Task<string> GetOTP(AsyncPSCmdlet cmdlet)
    {
        if (_totpSeed != null)
        {
            Totp totp = new(_totpSeed);
            return totp.ComputeTotp();
        }

        if (_onlineOtp)
        {
            await _api.CredentialsSendOTP(_credId, cancelToken: cmdlet.CancelToken, cmdlet: cmdlet);
        }

        string promptMessage = $"Please enter OTP for {_credId} to authorize signing";
        FieldDescription prompt = new("OTP");
        prompt.SetParameterType(typeof(SecureString));

        SecureString otpSS = (SecureString)cmdlet.Host.UI.Prompt(
            promptMessage,
            "",
            new(new[] { prompt }))[prompt.Name].BaseObject;

        return new NetworkCredential("", otpSS).Password;
    }
}

internal record PendingOperation(string Content, string Algorithm);

internal sealed class SslDotComRSAKey : RSA
{
    private readonly SslDotComKey _key;
    public SslDotComRSAKey(SslDotComKey key)
    {
        _key = key;
    }

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (padding.Mode != RSASignaturePaddingMode.Pkcs1)
        {
            throw new CryptographicException($"Unsupported padding mode {padding.Mode}");
        }

        return _key.Sign(hash, hashAlgorithm);
    }

    public override RSAParameters ExportParameters(bool includePrivateParameters) => throw new NotImplementedException();

    public override void ImportParameters(RSAParameters parameters) => throw new NotImplementedException();
}

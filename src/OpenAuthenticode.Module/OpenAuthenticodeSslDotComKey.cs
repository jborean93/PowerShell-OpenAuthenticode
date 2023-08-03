using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Net;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace OpenAuthenticode.Shared;

[Cmdlet(
    VerbsCommon.Get,
    "OpenAuthenticodeSslDotComKey",
    DefaultParameterSetName = "AuthorizationCode"
)]
[OutputType(typeof(SslDotComKey))]
public sealed class GetOpenAuthenticodeSslDotComKey : AsyncPSCmdlet
{
    private const string _redirectUri = "urn:ietf:wg:oauth:2.0:oob";

    [Parameter]
    public string ApiEndpoint { get; set; } = "https://cs.ssl.com/";

    [Parameter]
    [Alias("CredentialID")]
    public SslDotComCertificate? Certificate { get; set; }

    [Parameter]
    public string? TOPTSecret { get; set; }

    #region OAuth

    [Parameter(
        Mandatory = true
    )]
    public string? ClientId { get; set; }

    [Parameter(
        Mandatory = true
    )]
    [StringAsSecureStringTransformer]
    public SecureString? ClientSecret { get; set; }

    [Parameter(
        ParameterSetName = "AuthorizationCode"
    )]
    [StringAsSecureStringTransformer]
    public SecureString? AuthorizationCode { get; set; }

    [Parameter(
        Mandatory = true,
        ParameterSetName = "Credential"
    )]
    [Credential]
    public PSCredential? Credential { get; set; }

    [Parameter(
        Mandatory = true,
        ParameterSetName = "UserName"
    )]
    public string? UserName { get; set; }

    [Parameter(
        Mandatory = true,
        ParameterSetName = "UserName"
    )]
    [StringAsSecureStringTransformer]
    public SecureString? Password { get; set; }

    #endregion OAuth

    protected override async Task EndProcessingAsync()
    {
        try
        {
            SslDotComCscApi cscApi = new(new Uri(ApiEndpoint));
            await AuthenticateApiAsync(cscApi);
            SslDotComCredential? credential = await SelectCredential(cscApi);
            if (credential == null)
            {
                return;
            }
            WriteVerbose($"Using credential {credential.CredentialId} with certificate {credential.Certificates[0].Subject}");

            bool malwareScanRequired = await cscApi.ScanSettings(credential.CredentialId, CancelToken, this);
            SslDotComKey key = new(
                cscApi,
                credential.CredentialId,
                credential.Certificates,
                credential.OnlineOtp,
                credential.Raw.Key.Algorithms,
                malwareScanRequired,
                string.IsNullOrWhiteSpace(TOPTSecret) ? null : Convert.FromBase64String(TOPTSecret)
            );
            WriteObject(key);
        }
        catch (PipelineStoppedException)
        {
            return;
        }
        catch (Exception e)
        {
            ErrorRecord err = new(
                e,
                "SslDotComKeyError",
                ErrorCategory.NotSpecified,
                null);
            WriteError(err);
        }
    }

    private async Task AuthenticateApiAsync(SslDotComCscApi api)
    {
        Debug.Assert(ClientId != null);
        Debug.Assert(ClientSecret != null);

        // Trim out any whitespace in case of copy/paste problems.
        string clientId = ClientId.Trim();
        string clientSecret = SecureStringToString(ClientSecret).Trim();

        CscV0Api.ApiInfo apiInfo = await api.Info(CancelToken, cmdlet: this);

        if (string.IsNullOrWhiteSpace(apiInfo.OAuth2))
        {
            ErrorRecord err = new(
                new ArgumentException("Failed to retrieve OAuth2 endpoint from API, cannot continue"),
                "NoOAuth2Endpoint",
                ErrorCategory.AuthenticationError,
                null);
            ThrowTerminatingError(err);
        }

        UriBuilder oauthTokenUriBuilder = new(apiInfo.OAuth2);
        oauthTokenUriBuilder.Path = null;

        if (ParameterSetName == "AuthorizationCode")
        {
            if (AuthorizationCode == null)
            {
                UriBuilder oauthUrlBuilder = new UriBuilder(apiInfo.OAuth2);
                oauthUrlBuilder.Query = $"client_id={clientId}&redirect_uri={_redirectUri}&response_type=code&scope=service";

                string promptMsg = @$"
    No AuthorizationCode was specified. Please go to the following URL
    and paste in the result authorization code to continue.

    {oauthUrlBuilder.Uri.AbsoluteUri}

    You may need to load the URL twice if the first attempt goes to the account
    settings page. The ClientID must be a registered OAuth application that has
    the service scope and redirect URL of '{_redirectUri}' for this to work.";

                FieldDescription authField = new("Authorization Code");
                authField.SetParameterType(typeof(SecureString));
                AuthorizationCode = (SecureString)Host.UI.Prompt(
                    "",
                    promptMsg,
                    new(new[] { authField })
                )["Authorization Code"].BaseObject;
            }

            if (AuthorizationCode.Length == 0)
            {
                ErrorRecord err = new(
                    new ArgumentException("No AuthorizationCode was specified, cannot continue"),
                    "NoAuthorizationCode",
                    ErrorCategory.AuthenticationError,
                    null);
                ThrowTerminatingError(err);
                return;
            }

            await api.OAuth2SslDotComToken(
                oauthTokenUriBuilder.Uri,
                "authorization_code",
                clientId,
                clientSecret,
                code: SecureStringToString(AuthorizationCode).Trim(),
                redirectUri: _redirectUri,
                cancelToken: CancelToken);
        }
        else
        {
            string username;
            string password;
            if (ParameterSetName == "Credential")
            {
                Debug.Assert(Credential != null);
                username = Credential.UserName;
                password = Credential.GetNetworkCredential().Password;
            }
            else
            {
                Debug.Assert(UserName != null);
                Debug.Assert(Password != null);
                username = UserName;
                password = SecureStringToString(Password);
            }

            await api.OAuth2SslDotComToken(
                oauthTokenUriBuilder.Uri,
                "password",
                clientId,
                clientSecret,
                username: username,
                password: password,
                cancelToken: CancelToken);
        }
    }

    private async Task<SslDotComCredential?> SelectCredential(SslDotComCscApi api)
    {
        if (Certificate?.IsCredentialId == true)
        {
            WriteVerbose($"Getting credential info for credential id '{Certificate.Value}'");
            CscV0Api.CredentialInfo credInfo;
            try
            {
                credInfo = await api.CredentialsInfoAsync(
                    Certificate.Value,
                    certificates: "chain",
                    certInfo: false,
                    authInfo: true,
                    cancelToken: CancelToken,
                    cmdlet: this);
            }
            catch (CscBadRequestException e)
            {
                ArgumentException exc = new(
                    $"Provided credential id '{Certificate.Value}' could not be found",
                    e);
                ErrorRecord err = new(
                    exc,
                    "UnknownSslDotComCredentialId",
                    ErrorCategory.InvalidArgument,
                    Certificate.Value);
                WriteError(err);
                return null;
            }

            SslDotComCredential info = SslDotComCredential.CreateFromApiResponse(Certificate.Value, credInfo);
            string? problem = info.CheckValidity();
            if (!string.IsNullOrWhiteSpace(problem))
            {
                string msg = $"Provided credential id '{Certificate.Value}' is not usable: {problem}";
                ErrorRecord err = new(
                    new ArgumentException(msg),
                    "UnusableSslDotComCredentialId",
                    ErrorCategory.InvalidArgument,
                    Certificate.Value);
                WriteError(err);
                return null;
            }

            return info;
        }

        WriteVerbose("No explicit credential provided, getting list of available credential");

        string[][] credentialResults = await Task<string[]>.WhenAll(
            new []
            {
                api.SafeCredentialsListAsync("EVCS", CancelToken, this),
                api.SafeCredentialsListAsync("OVCS", CancelToken, this)
            });

        string? certThumbprint = Certificate?.Value;
        foreach (string[] credentials in credentialResults)
        {
            foreach (string credId in credentials)
            {
                WriteVerbose($"Getting credential information for '{credId}'");
                CscV0Api.CredentialInfo credInfo = await api.CredentialsInfoAsync(
                    credId,
                    certificates: "chain",
                    certInfo: false,
                    authInfo: true,
                    cancelToken: CancelToken,
                    cmdlet: this);

                SslDotComCredential info = SslDotComCredential.CreateFromApiResponse(credId, credInfo);
                string? problem = info.CheckValidity();

                if (string.IsNullOrWhiteSpace(certThumbprint))
                {
                    if (problem == null)
                    {
                        return info;
                    }
                    WriteVerbose($"Credential '{credId}' is invalid, skipping: {problem}");
                    continue;
                }
                else if (info.Certificates[0].Thumbprint != certThumbprint)
                {
                    WriteVerbose($"Credential '{credId}' certificate thumbprint does match requested certificate");
                    continue;
                }
                else if (string.IsNullOrWhiteSpace(problem))
                {
                    return info;
                }
                else
                {
                    string msg = $"Provided certificate thumbprint credential '{credId}' is not usable: {problem}";
                    ErrorRecord err = new(
                        new ArgumentException(msg),
                        "UnusableSslDotComCredentialIdThumbprint",
                        ErrorCategory.InvalidArgument,
                        certThumbprint);
                    WriteError(err);
                    return null;
                }
            }
        }

        WriteError(new(
            new ItemNotFoundException("Failed to find a credential to use for signing"),
            "NoAvailableSslDotComCredential",
            ErrorCategory.ResourceUnavailable,
            null));
        return null;
    }

    private static string SecureStringToString(SecureString ss)
        => new NetworkCredential("", ss).Password;
}

public sealed class SslDotComCertificate
{
    internal bool IsCredentialId { get; }

    internal string Value { get; }

    public SslDotComCertificate(X509Certificate2 certificate)
    {
        Value = certificate.Thumbprint;
        IsCredentialId = false;
    }

    public SslDotComCertificate(string certificate)
    {
        if (Guid.TryParse(certificate, out var credId))
        {
            Value = credId.ToString();
            IsCredentialId = true;
        }
        else if (Regex.IsMatch(certificate, @"^[A-Fa-f0-9]{40}$"))
        {
            Value = certificate;
            IsCredentialId = false;
        }
        else
        {
            throw new ArgumentException("Provided certificate value must be a GUID or a certificate thumbprint");
        }
    }
}

internal record SslDotComCredential(
    string CredentialId,
    X509Certificate2[] Certificates,
    bool OnlineOtp,
    CscV0Api.CredentialInfo Raw
)
{
    public static SslDotComCredential CreateFromApiResponse(string credId, CscV0Api.CredentialInfo info)
    {
        X509Certificate2[] certs = (info.Certificate.Certificates ?? Array.Empty<string>())
            .Select(c => new X509Certificate2(Convert.FromBase64String(c)))
            .ToArray();
        return new(credId, certs, info.Otp?.Type == "online", info);
    }

    public string? CheckValidity()
    {
        if (Raw.Key.Status != "enabled")
        {
            return $"key is not enabled but '{Raw.Key.Status}'";
        }
        if ((Raw.Certificate.Certificates?.Length ?? 0) < 1)
        {
            return $"no certificates are associated with the credential";
        }
        if (Raw.Certificate.Status != "valid")
        {
            return $"certificate is not valid but '{Raw.Certificate.Status}'";
        }

        return null;
    }
}


internal sealed class SslDotComCscApi : CscV0Api
{
    private record ScanSettingsResult(
        [property: JsonPropertyName("malware_scan_enabled")] bool MalwareScanEnabled
    );

    private record ScanResult(
        [property: JsonPropertyName("malware_detected")] bool MalwareDetected
    );

    public SslDotComCscApi(Uri endpoint) : base(endpoint)
    { }

    public async Task<OAuth2TokenResponse> OAuth2SslDotComToken(
        Uri oauth2Endpoint,
        string grantType,
        string clientId,
        string clientSecret,
        string? code = null,
        string? redirectUri = null,
        string? username = null,
        string? password = null,
        CancellationToken? cancelToken = null,
        AsyncPSCmdlet? cmdlet = null
    )
    {
        // SSL.com use a custom OAuth endpoint to support getting a bearer
        // token using a username/password. The CSC exposed oauth2/token
        // endpoint doesn't work for either so this is used instead.
        Dictionary<string, object> body = new()
        {
            { "grant_type", grantType },
            { "client_id", clientId },
            { "client_secret", clientSecret }
        };
        if (!string.IsNullOrEmpty(code))
        {
            body["code"] = code;
        }
        if (!string.IsNullOrWhiteSpace(redirectUri))
        {
            body["redirect_uri"] = redirectUri;
        }
        if (!string.IsNullOrWhiteSpace(username))
        {
            body["username"] = username;
        }
        if (!string.IsNullOrWhiteSpace(password))
        {
            body["password"] = password;
        }

        OAuth2TokenResponse token = await CallApi<OAuth2TokenResponse>(
            "oauth2/token",
            body,
            cancelToken,
            "retrieve OAuth2 Bearer token",
            endpoint: oauth2Endpoint,
            cmdlet: cmdlet);

        _tokenInfo = token;
        return token;
    }

    public async Task<string[]> SafeCredentialsListAsync(
        string? certificateType = null,
        CancellationToken? cancelToken = default,
        AsyncPSCmdlet? cmdlet = null
    )
    {
        try
        {
            CredentialList credentials = await CredentialsListAsync(
                clientData: certificateType,
                cancelToken: cancelToken,
                cmdlet: cmdlet);
            return credentials.CredentialIds;
        }
        catch (CscBadRequestException)
        {
            // SSL.com returns a 400 bad request if there are no credentials
            // for the certificate type requests.
            return Array.Empty<string>();
        }
    }

    public async Task<bool> ScanHash(
        string credentialId,
        string hashToScan,
        string hashToSign,
        CancellationToken? cancelToken = default,
        AsyncPSCmdlet? cmdlet = null
    )
    {
        Dictionary<string, object> body = new()
        {
            { "credential_id", credentialId },
            { "hash_to_scan", hashToScan },
            { "hash_to_sign", hashToSign }
        };

        ScanResult result = await CallApi<ScanResult>(
            "scan/hash",
            body,
            cancelToken,
            "send hashes for malware scanning",
            cmdlet: cmdlet);

        return result.MalwareDetected;
    }

    public async Task<bool> ScanSettings(
        string credentialId,
        CancellationToken? cancelToken = default,
        AsyncPSCmdlet? cmdlet = null
    )
    {
        Dictionary<string, object> body = new()
        {
            { "credential_id", credentialId }
        };

        ScanSettingsResult result = await CallApi<ScanSettingsResult>(
            "scan/settings",
            body,
            cancelToken,
            "retrieve malware scan settings",
            cmdlet: cmdlet);

        return result.MalwareScanEnabled;
    }
}

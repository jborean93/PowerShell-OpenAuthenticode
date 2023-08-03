using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace OpenAuthenticode.Shared;

// https://cloudsignatureconsortium.org/wp-content/uploads/2020/05/CSC_API_V0_0.1.7.9.pdf

internal class CscV0Api
{
    public record ErrorMessage(
        [property: JsonPropertyName("error")] string Error,
        [property: JsonPropertyName("error_description")] string? ErrorDescription
    );

    public record ApiInfo(
        // The version of this specification implemented by the provider.
        [property: JsonPropertyName("specs")] string Spec,

        // The commercial name of the Remote Service.
        [property: JsonPropertyName("name")] string Name,

        // The URI of the image file containing the logo of the Remote Service.
        [property: JsonPropertyName("logo")] string Logo,

        // The ISO 3166-1 Alpha-2 code of the Country where the Remote Service
        // provider is established.
        [property: JsonPropertyName("region")] string Region,

        // The language used in the responses, specified according to RFC 3066.
        [property: JsonPropertyName("lang")] string Language,

        // Free-form description of the Remote Service in the lang language.
        [property: JsonPropertyName("description")] string Description,

        // One or more values corresponding to the auth mechanisms supported.
        // Can be external, TLS, basic, digest, oauth2code, oauth2implicit,
        // oauth2client.
        [property: JsonPropertyName("authType")] string[] AuthType,

        // Specifies the complete URI of the OAuth 2.0 service authorization
        // endpoint.
        [property: JsonPropertyName("oauth2")] string? OAuth2,

        // List of names of all the API methods described in the CSC specification
        // that are implemented and supported by the Remote Service.
        [property: JsonPropertyName("methods")] string[] Methods
    );

    public record CredentialList(
        // One or more credentialID associated with the provided or implicit userID.
        [property: JsonPropertyName("credentialIDs")] string[] CredentialIds,

        // The page token for the next page of items. No value is returned if the
        // Remote Service does not support items pagination or in cast the last
        // page is returned.
        [property: JsonPropertyName("nextPageToken")] string? NextPageToken
    );

    public record OAuth2TokenResponse(
        // The short-lived access token to be used depending on the scope of the
        // OAuth 2.0 authorization request.
        [property: JsonPropertyName("access_token")] string AccessToken,

        // The long-lived refresh token used to re-authenticate the user on the
        // subsequent session.
        [property: JsonPropertyName("refresh_token")] string? RefreshToken,

        // Specifies a "Bearer" token type as defined in RFC6750.
        [property: JsonPropertyName("token_type")] string TokenType,

        // The lifetime in seconds of the service access token. If omitted, the
        // default expiration time is 3600 (1 hour).
        [property: JsonPropertyName("expires_in")] int? ExpiresIn
    );

    public record CredentialInfo(
        // A free form description of the credential in the lang language.
        [property: JsonPropertyName("description")] string? Description,

        // The signing key information associated with the credential.
        [property: JsonPropertyName("key")] Key Key,

        // The certificate information associated with the credential.
        [property: JsonPropertyName("cert")] Certificate Certificate,

        // The authentication mode.
        [property: JsonPropertyName("authMode")] string AuthMode,

        // The Sole Control Assurance Level required by the credential.
        // "1": at least a basic authz is required. Does not require any of
        //      the credential authz methods not to pass the SAD to the
        //      signHash method.
        // "2": At least a two-factor authz is required.
        [property: JsonPropertyName("SCAL")] string? SoleControlAssuranceLevel,

        // The pin information associated with the credential.
        [property: JsonPropertyName("PIN")] Pin? Pin,

        // The OTP information associated with the credential.
        [property: JsonPropertyName("OTP")] Otp? Otp,

        // Specifies if the credential supports multiple signatures to be
        // created with a single authz request.
        [property: JsonPropertyName("multisign")] bool MultiSign,

        // The language used in the responses, specified according to RFC 3066.
        [property: JsonPropertyName("lang")] string? Language
    );

    public record Key(
        // The status of enablement of the signing key.
        [property: JsonPropertyName("status")] string Status,

        // The list of OIDs of the supported key algorithms.
        [property: JsonPropertyName("algo")] string[] Algorithms,

        // The length of the cryptographic key in bits.
        [property: JsonPropertyName("len")] int Length,

        // The OID of the ECDSA curve.
        [property: JsonPropertyName("curve")] string? Curve
    );

    public record Certificate(
        // The status of the end entity certificate.
        [property: JsonPropertyName("status")] string? Status,

        // Contains one or more base64 encoded X509v3 certificates from
        // the certificate chain.
        [property: JsonPropertyName("certificates")] string[]? Certificates,

        // The issuer subject distinguished name from the end entity certificate.
        [property: JsonPropertyName("issuerDN")] string? IssuerDN,

        // The serial number from the end entity certificate in hex encoded form.
        [property: JsonPropertyName("serialNumber")] string? SerialNumber,

        // The distinguished name of the end entity certificate.
        [property: JsonPropertyName("subjectDN")] string? SubjectDN,

        // The validity start date from the end entity certificate. The format is
        // in the GeneralizedTime format (RFC 2459).
        [property: JsonPropertyName("validFrom")] string? ValidFrom,

        // The validity end date from the end entity certificate. The format is
        // in the GeneralizedTime format (RFC 2459).
        [property: JsonPropertyName("validTo")] string? ValidTo
    );

    public record Pin(
        // Specifies if a text-based PIN is required or not.(true, false, optional)
        [property: JsonPropertyName("presence")] string? Presence,

        // The format of the PIN.
        [property: JsonPropertyName("format")] string? Format,

        // Specifies an optional label for the data field used to collect the PIN.
        [property: JsonPropertyName("label")] string? Label,

        // The free form description of the PIN.
        [property: JsonPropertyName("description")] string? Description
    );

    public record Otp(
        // Specifies if a text based PIN is required or not.
        [property: JsonPropertyName("presence")] string? Presence,

        // The TOP type
        // offline: An OTP is generated offline with a dedicated device.
        // online:  An OTP is generated online with credentials/sendOTP.
        [property: JsonPropertyName("type")] string? Type,

        // Optional label for the data field used to collect the OTP in
        // the user interface.
        [property: JsonPropertyName("label")] string? Label,

        // Optionally specifies a free form description of the OTP mechanism.
        [property: JsonPropertyName("description")] string? Description,

        // The identifier of the OTP device or application.
        [property: JsonPropertyName("ID")] string? Id,

        // The provider of the OTP device.
        [property: JsonPropertyName("provider")] string? Provider
    );

    public record AuthorizedCredentials(
        // The Signature Activation Data to provide as input to the
        // signatures/signHash method.
        [property: JsonPropertyName("SAD")] string SignatureActivationData,

        // The lifetime in seconds of the service access token. if omitted,
        // the default expiration time is 3600 (1 hour).
        [property: JsonPropertyName("expiresIn")] int? ExpiresIn
    );

    public record SignedHash(
        // One of more Base64-encoded signed hash.
        [property: JsonPropertyName("signatures")] string[] Signatures
    );

    private HttpClient _client;
    private Uri _endpoint;
    internal OAuth2TokenResponse? _tokenInfo;

    public CscV0Api(Uri endpoint)
    {
        _client = new();
        _client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(
            "OpenAuthenticode",
            typeof(LoadContext).Assembly.GetName()?.Version?.ToString() ?? ""));
        _endpoint = endpoint;
    }

    public async Task<AuthorizedCredentials> CredentialsAuthorizeAsync(
        string credentialId,
        int numSignatures,
        string[]? hash = null,
        string? pin = null,
        string? otp = null,
        string? description = null,
        string? clientData = null,
        CancellationToken? cancelToken = default,
        AsyncPSCmdlet? cmdlet = null
    )
    {
        Dictionary<string, object> body = new()
        {
            { "credentialID", credentialId },
            { "numSignatures", numSignatures }
        };
        if (hash != null)
        {
            body["hash"] = hash;
        }
        if (!string.IsNullOrWhiteSpace(pin))
        {
            body["PIN"] = pin;
        }
        if (!string.IsNullOrWhiteSpace(otp))
        {
            body["OTP"] = otp;
        }
        if (!string.IsNullOrWhiteSpace(description))
        {
            body["description"] = description;
        }
        if (!string.IsNullOrWhiteSpace(clientData))
        {
            body["clientData"] = clientData;
        }

        return await CallApi<AuthorizedCredentials>(
            "csc/v0/credentials/authorize",
            body,
            cancelToken,
            "authorize credentials for signing",
            cmdlet: cmdlet);
    }

    public async Task<CredentialList> CredentialsListAsync(
        string? userID = null,
        int? maxResults = null,
        string? pageToken = null,
        string? clientData = null,
        CancellationToken? cancelToken = default,
        AsyncPSCmdlet? cmdlet = null
    )
    {
        Dictionary<string, object> body = new();
        if (!string.IsNullOrWhiteSpace(userID))
        {
            body["userID"] = userID;
        }
        if (maxResults != null)
        {
            body["maxResults"] = maxResults;
        }
        if (!string.IsNullOrWhiteSpace(pageToken))
        {
            body["pageToken"] = pageToken;
        }
        if (!string.IsNullOrWhiteSpace(clientData))
        {
            body["clientData"] = clientData;
        }

        return await CallApi<CredentialList>(
            "csc/v0/credentials/list",
            body,
            cancelToken,
            "retrieve credentials list",
            cmdlet: cmdlet);
    }

    public async Task<CredentialInfo> CredentialsInfoAsync(
        string credentialId,
        string certificates = "single",  // none, single*, chain
        bool certInfo = false,
        bool authInfo = false,
        string? lang = null,
        string? clientData = null,
        CancellationToken? cancelToken = default,
        AsyncPSCmdlet? cmdlet = null
    )
    {
        Dictionary<string, object> body = new()
        {
            { "credentialID", credentialId },
            { "certificates", certificates },
            { "certInfo", certInfo },
            { "authInfo", authInfo }
        };
        if (!string.IsNullOrWhiteSpace(lang))
        {
            body["lang"] = lang;
        }
        if (!string.IsNullOrWhiteSpace(clientData))
        {
            body["clientData"] = clientData;
        }

        return await CallApi<CredentialInfo>(
            "csc/v0/credentials/info",
            body,
            cancelToken,
            "retrieve certificate info",
            cmdlet: cmdlet);
    }

    public async Task CredentialsSendOTP(
        string credentialId,
        string? clientData = null,
        CancellationToken? cancelToken = default,
        AsyncPSCmdlet? cmdlet = null
    )
    {
        Dictionary<string, object> body = new()
        {
            { "credentialID", credentialId },
        };
        if (!string.IsNullOrWhiteSpace(clientData))
        {
            body["clientData"] = clientData;
        }

        await CallApi<Dictionary<string, object>>(
            "csc/v0/credentials/sendOTP",
            body,
            cancelToken,
            "start the online OTP generation mechanism",
            cmdlet: cmdlet);
    }

    public async Task<ApiInfo> Info(
        CancellationToken? cancelToken = default,
        AsyncPSCmdlet? cmdlet = null
    )
    {
        return await CallApi<ApiInfo>(
            "csc/v0/info",
            new(),
            cancelToken,
            "retrieve API info",
            cmdlet: cmdlet);
    }

    public async Task<OAuth2TokenResponse> OAuth2Token(
        string grantType,
        string clientId,
        string clientSecret,
        string? code = null,
        string? refreshToken = null,
        string? redirectUri = null,
        string? clientData = null,
        CancellationToken? cancelToken = default,
        AsyncPSCmdlet? cmdlet = null
    )
    {
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
        if (!string.IsNullOrWhiteSpace(refreshToken))
        {
            body["refresh_token"] = refreshToken;
        }
        if (!string.IsNullOrWhiteSpace(redirectUri))
        {
            body["redirect_uri"] = redirectUri;
        }
        if (!string.IsNullOrWhiteSpace(clientData))
        {
            body["clientData"] = clientData;
        }

        OAuth2TokenResponse token = await CallApi<OAuth2TokenResponse>(
            "csc/v0/oauth2/token",
            body,
            cancelToken,
            "retrieve OAuth 2.0 bearer token",
            cmdlet: cmdlet);

        _tokenInfo = token;
        return token;
    }

    public async Task<SignedHash> SignaturesSignHashAsync(
        string credentialId,
        string sad,
        string[] hash,
        string signAlgo,
        string? signAlgoParams = null,
        string? clientData = null,
        CancellationToken? cancelToken = default,
        AsyncPSCmdlet? cmdlet = null
    )
    {
        Dictionary<string, object> body = new()
        {
            { "credentialID", credentialId },
            { "SAD", sad },
            { "hash", hash },
            { "signAlgo", signAlgo }
        };
        if (!string.IsNullOrWhiteSpace(signAlgoParams))
        {
            body["signAlgoParams"] = signAlgoParams;
        }
        if (!string.IsNullOrWhiteSpace(clientData))
        {
            body["clientData"] = clientData;
        }

        return await CallApi<SignedHash>(
            "csc/v0/signatures/signHash",
            body,
            cancelToken,
            "sign provided hashes",
            cmdlet: cmdlet);
    }

    protected async Task<T> CallApi<T>(
        string apiPath,
        Dictionary<string, object> body,
        CancellationToken? cancelToken,
        string purpose,
        Uri? endpoint = null,
        AsyncPSCmdlet? cmdlet = null
    )
    {
        UriBuilder targetBuilder = new(endpoint ?? _endpoint);
        targetBuilder.Path = apiPath;

        string requestContent = JsonSerializer.Serialize(body);
        HttpRequestMessage request = new()
        {
            Method = HttpMethod.Post,
            RequestUri = targetBuilder.Uri,
            Content = new StringContent(requestContent, Encoding.UTF8, "application/json"),
        };
        if (_tokenInfo != null)
        {
            request.Headers.Authorization = new("Bearer", _tokenInfo.AccessToken);
        }

        cmdlet?.WriteVerbose($"Sending POST request to {targetBuilder.Uri.AbsoluteUri}");
        cmdlet?.WriteDebug($"POST request raw content: {requestContent}");
        HttpResponseMessage response = await _client.SendAsync(request);
        cmdlet?.WriteVerbose($"Receive POST reply with status {(int)response.StatusCode} {response.StatusCode}");

        string responseContent = await response.Content.ReadAsStringAsync(cancellationToken: cancelToken ?? default);
        cmdlet?.WriteDebug($"POST reply raw content: {responseContent}");

        if (
            response.StatusCode == HttpStatusCode.BadRequest &&
            response.Content.Headers.ContentType?.MediaType == "application/json"
        )
        {
            ErrorMessage errorInfo = JsonSerializer.Deserialize<ErrorMessage>(responseContent)!;
            throw new CscBadRequestException($"Failed to {purpose}", errorInfo.Error, errorInfo.ErrorDescription);
        }
        else if (!response.IsSuccessStatusCode)
        {
            StringBuilder errorMessage = new($"Failed to {purpose} - {(int)response.StatusCode} {response.StatusCode}");
            if (!string.IsNullOrWhiteSpace(responseContent))
            {
                errorMessage.Append($": {responseContent}");
            }
            throw new HttpRequestException(errorMessage.ToString(), null, response.StatusCode);
        }

        return JsonSerializer.Deserialize<T>(responseContent)!;
    }
}

public class CscBadRequestException : HttpRequestException
{
    public string Error { get; }
    public string? ErrorDescription { get; }

    public CscBadRequestException(string message, string error, string? errorDescription)
        : base(BuildExceptionMessage(message, error, errorDescription), null, HttpStatusCode.BadRequest)
    {
        Error = error;
        ErrorDescription = errorDescription;
    }

    private static string BuildExceptionMessage(string message, string error, string? errorDescription)
    {
        StringBuilder errorMessage = new($"{message} - {error}");
        if (!string.IsNullOrWhiteSpace(errorDescription))
        {
            errorMessage.Append($": {errorDescription}");
        }

        return errorMessage.ToString();
    }
}

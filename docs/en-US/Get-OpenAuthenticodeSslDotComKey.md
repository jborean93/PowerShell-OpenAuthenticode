---
external help file: OpenAuthenticode.Module.dll-Help.xml
Module Name: OpenAuthenticode
online version: https://www.github.com/jborean93/PowerShell-OpenAuthenticode/blob/main/docs/en-US/Get-OpenAuthenticodeSslDotComKey.md
schema: 2.0.0
---

# Get-OpenAuthenticodeSslDotComKey

## SYNOPSIS
Gets a SSL.com certificate key for use with Authenticode signing.

## SYNTAX

### AuthorizationCode (Default)
```
Get-OpenAuthenticodeSslDotComKey [-ApiEndpoint <String>] [-Certificate <SslDotComCertificate>]
 [-TOPTSecret <String>] -ClientId <String> -ClientSecret <SecureString> [-AuthorizationCode <SecureString>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### Credential
```
Get-OpenAuthenticodeSslDotComKey [-ApiEndpoint <String>] [-Certificate <SslDotComCertificate>]
 [-TOPTSecret <String>] -ClientId <String> -ClientSecret <SecureString> -Credential <PSCredential>
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### UserName
```
Get-OpenAuthenticodeSslDotComKey [-ApiEndpoint <String>] [-Certificate <SslDotComCertificate>]
 [-TOPTSecret <String>] -ClientId <String> -ClientSecret <SecureString> -UserName <String>
 -Password <SecureString> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Gets the SSL.com certificate and key with the credentials specified.
This key can be used with [Set-OpenAuthenticodeSignature](./Set-OpenAuthenticodeSignature.md) to sign a file that is located in an SSL.com account.
It uses the eSigner API to request a signed hash of the data needed without having the private key leave SSL.com's secure enclave.

Currently the only signing algorithm that is supported by SSL.com is SHA256, using any other algorithm will result in an error.

Before this cmdlet can be used as a key for signing files, a OAuth2 application needs to be registered for this cmdlet to use.
See [Register an Application with eSigner's CSC API](https://www.ssl.com/how-to/register-application-esigner-csc-api/) for a guide on how to set up a registered OAuth2 application.
When creating the registered app the following must be set:

+ `Application Name`: Can be anything but recommended to be something that can tie it back to this module.

+ `Redirect URI`: Must be `urn:ietf:wg:oauth:2.0:oob` to support this cmdlet for prompting for the authorization code interactively

+ `Scopes`: Must be `service`

Once registered the `Client ID` and `Client Secret` are used to authenticate as this registered OAuth2 application.
The `-UserName`/`-Password` or `-Credential` parameters can also be used in conjunction with `-ClientID`/`-ClientSecret` to automatically authenticate the user without any interactive prompts.
Using just `-ClientID`/`-ClientSecret` will have the module prompt for the authorization code alongside a URL that can get this one time code.

Once the key information has been retrieved, a signing operation will also require the One Time Password (OTP) value per operation (per `Set-OpenAuthenticodeSignature`/`Add-OpenAuthenticodeSignature` call).
These cmdlets will prompt for the OTP when required.
The `-TOTPSecret` parameter can be used to provide the TOPT secret code so that the OTP can be generated without any prompt.

Overall the following parameters are sensitive values and should be protected in whatever way possible:

+ `ClientSecret` - The registered OAuth2 application secret

+ `Credential` / `Username` / `Password` - The SSL.com credentials used for non-interactive logins

+ `TOPTSecret` - The certificate's TOPT secret code used for non-interactive OTP generation

## EXAMPLES

### Example 1: Create key with interactive prompts
```powershell
PS C:\> $keyParams = @{
    ClientId = 'AB19ajIo1GrcTm-tg2aq6-Zml1CJNtwcQzvp82Jv-wdnk'
    ClientSecret = '...'
}
PS C:\> $key = Get-OpenAuthenticodeSslDotComKey @keyParams

    No AuthorizationCode was specified. Please go to the following URL
    and paste in the result authorization code to continue.

    https://login.ssl.com/oauth2/authorize?client_id=AB19ajIo1GrcTm-tg2aq6-Zml1CJNtwcQzvp82Jv-wdnk&redirect_uri=urn:ietf:wg:oauth:2.0:oob&response_type=code&scope=service

    You may need to load the URL twice if the first attempt goes to the account
    settings page. The ClientID must be a registered OAuth application that has
    the service scope and redirect URL of 'urn:ietf:wg:oauth:2.0:oob' for this to work.
Authorization Code: *******************************************

PS C:\> Set-OpenAuthenticodeSignature test.ps1 -Key $key
Please enter OTP for b6216ec3-b5b7-44a7-8ac9-836ad49a1952 to authorize signing
OTP: 123456
```

This example will create a key object with the OAuth2 registered client.
As no username/password or authorization key is supplied, the cmdlet will prompt for the user to manually sign in with the link supplied and provide the authorization code it generates.
Once logged in successfully, it will select the first valid certificate available for use with signing.
When signing the data, a prompt for the One Time Password (OTP) will be shown.
Enter this OTP for the signing to continue.

### Example 2: Create key with no interaction
```powershell
PS C:\> $keyParams = @{
    ClientId = 'AB19ajIo1GrcTm-tg2aq6-Zml1CJNtwcQzvp82Jv-wdnk'
    ClientSecret = '...'
    UserName = 'username'
    Password = 'SSL.com Password'
    TOTPSecret = '...'
}
PS C:\> $key = Get-OpenAuthenticodeSslDotComKey @keyParams
PS C:\> Set-OpenAuthenticodeSignature test.ps1 -Key $key
```

Provides the `UserName` and `Password` (or alternatively use `-Credential`) to authorize the user with OAuth2 password based authentication.
The `-TOPTSecret` is also provided so that the signing operation will not need to prompt for the OTP.
Keep in mind the `-TOPTSecret` is not the OTP bin at the current time but rather the TOTP secret code (seed) that can be retrieved through the certificate details page.

### Example 3: Use a specific certificate specified by credential id for signing
```powershell
PS C:\> $keyParams = @{
    ClientId = 'AB19ajIo1GrcTm-tg2aq6-Zml1CJNtwcQzvp82Jv-wdnk'
    ClientSecret = '...'
    UserName = 'username'
    Password = 'SSL.com Password'
    TOTPSecret = '...'
    Certificate = '0a8b5f68-406b-4f61-88dc-3e7aaa8e6bbe'
}
PS C:\> $key = Get-OpenAuthenticodeSslDotComKey @keyParams
PS C:\> Set-OpenAuthenticodeSignature test.ps1 -Key $key
```

Specifies the eSigner credential ID associated with the certificate to use for signing instead of selecting the first certificate found.
If the certificate for this ID is not found, an error will be written.

### Example 4: Use a specific certificate specified by thumbprint for signing
```powershell
PS C:\> $cert  [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pathToCert)
PS C:\> $keyParams = @{
    ClientId = 'AB19ajIo1GrcTm-tg2aq6-Zml1CJNtwcQzvp82Jv-wdnk'
    ClientSecret = '...'
    UserName = 'username'
    Password = 'SSL.com Password'
    TOTPSecret = '...'
    Certificate = $cert.Thumbprint
}
PS C:\> $key = Get-OpenAuthenticodeSslDotComKey @keyParams
PS C:\> Set-OpenAuthenticodeSignature test.ps1 -Key $key
```

Specifies the certificate thumbprint of a certificate to use for signing.
This thumbprint can be retrieved from the `.crt` downloaded from the eSigner portal or just manually retrieved through other means.
If the certificate with this thumbprint is not found, an error will be written.

## PARAMETERS

### -ApiEndpoint
The SSL.com eSigner API endpoint to use for key operations.
This defaults to the production API for eSigner, use `https://cs-try.ssl.com/` when testing out the sandbox eSigner instance.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: https://cs.ssl.com/
Accept pipeline input: False
Accept wildcard characters: False
```

### -AuthorizationCode
The OAuth2 authorization code which can be retrieved manually through `https://login.ssl.com/` by selecting `AUTHORIZE` on a registered OAuth2 application for your account.
If omitted, the cmdlet will display a URL which can be used to retrieve this code interactively.
An Authorization Code can only be used once.

It might be necessary to open the link twice if the first attempt goes directly to the account management page.
The second attempt should redirect to a page that contains the authorization code that can be typed into the prompt to continue.

```yaml
Type: SecureString
Parameter Sets: AuthorizationCode
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Certificate
Selects the certificate to use for the signing operations.
This value can be one of the following:

+ eSigner credential ID GUID string

+ Certificate Thumbprint string

+ X509Certificate2 object

The eSigner credential ID is the GUID identifier for the signing credential associated with the certificate.
This can be retrieved through the eSigner certificate details page under the `SIGNING CREDENTIALS` section.

The certificate thumbprint string or X509Certificate2 is used to select the certificate in the eSigner account that matches with that thumbprint.

If no certificate or credential is specified, the first valid certificate found in the eSigner account will be used.
Use the `-Verbose` parameter to see what certificate was selected if none are provided.

```yaml
Type: SslDotComCertificate
Parameter Sets: (All)
Aliases: CredentialID

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ClientId
The registered OAuth client identifier that has been registered for `OpenAuthenticode`.
An OAuth2 application can be registered under https://login.ssl.com/ with the scope of `service` and redirect URI of `urn:ietf:wg:oauth:2.0:oob`.
It is important that the redirect URI is the one above to ensure OpenAuthenticode can prompt for an authorization code.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ClientSecret
The registered OAuth client secret that has been registered for `OpenAuthenticode`.
An OAuth2 application can be registered under https://login.ssl.com/ with the scope of `service` and redirect URI of `urn:ietf:wg:oauth:2.0:oob`.

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
The username and password credential for the SSL.com account.
This can be used to bypass the OAuth2 authorization prompt and log in without any interaction required.

```yaml
Type: PSCredential
Parameter Sets: Credential
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Password
The password for the SSL.com account.
This can be used with `-UserName` to bypass the OAuth2 authorization prompt and log in without any interaction required.

```yaml
Type: SecureString
Parameter Sets: UserName
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
New common parameter introduced in PowerShell 7.4.

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TOPTSecret
The Time-based One Time Password (TOTP) secret that can be used to generate OTP codes during signing.
This secret is generated in the eSigner console for the certificate when setting up the second factor authentication.
See the section [Type in your eSigner Time-based One-Time Password (TOTP)](https://www.ssl.com/how-to/automate-ev-code-signing-with-signtool-or-certutil-esigner/) for more information on how to get this code.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserName
The username for the SSL.com account.
This can be used with `-Password` to bypass the OAuth2 authorization prompt and log in without any interaction required.

```yaml
Type: String
Parameter Sets: UserName
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
None

## OUTPUTS

### OpenAuthenticode.Module.SslDotComKey
The SSL.com key object that can be used with the `-Key` parameter in `Set-OpenAuthenticodeSignature`.

## NOTES
SSL.com has functionality to scan the data for malware before it can sign the data.
If malware scanning is enabled on the certificate used for signing, the cmdlet will send the file(s)'s hash to SSL.com for a pre-check as required by their API.
The only way to avoid this step is to disable the malware checks in the certificate details page.

Using the `-Debug` parameter will output log level API operations and could expose sensitive data.
Make sure to only use `-Debug` for debugging scenarios to avoid accidentally exposing this data.

## RELATED LINKS

[eSigner FAQ](https://www.ssl.com/faqs/esigner-faq/)

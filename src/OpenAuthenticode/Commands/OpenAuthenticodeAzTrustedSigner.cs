using System;
using System.Diagnostics;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.CodeSigning;
using OpenAuthenticode.Keys;

namespace OpenAuthenticode.Commands;

[Cmdlet(VerbsCommon.Get, "OpenAuthenticodeAzTrustedSigner")]
[OutputType(typeof(AzureTrustedSigner))]
public sealed class GetOpenAuthenticodeAzTrustedSigner : AsyncPSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0
    )]
    public string AccountName { get; set; } = default!;

    [Parameter(
        Mandatory = true,
        Position = 1
    )]
    public string ProfileName { get; set; } = default!;

    [Parameter(
        Mandatory = true,
        Position = 2
    )]
    [ArgumentCompleter(typeof(AzureEndpointCompletionsAttribute))]
    [AzureEndpointTransformation]
    public Uri Endpoint { get; set; } = default!;

    [Parameter]
    public string? CorrelationId { get; set; }

    [Parameter()]
    public AzureTokenSource TokenSource { get; set; } = AzureTokenSource.Default;

    protected override async Task ProcessRecordAsync(AsyncPipeline pipeline, CancellationToken cancellationToken)
    {
        Debug.Assert(AccountName != null);
        Debug.Assert(ProfileName != null);
        Debug.Assert(Endpoint != null);

        CertificateProfileClientOptions options = new();
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsTelemetryEnabled = false;
        var cred = TokenCredentialBuilder.GetTokenCredential(TokenSource);
        CertificateProfileClient client = new(cred, endpoint: Endpoint, options: options);

        byte[] rawChain;
        try
        {
            pipeline.WriteVerbose($"Getting certificate chain from Azure Code Signing service for {AccountName} {ProfileName} at {Endpoint}");
            Response<Stream> chainResponse = await client.GetSignCertificateChainAsync(
                codeSigningAccountName: AccountName,
                certificateProfileName: ProfileName,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            rawChain = new byte[chainResponse.Value.Length];
            await chainResponse.Value.CopyToAsync(
                new MemoryStream(rawChain), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            ErrorRecord err = new(
                e,
                "AzTrustedSignerKeyError",
                ErrorCategory.NotSpecified,
                null);
            await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
            return;
        }

        pipeline.WriteVerbose("Importing certificate chain");
        X509Certificate2Collection chain = [];
        chain.Import(rawChain);

        X509Certificate2 cert = CertificateHelper.GetAzureTrustedSigningCertificate(chain, pipeline: pipeline);
        pipeline.WriteVerbose($"Creating AzureTrustedSigner object with cert '{cert.SubjectName.Name}' - {cert.Thumbprint}");

        try
        {
            KeyType keyType = cert.GetOpenAuthenticodeKeyType();
            if (keyType != KeyType.RSA)
            {
                throw new NotImplementedException($"Azure Trusting Signing implementation does not support {keyType} keys");
            }
        }
        catch (Exception e)
        {
            ErrorRecord err = new(
                e,
                "AzTrustedSigningUnknownKeyType",
                ErrorCategory.NotSpecified,
                null);
            await pipeline.WriteErrorAsync(err, cancellationToken: cancellationToken).ConfigureAwait(false);
            return;
        }

        AzureTrustedSigner signerKey = new(
            client,
            cert,
            AccountName,
            ProfileName,
            CorrelationId);
        await pipeline.WriteObjectAsync(signerKey, cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}

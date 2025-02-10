using System;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace OpenAuthenticode.Module;

[Cmdlet(VerbsCommon.Get, "OpenAuthenticodeAzKey")]
[OutputType(typeof(AzureKey))]
public sealed class GetOpenAuthenticodeAzKey : AsyncPSCmdlet
{
    [Parameter(Mandatory = true, Position = 0)]
    [Alias("VaultName")]
    public string Vault { get; set; } = "";

    [Parameter(Mandatory = true, Position = 1)]
    [Alias("CertificateName")]
    public string Certificate { get; set; } = "";

    [Parameter]
    public AzureTokenSource TokenSource { get; set; } = AzureTokenSource.Default;

    protected override async Task ProcessRecordAsync()
    {
        string keyVaultUrl = $"https://{Vault}.vault.azure.net/";

        try
        {
            TokenCredential cred = TokenCredentialBuilder.GetTokenCredential(TokenSource);

            CertificateClient certClient = new(new Uri(keyVaultUrl), cred);
            KeyVaultCertificateWithPolicy certInfo = await certClient.GetCertificateAsync(
                Certificate).ConfigureAwait(false);

            CryptographyClient c = new(certInfo.KeyId, cred);
            X509Certificate2 cert = new(certInfo.Cer);
            KeyType keyType = cert.GetOpenAuthenticodeKeyType();

            SignatureAlgorithm? ecdsaAlgorithm = null;
            HashAlgorithmName? defaultAlgorithm = null;
            HashAlgorithmName[] allowedAlgorithms;
            string? curveName = certInfo.Policy.KeyCurveName?.ToString();
            if (curveName is not null)
            {
                (string curveAzureName, defaultAlgorithm) = AzureKeyAlgorithms.GetAzureEcdsaInfo(curveName);
                ecdsaAlgorithm = new(curveAzureName);
                allowedAlgorithms = [defaultAlgorithm.Value];
            }
            else
            {
                allowedAlgorithms = [
                    HashAlgorithmName.SHA1,
                    HashAlgorithmName.SHA256,
                    HashAlgorithmName.SHA384,
                    HashAlgorithmName.SHA512,
                ];
            }

            AzureKey azureKey = new(c, cert, keyType, allowedAlgorithms, defaultAlgorithm, ecdsaAlgorithm);
            WriteObject(azureKey);
        }
        catch (Exception e)
        {
            ErrorRecord err = new(
                e,
                "AzKeyError",
                ErrorCategory.NotSpecified,
                null);
            WriteError(err);
        }
    }
}

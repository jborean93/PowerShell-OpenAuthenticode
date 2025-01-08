using System;
using System.Management.Automation;

namespace OpenAuthenticode.Shared;

[Cmdlet(VerbsCommon.Get, "OpenAuthenticodeAzKey")]
[OutputType(typeof(AzureKey))]
public sealed class GetOpenAuthenticodeAzKey : PSCmdlet
{
    [Parameter(Mandatory = true, Position = 0)]
    [Alias("VaultName")]
    public string Vault { get; set; } = "";

    [Parameter(Mandatory = true, Position = 1)]
    [Alias("CertificateName")]
    public string Certificate { get; set; } = "";

    [Parameter(Position = 2)]
    public AzureTokenSource TokenSource { get; set; } = AzureTokenSource.Default;

    protected override void ProcessRecord()
    {
        try
        {
            WriteObject(AzureKey.Create(Vault, Certificate, TokenSource));
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

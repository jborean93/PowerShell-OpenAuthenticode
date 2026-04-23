using System;
using Azure.Core;
using Azure.Identity;

namespace OpenAuthenticode;

public enum AzureTokenSource
{
    Default,
    Environment,
    AzurePowerShell,
    AzureCli,
    ManagedIdentity,
}

public static class TokenCredentialBuilder
{
    public static TokenCredential GetTokenCredential(AzureTokenSource tokenSource) => tokenSource switch
    {
        AzureTokenSource.Default => new DefaultAzureCredential(includeInteractiveCredentials: false),
        AzureTokenSource.Environment => new EnvironmentCredential(),
        AzureTokenSource.AzurePowerShell => new AzurePowerShellCredential(),
        AzureTokenSource.AzureCli => new AzureCliCredential(),
        AzureTokenSource.ManagedIdentity => new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned),
        _ => throw new NotImplementedException($"Unknown AzureTokenSource {tokenSource} specified."),
    };
}

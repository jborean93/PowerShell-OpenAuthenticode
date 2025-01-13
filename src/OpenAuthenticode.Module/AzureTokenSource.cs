using System;
using Azure.Core;
using Azure.Identity;

namespace OpenAuthenticode.Module;

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
        AzureTokenSource.ManagedIdentity => new ManagedIdentityCredential(),
        _ => throw new NotImplementedException($"Unknown AzureTokenSource {tokenSource} specified."),
    };
}

using Azure.Core;
using Azure.Identity;

namespace OpenAuthenticode.Shared {
    public enum AzureTokenSource {
        Default,
        Environment,
        AzurePowerShell,
        AzureCli,
        ManagedIdentity,
    }

    public class TokenCredentialBuilder {
        public static TokenCredential GetTokenCredential(AzureTokenSource tokenSource) {
            switch(tokenSource) {
                case AzureTokenSource.Environment:
                    return new EnvironmentCredential();
                case AzureTokenSource.AzurePowerShell:
                    return new AzurePowerShellCredential();
                case AzureTokenSource.AzureCli:
                    return new AzureCliCredential();
                case AzureTokenSource.ManagedIdentity:
                    return new ManagedIdentityCredential();
                default:
                    return new DefaultAzureCredential(includeInteractiveCredentials: false);
            }
        }
    }
}

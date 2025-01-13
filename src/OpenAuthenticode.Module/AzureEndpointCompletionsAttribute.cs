using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Language;

namespace OpenAuthenticode.Module;

public class AzureEndpointCompletionsAttribute : IArgumentCompleter
{
    public static CompletionResult[] _knownEndpoints = [
        new CompletionResult(
            nameof(AzureEndpointTransformationAttribute.EastUS),
            AzureEndpointTransformationAttribute.EastUSName,
            CompletionResultType.Text,
            AzureEndpointTransformationAttribute.EastUS),

        new CompletionResult(
            nameof(AzureEndpointTransformationAttribute.WestCentralUS),
            AzureEndpointTransformationAttribute.WestCentralUSName,
            CompletionResultType.Text,
            AzureEndpointTransformationAttribute.WestCentralUS),

        new CompletionResult(
            nameof(AzureEndpointTransformationAttribute.WestUS2),
            AzureEndpointTransformationAttribute.WestUS2Name,
            CompletionResultType.Text,
            AzureEndpointTransformationAttribute.WestUS2),

        new CompletionResult(
            nameof(AzureEndpointTransformationAttribute.WestUS3),
            AzureEndpointTransformationAttribute.WestUS3Name,
            CompletionResultType.Text,
            AzureEndpointTransformationAttribute.WestUS3),

        new CompletionResult(
            nameof(AzureEndpointTransformationAttribute.NorthEurope),
            AzureEndpointTransformationAttribute.NorthEuropeName,
            CompletionResultType.Text,
            AzureEndpointTransformationAttribute.NorthEurope),

        new CompletionResult(
            nameof(AzureEndpointTransformationAttribute.WestEurope),
            AzureEndpointTransformationAttribute.WestEuropeName,
            CompletionResultType.Text,
            AzureEndpointTransformationAttribute.WestEurope),
    ];

    public static CompletionResult[] _knownEndpointsUrl = [
        new CompletionResult(
            AzureEndpointTransformationAttribute.EastUS,
            AzureEndpointTransformationAttribute.EastUSName,
            CompletionResultType.Text,
            nameof(AzureEndpointTransformationAttribute.EastUS)),

        new CompletionResult(
            AzureEndpointTransformationAttribute.WestCentralUS,
            AzureEndpointTransformationAttribute.WestCentralUSName,
            CompletionResultType.Text,
            nameof(AzureEndpointTransformationAttribute.WestCentralUS)),

        new CompletionResult(
            AzureEndpointTransformationAttribute.WestUS2,
            AzureEndpointTransformationAttribute.WestUS2Name,
            CompletionResultType.Text,
            nameof(AzureEndpointTransformationAttribute.WestUS2)),

        new CompletionResult(
            AzureEndpointTransformationAttribute.WestUS3,
            AzureEndpointTransformationAttribute.WestUS3Name,
            CompletionResultType.Text,
            nameof(AzureEndpointTransformationAttribute.WestUS3)),

        new CompletionResult(
            AzureEndpointTransformationAttribute.NorthEurope,
            AzureEndpointTransformationAttribute.NorthEuropeName,
            CompletionResultType.Text,
            nameof(AzureEndpointTransformationAttribute.NorthEurope)),

        new CompletionResult(
            AzureEndpointTransformationAttribute.WestEurope,
            AzureEndpointTransformationAttribute.WestEuropeName,
            CompletionResultType.Text,
            nameof(AzureEndpointTransformationAttribute.WestEurope)),
    ];

    public IEnumerable<CompletionResult> CompleteArgument(
        string commandName,
        string parameterName,
        string wordToComplete,
        CommandAst commandAst,
        IDictionary fakeBoundParameters)
    {
        if (string.IsNullOrWhiteSpace(wordToComplete))
        {
            wordToComplete = "";
        }

        WildcardPattern wildcardPattern = new($"{wordToComplete}*", WildcardOptions.IgnoreCase);

        if (wordToComplete.StartsWith("https://", System.StringComparison.OrdinalIgnoreCase))
        {
            foreach (CompletionResult completion in _knownEndpointsUrl)
            {
                if (wildcardPattern.IsMatch(completion.CompletionText) || wildcardPattern.IsMatch(completion.ToolTip))
                {
                    yield return completion;
                }
            }

            yield break;
        }

        foreach (CompletionResult completion in _knownEndpoints)
        {
            if (wildcardPattern.IsMatch(completion.CompletionText) || wildcardPattern.IsMatch(completion.ToolTip))
            {
                yield return completion;
            }
        }
    }
}

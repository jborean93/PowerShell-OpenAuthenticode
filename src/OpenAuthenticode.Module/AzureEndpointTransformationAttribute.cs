using System;
using System.Management.Automation;

namespace OpenAuthenticode.Module;

public sealed class AzureEndpointTransformationAttribute : ArgumentTransformationAttribute
{
    public const string EastUS = "https://eus.codesigning.azure.net";
    public const string EastUSName = "East US";

    public const string WestCentralUS = "https://wcus.codesigning.azure.net";
    public const string WestCentralUSName = "West Central US";

    public const string WestUS2 = "https://wus2.codesigning.azure.net";
    public const string WestUS2Name = "West US 2";

    public const string WestUS3 = "https://wus3.codesigning.azure.net";
    public const string WestUS3Name = "West US 3";

    public const string NorthEurope = "https://neu.codesigning.azure.net";
    public const string NorthEuropeName = "North Europe";

    public const string WestEurope = "https://weu.codesigning.azure.net";
    public const string WestEuropeName = "West Europe";

    public override object Transform(EngineIntrinsics engineIntrinsics, object inputData)
    {
        string value = LanguagePrimitives.ConvertTo<string>(inputData);
        string valueUpper = value.ToUpperInvariant();
        if (valueUpper == nameof(EastUS).ToUpperInvariant())
        {
            return new Uri(EastUS);
        }
        else if (valueUpper == nameof(WestCentralUS).ToUpperInvariant())
        {
            return new Uri(WestCentralUS);
        }
        else if (valueUpper == nameof(WestUS2).ToUpperInvariant())
        {
            return new Uri(WestUS2);
        }
        else if (valueUpper == nameof(WestUS3).ToUpperInvariant())
        {
            return new Uri(WestUS3);
        }
        else if (valueUpper == nameof(NorthEurope).ToUpperInvariant())
        {
            return new Uri(NorthEurope);
        }
        else if (valueUpper == nameof(WestEurope).ToUpperInvariant())
        {
            return new Uri(WestEurope);
        }

        return inputData;
    }
}

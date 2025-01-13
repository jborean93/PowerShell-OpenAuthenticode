using System.Management.Automation;
using System.Security;

namespace OpenAuthenticode.Module;

internal sealed class StringAsSecureStringTransformer : ArgumentTransformationAttribute
{
    public override object Transform(EngineIntrinsics engineIntrinsics, object inputData)
    {
        if (inputData is PSObject psObj)
        {
            inputData = psObj.BaseObject;
        }

        return inputData switch
        {
            SecureString => inputData,
            string s => FromString(s),
            _ => throw new ArgumentTransformationMetadataException(
                $"Could not convert input '{inputData}' to a valid SecureString object."),
        };
    }

    private SecureString FromString(string value)
    {
        SecureString s = new();
        foreach (char c in value)
        {
            s.AppendChar(c);
        }

        return s;
    }
}

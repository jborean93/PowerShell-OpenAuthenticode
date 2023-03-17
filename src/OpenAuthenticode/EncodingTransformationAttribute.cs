using System;
using System.Management.Automation;
using System.Text;
using System.Globalization;

namespace OpenAuthenticode;

public sealed class EncodingTransformAttribute : ArgumentTransformationAttribute
{
    public override object Transform(EngineIntrinsics engineIntrinsics, object inputData) => inputData switch
    {
        Encoding => inputData,
        string s => GetEncodingFromString(s.ToUpperInvariant()),
        int i => Encoding.GetEncoding(i),
        _ => throw new ArgumentTransformationMetadataException($"Could not convert input '{inputData}' to a valid Encoding object."),
    };

    private static Encoding GetEncodingFromString(string encoding) => encoding switch
    {
        "ASCII" => new ASCIIEncoding(),
        "ANSI" => Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.ANSICodePage),
        "BIGENDIANUNICODE" => new UnicodeEncoding(true, true),
        "BIGENDIANUTF32" => new UTF32Encoding(true, true),
        "OEM" => Console.OutputEncoding,
        "UNICODE" => new UnicodeEncoding(),
        "UTF8" => new UTF8Encoding(),
        "UTF8BOM" => new UTF8Encoding(true),
        "UTF8NOBOM" => new UTF8Encoding(),
        "UTF32" => new UTF32Encoding(),
        _ => Encoding.GetEncoding(encoding),
    };
}

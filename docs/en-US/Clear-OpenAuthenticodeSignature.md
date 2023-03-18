---
external help file: OpenAuthenticode.dll-Help.xml
Module Name: OpenAuthenticode
online version:
schema: 2.0.0
---

# Clear-OpenAuthenticodeSignature

## SYNOPSIS
Removes all Authenticode signatures from the path specified.

## SYNTAX

### Path (Default)
```
Clear-OpenAuthenticodeSignature [-Path] <String[]> [-Encoding <Encoding>] [-Provider <AuthenticodeProvider>]
 [-WhatIf] [-Confirm] [<CommonParameters>]
```

### LiteralPath
```
Clear-OpenAuthenticodeSignature -LiteralPath <String[]> [-Encoding <Encoding>]
 [-Provider <AuthenticodeProvider>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Clears the Authenticode signature from the path specified.
This effectively removes the signature contents from the file specified making it unsigned.

No action is performed if the file has no Authenticode signature present.

See [about_AuthenticodeProviders](./about_AuthenticodeProviders.md) for more information about what providers are currently supported.
When using a file path that has no extension, an explicit `-Provider` must be specified to indicate what Authenticode provider needs to be used to retrieve and validate the signature.

## EXAMPLES

### Example 1: Remove the Authenticode signature for a file
```powershell
PS C:\> Clear-OpenAuthenticodeSignature -Path test.ps1
```

Removes the Authenticode signature information on the PowerShell script `test.ps1`

### Example 2: Remove the Authenticode signature on a file without an extension
```powershell
PS C:\> Clear-OpenAuthenticodeSignature -Path my_binary -Provider PEBinary
```

Removes the Authenticode signature information on the PE binary file `my_binary`.
As the file has no extension, the `-Provider` parameter tells the cmdlet how to manage the file `my_binary`.

## PARAMETERS

### -Encoding
A hint to provide to the Authenticode provider that indicates what the file string encoding method is.
This is only used by Authenticode providers that need to read the file as a string, like PowerShell.
The default used is dependent on the Authenticode provider but most commonly will be `UTF-8`.

This accepts a `System.Text.Encoding` type but also a string or int representing the encoding from `[System.Text.Encoding]::GetEncoding(...)`.
Some common encoding values are:

* `Utf8` - UTF-8 but without a Byte Order Mark (BOM)
* `ASCII` - ASCII (bytes 0-127)
* `ANSI` - The ANSI encoding commonly used in legacy Windows encoding
* `OEM` - The value of `[System.Text.Encoding]::Default` which is UTF-8 without a BOM
* `Unicode` - UTF-16-LE
* `Utf8Bom` - UTF-8 but with a BOM
* `Utf8NoBom` - Same as `Utf8`

The `ANSI` encoding typically refers to the legacy Windows encoding used in older PowerShell versions.
If creating a script that should be used across the various PowerShell versions, it is highly recommended to use an encoding with a `BOM` like `Utf8Bom` or `Unicode`.

```yaml
Type: Encoding
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LiteralPath
Specifies the path to the files to clear the Authenticode signature on.
Unlike `-Path`, the path is used exactly as it is typed, no wildcard matching will occur.

```yaml
Type: String[]
Parameter Sets: LiteralPath
Aliases: PSPath

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Path
The path to the files to clear the Authenticode signature on.
Wildcards are permitted and a signature will be outputted for every file that matches the wildcard.
This is only supported for paths in the FileSystem provider.

```yaml
Type: String[]
Parameter Sets: Path
Aliases: FilePath

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: True
```

### -Provider
Specify the Authenticode provider used to extract the signature.
This is required if the `-Content` or `-RawContent` parameter is specified.
If `-Path`, or `-LiteralPath` is specified, the provider is found based on the extension of the file being read.
If the file has no extension then an explicit provider must be specified.

Valid providers are:

* `NotSpecified` - Uses the file extension to find the provider
* `PowerShell` - Uses the PowerShell script Authenticode provider
* `PEBinary` - Windows `.exe`, `.dll` files, including cross platform dotnet assemblies

```yaml
Type: AuthenticodeProvider
Parameter Sets: (All)
Aliases:
Accepted values: NotSpecified, PowerShell, PEBinary

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String[]
Accepts a list of paths for the `-Path` parameter.

## OUTPUTS

### None
None

## NOTES

## RELATED LINKS

[Authenticode Digital Signatures](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)

# Copyright: (c) 2026, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

#Requires -Version 7.4

using namespace System.Buffers.Binary
using namespace System.IO
using namespace System.Text

Add-Type -TypeDefinition @'
using System;

public static class SpanHelpers
{
    public static int LastIndexOf(ArraySegment<byte> data, byte[] pattern)
        => MemoryExtensions.LastIndexOf(data.AsSpan(), pattern.AsSpan());
}
'@

class EndOfCentralDirectory {
    static [int]$Signature = 0x06054b50
    static [int]$MinSize = 22

    [long]$Offset
    [short]$DiskNumber
    [short]$DiskWithCentralDirectory
    [short]$CentralDirectoryCountForThisDisk
    [short]$CentralDirectoryCount
    [int]$CentralDirectorySize
    [int]$CentralDirectoryOffset
    [short]$CommentLength
    [byte[]]$Comment
}

class EndOfCentralDirectory64Locator {
    static [int]$Signature = 0x07064b50
    static [int]$MinSize = 20

    [long]$Offset
    [int]$DiskWithEOCD64
    [long]$EOCD64Offset
    [int]$TotalDisks
}

class EndOfCentralDirectory64 {
    static [int]$Signature = 0x06064b50
    static [int]$MinSize = 56

    [long]$Offset
    [long]$SizeOfEOCD64
    [short]$VersionMadeBy
    [short]$VersionNeeded
    [int]$DiskNumber
    [int]$DiskWithCentralDirectory
    [long]$CentralDirectoryCountForThisDisk
    [long]$CentralDirectoryCount
    [long]$CentralDirectorySize
    [long]$CentralDirectoryOffset
    [byte[]]$ExtensibleData
}

class ExtraField {
    [short]$HeaderId
    [short]$DataSize
    [byte[]]$Data
}

[Flags()] enum FileFlags : short {
    None = 0x0000
    Encrypted = 0x0001
    Compression1 = 0x0002
    Compression2 = 0x0004
    DataDescriptor = 0x0008
    EnhancedDeflation = 0x0010
    CompressedPatchedData = 0x0020
    StrongEncryption = 0x0040
    Reserved7 = 0x0080
    Reserved8 = 0x0100
    Reserved9 = 0x0200
    Reserved10 = 0x0400
    UTF8Encoding = 0x0800
    Reserved12 = 0x1000
    CentralDirectoryEncrypted = 0x2000
    Reserved14 = 0x4000
    Reserved15 = "0x8000"
}

class CentralDirectory {
    static [int]$Signature = 0x02014b50
    static [int]$MinSize = 46

    [long]$Offset
    [short]$VersionMadeBy
    [short]$VersionNeeded
    [FileFlags]$Flags
    [short]$CompressionMethod
    [short]$LastModTime
    [short]$LastModDate
    [int]$CRC32
    [int]$CompressedSize
    [int]$UncompressedSize
    [short]$FileNameLength
    [short]$ExtraFieldLength
    [short]$FileCommentLength
    [short]$DiskNumberStart
    [short]$InternalFileAttributes
    [int]$ExternalFileAttributes
    [int]$LocalHeaderOffset
    [string]$FileName
    [ExtraField[]]$ExtraFields
    [string]$FileComment
}

class DataDescriptor {
    static [int]$Signature = 0x08074b50

    [long]$Offset
    [int]$CRC32
    [long]$CompressedSize
    [long]$UncompressedSize
}

class LocalFileHeader {
    static [int]$Signature = 0x04034b50
    static [int]$MinSize = 30

    [long]$Offset
    [short]$VersionNeeded
    [FileFlags]$Flags
    [short]$CompressionMethod
    [short]$LastModTime
    [short]$LastModDate
    [int]$CRC32
    [int]$CompressedSize
    [int]$UncompressedSize
    [short]$FileNameLength
    [short]$ExtraFieldLength
    [string]$FileName
    [ExtraField[]]$ExtraFields
    [long]$CompressedDataOffset
    [DataDescriptor]$DataDescriptor
}

class ZipStructure {
    [EndOfCentralDirectory]$EOCD
    [EndOfCentralDirectory64Locator]$EOCD64Locator
    [EndOfCentralDirectory64]$EOCD64
    [CentralDirectory[]]$CentralDirectoryEntries
    [LocalFileHeader[]]$LocalFileHeaders
}


function Write-ZipInfo {
    param(
        [Parameter(Mandatory)]
        [string]
        $Message,

        [ValidateSet('Black', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White',
                     'BrightBlack', 'BrightBlue', 'BrightGreen', 'BrightCyan', 'BrightRed',
                     'BrightMagenta', 'BrightYellow', 'BrightWhite')]
        [string]
        $ForegroundColor = 'BrightWhite'
    )

    $colorStyle = $PSStyle.Foreground."$ForegroundColor"
    $coloredMessage = "$colorStyle$Message$($PSStyle.Reset)"
    Write-Information $coloredMessage
}

function ConvertFrom-DosDateTime {
    <#
    .SYNOPSIS
    Converts DOS date/time to .NET DateTime.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [short]$DosTime,

        [Parameter(Mandatory)]
        [short]$DosDate
    )

    try {
        $year = (($DosDate -shr 9) -band 0x7F) + 1980
        $month = ($DosDate -shr 5) -band 0x0F
        $day = $DosDate -band 0x1F

        $hour = ($DosTime -shr 11) -band 0x1F
        $minute = ($DosTime -shr 5) -band 0x3F
        $second = ($DosTime -band 0x1F) * 2

        if ($year -lt 1980 -or $year -gt 2107 -or $month -lt 1 -or $month -gt 12 -or $day -lt 1 -or $day -gt 31) {
            return $null
        }

        [DateTime]::new($year, $month, $day, $hour, $minute, $second)
    }
    catch {
        return $null
    }
}

function Get-CompressionMethodName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [short]$Method
    )

    switch ($Method) {
        0 { "Stored (no compression)" }
        1 { "Shrunk" }
        2 { "Reduced (factor 1)" }
        3 { "Reduced (factor 2)" }
        4 { "Reduced (factor 3)" }
        5 { "Reduced (factor 4)" }
        6 { "Imploded" }
        7 { "Reserved (Tokenizing)" }
        8 { "Deflated" }
        9 { "Enhanced Deflate" }
        10 { "PKWare DCL Imploded" }
        12 { "BZIP2" }
        14 { "LZMA" }
        18 { "IBM TERSE" }
        19 { "IBM LZ77 z" }
        98 { "PPMd" }
        default { "Unknown ($Method)" }
    }
}

function Get-ZipEndOfCentralDirectory {
    [OutputType([EndOfCentralDirectory])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [FileStream]
        $Stream
    )

    Write-ZipInfo "Searching for End of Central Directory..." -ForegroundColor BrightCyan

    $signature = [byte[]]::new(4)
    [BinaryPrimitives]::WriteInt32LittleEndian($signature, [EndOfCentralDirectory]::Signature)
    $minSize = [EndOfCentralDirectory]::MinSize

    # The EOCD must be located within the last 64KiB + EOCD_MIN_SIZE. The 64KiB
    # is the maximum size of the comment field.
    $bufferSize = $minSize + 65535
    if ($Stream.Length -lt $bufferSize) {
        $bufferSize = $Stream.Length
    }
    $buffer = [byte[]]::new($bufferSize)

    Write-ZipInfo "  Search window: $bufferSize bytes from EOF" -ForegroundColor BrightWhite

    try {
        $bufferOffset = $Stream.Length - $bufferSize
        $null = $Stream.Seek($bufferOffset, [SeekOrigin]::Begin)
        $null = $Stream.Read($buffer, 0, $buffer.Length)
        $dataView = [ArraySegment[byte]]::new($buffer)

        $pos = -1
        while ($true) {
            $pos = [SpanHelpers]::LastIndexOf($dataView, $signature)
            if ($pos -eq -1) {
                break
            }

            if ($Stream.Length - ($bufferOffset + $pos) -lt $minSize) {
                # Not enough data to contain the EOCD so keep searching
                $dataView = $dataView.Slice(0, $pos)
                continue
            }

            # Verify the comment length is valid and fits in the remaining
            # data after the EOCD structure.
            $commentLen = [BinaryPrimitives]::ReadUInt16LittleEndian(
                $dataView.Slice($pos + 20, 2))
            if ($pos + $minSize + $commentLen -le $buffer.Length) {
                break
            }

            $dataView = $dataView.Slice(0, $pos)
        }

        if ($pos -eq -1) {
            throw "End of Central Directory signature not found"
        }

        $actualOffset = $bufferOffset + $pos
        Write-ZipInfo "  Found EOCD at offset 0x$($actualOffset.ToString('X8')) ($actualOffset)" -ForegroundColor BrightGreen

        $diskNumber = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice($pos + 4, 2))
        $diskWithCD = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice($pos + 6, 2))
        $entriesOnDisk = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice($pos + 8, 2))
        $totalEntries = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice($pos + 10, 2))
        $cdSize = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice($pos + 12, 4))
        $cdOffset = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice($pos + 16, 4))
        $commentLen = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice($pos + 20, 2))
        if ($commentLen) {
            $comment = $dataView.Slice($pos + 22, $commentLen).ToArray()
        } else {
            $comment = [Array]::Empty[byte]()
        }

        Write-ZipInfo "  Total entries: $totalEntries" -ForegroundColor BrightWhite
        Write-ZipInfo "  CD offset: 0x$($cdOffset.ToString('X8'))" -ForegroundColor BrightWhite
        Write-ZipInfo "  CD size: $cdSize bytes" -ForegroundColor BrightWhite

        [EndOfCentralDirectory]@{
            Offset = $bufferOffset + $pos

            DiskNumber = $diskNumber
            DiskWithCentralDirectory = $diskWithCD
            CentralDirectoryCountForThisDisk = $entriesOnDisk
            CentralDirectoryCount = $totalEntries
            CentralDirectorySize = $cdSize
            CentralDirectoryOffset = $cdOffset
            CommentLength = $commentLen
            Comment = $comment
        }
    }
    catch {
        $err = $_
        $err.ErrorDetails = "Error processing file '$($fs.Name)': $($err)"
        $PSCmdlet.WriteError($err)
    }
}

function Get-Zip64EndOfCentralDirectoryLocator {
    [OutputType([EndOfCentralDirectory64Locator])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [FileStream]
        $Stream,

        [Parameter(Mandatory)]
        [long]
        $EOCDOffset
    )

    Write-ZipInfo "Searching for ZIP64 EOCD Locator..." -ForegroundColor BrightCyan

    $signature = [EndOfCentralDirectory64Locator]::Signature
    $minSize = [EndOfCentralDirectory64Locator]::MinSize

    $offset = $EOCDOffset - $minSize
    if ($offset -lt 0) {
        throw "Not enough data before EOCD to contain EOCD64 locator"
    }

    $buffer = [byte[]]::new($minSize)
    $null = $Stream.Seek($offset, [SeekOrigin]::Begin)
    $null = $Stream.Read($buffer, 0, $buffer.Length)

    $dataView = [ArraySegment[byte]]::new($buffer)
    $signature = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(0, 4))
    if ($signature -ne [EndOfCentralDirectory64Locator]::Signature) {
        # Signature does not match, there is no EOCD64 locator
        throw "EOCD64 locator signature not found at expected offset"
    }

    $diskWithEOCD64 = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(4, 4))
    $eocd64Offset = [BinaryPrimitives]::ReadInt64LittleEndian($dataView.Slice(8, 8))
    $totalDisks = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(16, 4))

    Write-ZipInfo "  Found ZIP64 EOCD Locator at offset 0x$($offset.ToString('X8'))" -ForegroundColor BrightGreen
    Write-ZipInfo "  ZIP64 EOCD offset: 0x$($eocd64Offset.ToString('X16'))" -ForegroundColor BrightWhite

    [EndOfCentralDirectory64Locator]@{
        Offset = $offset
        DiskWithEOCD64 = $diskWithEOCD64
        EOCD64Offset = $eocd64Offset
        TotalDisks = $totalDisks
    }
}

function Get-Zip64EndOfCentralDirectory {
    [OutputType([EndOfCentralDirectory64])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [FileStream]
        $Stream,

        [Parameter(Mandatory)]
        [long]
        $EOCD64Offset
    )

    Write-ZipInfo "Reading ZIP64 End of Central Directory..." -ForegroundColor BrightCyan

    $signature = [EndOfCentralDirectory64]::Signature
    $minSize = [EndOfCentralDirectory64]::MinSize

    $endOffset = $EOCD64Offset + $minSize
    if ($Stream.Length -lt $endOffset) {
        throw "Not enough data to read EOCD64 structure"
    }

    $bufferSize = 64KB
    if ($bufferSize -gt $Stream.Length) {
        $bufferSize = $Stream.Length
    }

    $buffer = [byte[]]::new($bufferSize)
    $null = $Stream.Seek($EOCD64Offset, [SeekOrigin]::Begin)
    $null = $Stream.Read($buffer, 0, $buffer.Length)

    $dataView = [ArraySegment[byte]]::new($buffer)
    $signature = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(0, 4))
    if ($signature -ne [EndOfCentralDirectory64]::Signature) {
        # Signature does not match, there is no EOCD64
        throw "EOCD64 signature not found at expected offset"
    }

    $sizeOfEOCD64 = [BinaryPrimitives]::ReadInt64LittleEndian($dataView.Slice(4, 12))
    $versionMadeBy = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(12, 2))
    $versionNeeded = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(14, 2))
    $diskNumber = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(16, 4))
    $diskWithCD = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(20, 4))
    $entriesOnDisk = [BinaryPrimitives]::ReadInt64LittleEndian($dataView.Slice(24, 8))
    $totalEntries = [BinaryPrimitives]::ReadInt64LittleEndian($dataView.Slice(32, 8))
    $cdSize = [BinaryPrimitives]::ReadInt64LittleEndian($dataView.Slice(40, 8))
    $cdOffset = [BinaryPrimitives]::ReadInt64LittleEndian($dataView.Slice(48, 8))

    Write-ZipInfo "  Found ZIP64 EOCD at offset 0x$($EOCD64Offset.ToString('X16'))" -ForegroundColor BrightGreen
    Write-ZipInfo "  Total entries: $totalEntries" -ForegroundColor BrightWhite
    Write-ZipInfo "  CD offset: 0x$($cdOffset.ToString('X16'))" -ForegroundColor BrightWhite
    Write-ZipInfo "  CD size: $cdSize bytes" -ForegroundColor BrightWhite

    $extensibleLength = $sizeOfEOCD64 - 44
    if ($extensibleLength) {
        Write-ZipInfo "  Extensible data: $extensibleLength bytes" -ForegroundColor BrightYellow
        if (($bufferSize - $minSize) -lt $extensibleLength) {
            $extensibleData = [byte[]]::new($extensibleLength)
            $null = $Stream.Seek($EOCD64Offset + $minSize, [SeekOrigin]::Begin)
            $null = $Stream.Read($extensibleData, 0, $extensibleData.Length)
        }
        else {
            $extensibleData = $dataView.Slice(56, $extensibleLength).ToArray()
        }
    } else {
        $extensibleData = [Array]::Empty[byte]()
    }

    [EndOfCentralDirectory64]@{
        Offset = $EOCD64Offset
        SizeOfEOCD64 = $sizeOfEOCD64
        VersionMadeBy = $versionMadeBy
        VersionNeeded = $versionNeeded
        DiskNumber = $diskNumber
        DiskWithCentralDirectory = $diskWithCD
        CentralDirectoryCountForThisDisk = $entriesOnDisk
        CentralDirectoryCount = $totalEntries
        CentralDirectorySize = $cdSize
        CentralDirectoryOffset = $cdOffset
        ExtensibleData = $extensibleData
    }
}

function Get-ZipExtraFieldName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [short]$HeaderId
    )

    switch ($HeaderId) {
        0x0001 { "ZIP64 extended information" }
        0x0007 { "AV Info" }
        0x0008 { "Reserved for extended language encoding data (PFS)" }
        0x0009 { "OS/2" }
        0x000a { "NTFS" }
        0x000c { "OpenVMS" }
        0x000d { "UNIX" }
        0x000e { "Reserved for file stream and fork descriptors" }
        0x000f { "Patch Descriptor" }
        0x0014 { "PKCS#7 Store for X.509 Certificates" }
        0x0015 { "X.509 Certificate ID and Signature for individual file" }
        0x0016 { "X.509 Certificate ID for Central Directory" }
        0x0017 { "Strong Encryption Header" }
        0x0018 { "Record Management Controls" }
        0x0019 { "PKCS#7 Encryption Recipient Certificate List" }
        0x0065 { "IBM S/390 (Z390), AS/400 (I400) attributes" }
        0x0066 { "Reserved for IBM S/390 (Z390), AS/400 (I400) attributes - compressed" }
        0x4690 { "POSZIP 4690 (reserved)" }
        0x5455 { "Extended Timestamp" }
        0x5855 { "Info-ZIP UNIX (original)" }
        0x6375 { "Info-ZIP Unicode Comment" }
        0x6542 { "BeOS/BeBox" }
        0x7075 { "Info-ZIP Unicode Path" }
        0x7441 { "AtheOS/Syllable" }
        0x756e { "ASi UNIX" }
        0x7855 { "Info-ZIP UNIX (new)" }
        0x7875 { "Info-ZIP UNIX 3rd generation" }
        0xa220 { "Microsoft Open Packaging Growth Hint" }
        0xfd4a { "SMS/QDOS" }
        0x9901 { "WinZip AES encryption" }
        0x9902 { "WinZip Unicode Filename" }
        default { "Unknown (0x$($HeaderId.ToString('X4')))" }
    }
}

function Format-ZipExtraFieldData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [short]$HeaderId,

        [Parameter(Mandatory)]
        [byte[]]$Data
    )

    switch ($HeaderId) {
        0x0001 {
            # ZIP64 - already parsed elsewhere, just show size
            Write-ZipInfo "      ZIP64 extended information ($($Data.Length) bytes)" -ForegroundColor Cyan
        }
        0x5455 {
            # Extended Timestamp
            if ($Data.Length -ge 1) {
                $flags = $Data[0]
                $offset = 1

                Write-ZipInfo "      Extended Timestamp:" -ForegroundColor Cyan

                if (($flags -band 0x01) -and ($Data.Length -ge $offset + 4)) {
                    $modTime = [BinaryPrimitives]::ReadInt32LittleEndian([ArraySegment[byte]]::new($Data, $offset, 4))
                    $modDateTime = [DateTimeOffset]::FromUnixTimeSeconds($modTime).LocalDateTime
                    Write-ZipInfo "        Modification: $($modDateTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
                    $offset += 4
                }

                if (($flags -band 0x02) -and ($Data.Length -ge $offset + 4)) {
                    $accTime = [BinaryPrimitives]::ReadInt32LittleEndian([ArraySegment[byte]]::new($Data, $offset, 4))
                    $accDateTime = [DateTimeOffset]::FromUnixTimeSeconds($accTime).LocalDateTime
                    Write-ZipInfo "        Access: $($accDateTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
                    $offset += 4
                }

                if (($flags -band 0x04) -and ($Data.Length -ge $offset + 4)) {
                    $createTime = [BinaryPrimitives]::ReadInt32LittleEndian([ArraySegment[byte]]::new($Data, $offset, 4))
                    $createDateTime = [DateTimeOffset]::FromUnixTimeSeconds($createTime).LocalDateTime
                    Write-ZipInfo "        Creation: $($createDateTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
                }
            }
        }
        0x7875 {
            # Info-ZIP UNIX 3rd generation (UID/GID)
            if ($Data.Length -ge 1) {
                $version = $Data[0]
                Write-ZipInfo "      Info-ZIP UNIX (v$version):" -ForegroundColor Cyan

                $offset = 1
                if ($Data.Length -ge $offset + 1) {
                    $uidSize = $Data[$offset]
                    $offset++

                    if ($Data.Length -ge $offset + $uidSize) {
                        $uid = switch ($uidSize) {
                            1 { $Data[$offset] }
                            2 { [BinaryPrimitives]::ReadUInt16LittleEndian([ArraySegment[byte]]::new($Data, $offset, 2)) }
                            4 { [BinaryPrimitives]::ReadUInt32LittleEndian([ArraySegment[byte]]::new($Data, $offset, 4)) }
                            default { 0 }
                        }
                        Write-ZipInfo "        UID: $uid" -ForegroundColor Cyan
                        $offset += $uidSize
                    }
                }

                if ($Data.Length -ge $offset + 1) {
                    $gidSize = $Data[$offset]
                    $offset++

                    if ($Data.Length -ge $offset + $gidSize) {
                        $gid = switch ($gidSize) {
                            1 { $Data[$offset] }
                            2 { [BinaryPrimitives]::ReadUInt16LittleEndian([ArraySegment[byte]]::new($Data, $offset, 2)) }
                            4 { [BinaryPrimitives]::ReadUInt32LittleEndian([ArraySegment[byte]]::new($Data, $offset, 4)) }
                            default { 0 }
                        }
                        Write-ZipInfo "        GID: $gid" -ForegroundColor Cyan
                    }
                }
            }
        }
        0x000a {
            # NTFS
            Write-ZipInfo "      NTFS extra field:" -ForegroundColor Cyan
            if ($Data.Length -ge 4) {
                $offset = 4  # Skip reserved

                while ($offset + 4 -le $Data.Length) {
                    $tag = [BinaryPrimitives]::ReadUInt16LittleEndian([ArraySegment[byte]]::new($Data, $offset, 2))
                    $size = [BinaryPrimitives]::ReadUInt16LittleEndian([ArraySegment[byte]]::new($Data, $offset + 2, 2))
                    $offset += 4

                    if ($tag -eq 0x0001 -and $size -ge 24) {
                        # Attribute tag 1: timestamps
                        $mtime = [BinaryPrimitives]::ReadInt64LittleEndian([ArraySegment[byte]]::new($Data, $offset, 8))
                        $atime = [BinaryPrimitives]::ReadInt64LittleEndian([ArraySegment[byte]]::new($Data, $offset + 8, 8))
                        $ctime = [BinaryPrimitives]::ReadInt64LittleEndian([ArraySegment[byte]]::new($Data, $offset + 16, 8))

                        $mtimeDate = [DateTime]::FromFileTimeUtc($mtime).ToLocalTime()
                        $atimeDate = [DateTime]::FromFileTimeUtc($atime).ToLocalTime()
                        $ctimeDate = [DateTime]::FromFileTimeUtc($ctime).ToLocalTime()

                        Write-ZipInfo "        Modified: $($mtimeDate.ToString('yyyy-MM-dd HH:mm:ss.fffffff'))" -ForegroundColor Cyan
                        Write-ZipInfo "        Accessed: $($atimeDate.ToString('yyyy-MM-dd HH:mm:ss.fffffff'))" -ForegroundColor Cyan
                        Write-ZipInfo "        Created: $($ctimeDate.ToString('yyyy-MM-dd HH:mm:ss.fffffff'))" -ForegroundColor Cyan
                    }

                    $offset += $size
                }
            }
        }
        0x9901 {
            # WinZip AES
            if ($Data.Length -ge 7) {
                $version = [BinaryPrimitives]::ReadUInt16LittleEndian([ArraySegment[byte]]::new($Data, 0, 2))
                $vendor = [System.Text.Encoding]::ASCII.GetString($Data, 2, 2)
                $strength = $Data[4]
                $method = [BinaryPrimitives]::ReadUInt16LittleEndian([ArraySegment[byte]]::new($Data, 5, 2))

                $strengthName = switch ($strength) {
                    1 { "128-bit" }
                    2 { "192-bit" }
                    3 { "256-bit" }
                    default { "Unknown ($strength)" }
                }

                Write-ZipInfo "      WinZip AES Encryption:" -ForegroundColor Cyan
                Write-ZipInfo "        Version: $version" -ForegroundColor Cyan
                Write-ZipInfo "        Vendor: $vendor" -ForegroundColor Cyan
                Write-ZipInfo "        Strength: $strengthName" -ForegroundColor Cyan
                Write-ZipInfo "        Compression Method: $method" -ForegroundColor Cyan
            }
        }
        0x7075 {
            # Info-ZIP Unicode Path
            if ($Data.Length -ge 6) {
                $version = $Data[0]
                $crc32 = [BinaryPrimitives]::ReadUInt32LittleEndian([ArraySegment[byte]]::new($Data, 1, 4))
                $unicodeName = [System.Text.Encoding]::UTF8.GetString($Data, 5, $Data.Length - 5)

                Write-ZipInfo "      Unicode Path (v$version):" -ForegroundColor Cyan
                Write-ZipInfo "        CRC32: 0x$($crc32.ToString('X8'))" -ForegroundColor Cyan
                Write-ZipInfo "        Path: $unicodeName" -ForegroundColor Cyan
            }
        }
        0x6375 {
            # Info-ZIP Unicode Comment
            if ($Data.Length -ge 6) {
                $version = $Data[0]
                $crc32 = [BinaryPrimitives]::ReadUInt32LittleEndian([ArraySegment[byte]]::new($Data, 1, 4))
                $unicodeComment = [System.Text.Encoding]::UTF8.GetString($Data, 5, $Data.Length - 5)

                Write-ZipInfo "      Unicode Comment (v$version):" -ForegroundColor Cyan
                Write-ZipInfo "        CRC32: 0x$($crc32.ToString('X8'))" -ForegroundColor Cyan
                Write-ZipInfo "        Comment: $unicodeComment" -ForegroundColor Cyan
            }
        }
        default {
            # Unknown - just show hex dump for first 32 bytes
            $hexDump = ($Data | Select-Object -First 32 | ForEach-Object { $_.ToString('X2') }) -join ' '
            if ($Data.Length -gt 32) {
                $hexDump += "... ($($Data.Length) bytes total)"
            }
            Write-ZipInfo "      Data: $hexDump" -ForegroundColor Cyan
        }
    }
}

function Get-ZipExtraField {
    [OutputType([ExtraField])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ArraySegment[byte]]
        $InputObject
    )

    process {
        $idx = 0
        while ($InputObject.Count) {
            if ($InputObject.Count -lt 4) {
                throw "Not enough data to read extra field header #$idx"
            }

            $headerId = [BinaryPrimitives]::ReadInt16LittleEndian($InputObject.Slice(0, 2))
            $dataSize = [BinaryPrimitives]::ReadInt16LittleEndian($InputObject.Slice(2, 2))

            if ($InputObject.Count -lt 4 + $dataSize) {
                throw "Not enough data to read extra field data #$idx with header ID 0x$($headerId.ToString('X4'))"
            }

            $data = $InputObject.Slice(4, $dataSize).ToArray()

            # Log extra field info
            $fieldName = Get-ZipExtraFieldName -HeaderId $headerId
            Write-ZipInfo "    Extra Field: 0x$($headerId.ToString('X4')) - $fieldName ($dataSize bytes)" -ForegroundColor Cyan
            Format-ZipExtraFieldData -HeaderId $headerId -Data $data

            [ExtraField]@{
                HeaderId = $headerId
                DataSize = $dataSize
                Data = $data
            }

            $InputObject = $InputObject.Slice(4 + $dataSize)
            $idx++
        }
    }
}

function Get-Zip64ExtraFieldValues {
    [CmdletBinding()]
    param (
        [Parameter()]
        [AllowEmptyCollection()]
        [ExtraField[]]
        $ExtraFields = @(),

        [Parameter(Mandatory)]
        [int]
        $UncompressedSize32,

        [Parameter(Mandatory)]
        [int]
        $CompressedSize32,

        [Parameter()]
        [int]
        $LocalHeaderOffset32 = 0
    )

    $zip64Extra = if ($ExtraFields -and $ExtraFields.Count -gt 0) {
        $ExtraFields | Where-Object { $_.HeaderId -eq 0x0001 }
    }

    if (-not $zip64Extra) {
        # No ZIP64 extra field, return original 32-bit values
        return @{
            ActualUncompressedSize = [long]$UncompressedSize32
            ActualCompressedSize = [long]$CompressedSize32
            ActualLocalHeaderOffset = [long]$LocalHeaderOffset32
        }
    }

    $data = $zip64Extra.Data
    $offset = 0

    # Fields appear in specific order, only if the 32-bit value is 0xFFFFFFFF
    $actualUncompressed = [long]$UncompressedSize32
    $actualCompressed = [long]$CompressedSize32
    $actualLocalHeaderOffset = [long]$LocalHeaderOffset32
    $dataView = [ArraySegment[byte]]::new($data)

    if ($UncompressedSize32 -eq -1) {
        if ($dataView.Count -lt 8) {
            throw "ZIP64 extra field too small for uncompressed size"
        }
        $actualUncompressed = [BinaryPrimitives]::ReadInt64LittleEndian($dataView.Slice(0, 8))
        Write-ZipInfo "    ZIP64 Extra: Uncompressed size = $actualUncompressed bytes (from 0xFFFFFFFF)" -ForegroundColor Cyan
        $dataView = $dataView.Slice(8)
    }

    if ($CompressedSize32 -eq -1) {
        if ($dataView.Count -lt 8) {
            throw "ZIP64 extra field too small for compressed size"
        }
        $actualCompressed = [BinaryPrimitives]::ReadInt64LittleEndian($dataView.Slice(0, 8))
        Write-ZipInfo "    ZIP64 Extra: Compressed size = $actualCompressed bytes (from 0xFFFFFFFF)" -ForegroundColor Cyan
        $dataView = $dataView.Slice(8)
    }

    if ($LocalHeaderOffset32 -eq -1) {
        if ($dataView.Count -lt 8) {
            throw "ZIP64 extra field too small for local header offset"
        }
        $actualLocalHeaderOffset = [BinaryPrimitives]::ReadInt64LittleEndian($dataView.Slice(0, 8))
        Write-ZipInfo "    ZIP64 Extra: Local header offset = 0x$($actualLocalHeaderOffset.ToString('X16')) (from 0xFFFFFFFF)" -ForegroundColor Cyan
    }

    return @{
        ActualUncompressedSize = $actualUncompressed
        ActualCompressedSize = $actualCompressed
        ActualLocalHeaderOffset = $actualLocalHeaderOffset
    }
}

function Get-ZipCentralDirectory {
    [OutputType([CentralDirectory])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [FileStream]
        $Stream,

        [Parameter(Mandatory)]
        [long]
        $Offset,

        [Parameter(Mandatory)]
        [long]
        $Size,

        [Parameter(Mandatory)]
        [long]
        $Count,

        [Parameter()]
        [Encoding]
        $Encoding
    )

    Write-ZipInfo "Reading Central Directory entries ($Count entries)..." -ForegroundColor BrightCyan

    if ($Stream.Length -lt ($Offset + $Size)) {
        throw "Not enough data to read Central Directory"
    }

    $sizeRemaining = $Size
    $bufferSize = 0
    $buffer = [Array]::Empty[byte]()
    $dataView = [ArraySegment[byte]]::Empty

    $ensureBuffer = {
        param([int]$RequiredSize)

        if ($dataView.Count -ge $RequiredSize) {
            return
        }

        $bufferSize = [Math]::Min($sizeRemaining, 64KB)
        $buffer = [byte[]]::new($bufferSize)
        $null = $Stream.Seek($Offset + $Size - $sizeRemaining, [SeekOrigin]::Begin)
        $null = $Stream.Read($buffer, 0, $buffer.Length)
        $dataView = [ArraySegment[byte]]::new($buffer)
    }

    for ($i = 0; $i -lt $Count; $i++) {
        . $ensureBuffer -RequiredSize ([CentralDirectory]::MinSize)

        $dirOffset = $Offset + $Size - $sizeRemaining
        $signature = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(0, 4))
        if ($signature -ne [CentralDirectory]::Signature) {
            throw "Central Directory signature not found at expected offset"
        }

        $versionMadeBy = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(4, 2))
        $versionNeeded = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(6, 2))
        $flags = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(8, 2))
        $compressionMethod = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(10, 2))
        $lastModTime = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(12, 2))
        $lastModDate = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(14, 2))
        $crc32 = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(16, 4))
        $compressedSize = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(20, 4))
        $uncompressedSize = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(24, 4))
        $fileNameLen = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(28, 2))
        $extraFieldLen = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(30, 2))
        $fileCommentLen = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(32, 2))
        $diskNumberStart = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(34, 2))
        $internalFileAttributes = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(36, 2))
        $externalFileAttributes = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(38, 4))
        $localHeaderOffset = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(42, 4))

        $dataView = $dataView.Slice(46)
        $sizeRemaining -= 46

        $cdEncoding = if ($Encoding) {
            $Encoding
        } elseif ($flags -band [FileFlags]::UTF8Encoding) {
            [Encoding]::UTF8
        } else {
            [Encoding]::GetEncoding(437)
        }

        $fileName = $null
        if ($fileNameLen) {
            . $ensureBuffer -RequiredSize $fileNameLen

            $fileName = $cdEncoding.GetString($dataView.Slice(0, $fileNameLen).ToArray())
            Write-ZipInfo "`n  Entry $($i + 1)/$Count : $fileName" -ForegroundColor BrightMagenta
            $dataView = $dataView.Slice($fileNameLen)
            $sizeRemaining -= $fileNameLen
        }

        # Log basic CD header info
        Write-ZipInfo "    CD Offset: 0x$($dirOffset.ToString('X8'))" -ForegroundColor BrightWhite
        Write-ZipInfo "    Version Made By: $versionMadeBy (v$($versionMadeBy / 10))" -ForegroundColor BrightWhite
        Write-ZipInfo "    Version Needed: $versionNeeded (v$($versionNeeded / 10))" -ForegroundColor BrightWhite

        $flagsStr = ([FileFlags]$flags).ToString()
        Write-ZipInfo "    Flags: 0x$($flags.ToString('X4')) ($flagsStr)" -ForegroundColor BrightWhite

        $compressionName = Get-CompressionMethodName -Method $compressionMethod
        Write-ZipInfo "    Compression: $compressionName" -ForegroundColor BrightWhite

        $timestamp = ConvertFrom-DosDateTime -DosTime $lastModTime -DosDate $lastModDate
        if ($timestamp) {
            Write-ZipInfo "    Last Modified: $($timestamp.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor BrightWhite
        }

        Write-ZipInfo "    CRC32: 0x$($crc32.ToString('X8'))" -ForegroundColor BrightWhite
        Write-ZipInfo "    Compressed Size (header): $compressedSize bytes" -ForegroundColor BrightWhite
        Write-ZipInfo "    Uncompressed Size (header): $uncompressedSize bytes" -ForegroundColor BrightWhite
        Write-ZipInfo "    Local Header Offset (header): 0x$($localHeaderOffset.ToString('X8'))" -ForegroundColor BrightWhite

        $extraFields = [Array]::Empty[ExtraField]()
        if ($extraFieldLen) {
            . $ensureBuffer -RequiredSize $extraFieldLen

            $extraFieldsView = $dataView.Slice(0, $extraFieldLen)
            $extraFields = @(Get-ZipExtraField -InputObject $extraFieldsView)

            $dataView = $dataView.Slice($extraFieldLen)
            $sizeRemaining -= $extraFieldLen
        }

        $comment = $null
        if ($fileCommentLen) {
            . $ensureBuffer -RequiredSize $fileCommentLen
            $comment = $cdEncoding.GetString($dataView.Slice(0, $fileCommentLen).ToArray())
            Write-ZipInfo "    Comment: $comment" -ForegroundColor BrightWhite
            $dataView = $dataView.Slice($fileCommentLen)
            $sizeRemaining -= $fileCommentLen
        }

        # Parse ZIP64 extra field if present to get actual 64-bit values
        $zip64Params = @{
            ExtraFields           = $extraFields
            UncompressedSize32    = $uncompressedSize
            CompressedSize32      = $compressedSize
            LocalHeaderOffset32   = $localHeaderOffset
        }
        $zip64Values = Get-Zip64ExtraFieldValues @zip64Params

        # Log final values after ZIP64 parsing
        if ($zip64Values.ActualCompressedSize -ne $compressedSize -or
            $zip64Values.ActualUncompressedSize -ne $uncompressedSize -or
            $zip64Values.ActualLocalHeaderOffset -ne $localHeaderOffset) {
            Write-ZipInfo "    ──────────────────────────────────────" -ForegroundColor BrightBlack
            Write-ZipInfo "    Actual Compressed Size: $($zip64Values.ActualCompressedSize) bytes" -ForegroundColor BrightGreen
            Write-ZipInfo "    Actual Uncompressed Size: $($zip64Values.ActualUncompressedSize) bytes" -ForegroundColor BrightGreen
            Write-ZipInfo "    Actual Local Header Offset: 0x$($zip64Values.ActualLocalHeaderOffset.ToString('X16'))" -ForegroundColor BrightGreen
        }

        [CentralDirectory]@{
            Offset = $dirOffset
            VersionMadeBy = $versionMadeBy
            VersionNeeded = $versionNeeded
            Flags = [FileFlags]$flags
            CompressionMethod = $compressionMethod
            LastModTime = $lastModTime
            LastModDate = $lastModDate
            CRC32 = $crc32
            CompressedSize = $zip64Values.ActualCompressedSize
            UncompressedSize = $zip64Values.ActualUncompressedSize
            FileNameLength = $fileNameLen
            ExtraFieldLength = $extraFieldLen
            FileCommentLength = $fileCommentLen
            DiskNumberStart = $diskNumberStart
            InternalFileAttributes = $internalFileAttributes
            ExternalFileAttributes = $externalFileAttributes
            LocalHeaderOffset = $zip64Values.ActualLocalHeaderOffset
            FileName = $fileName
            ExtraFields = $extraFields
            FileComment = $comment
        }
    }
}

function Get-ZipLocalFileHeader {
    [OutputType([LocalFileHeader])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [FileStream]
        $Stream,

        [Parameter(Mandatory, ValueFromPipeline)]
        [CentralDirectory[]]
        $InputObject,

        [Parameter()]
        [Encoding]
        $Encoding
    )

    begin {
        # The LCH can contain 2 variable fields of 64KB each. We set a buffer
        # to something that could contain all that data.
        $bufferSize = [Math]::Min($Stream.Length, 129KB)
        $buffer = [byte[]]::new($bufferSize)
    }

    process {
        foreach ($cd in $InputObject) {
            try {
                # The CD should already have ZIP64 values parsed from its extra field
                $offset = $cd.LocalHeaderOffset
                $cdCompressedSize = $cd.CompressedSize

                if ($Stream.Length -lt ($offset + [LocalFileHeader]::MinSize)) {
                    throw "Not enough data to read Local File Header for '$($cd.FileName)'"
                }

                $null = $Stream.Seek($offset, [SeekOrigin]::Begin)
                $null = $Stream.Read($buffer, 0, $buffer.Length)
                $dataView = [ArraySegment[byte]]::new($buffer)

                $signature = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(0, 4))
                if ($signature -ne [LocalFileHeader]::Signature) {
                    throw "Local File Header signature not found at expected offset for '$($cd.FileName)'"
                }

                $versionNeeded = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(4, 2))
                $flags = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(6, 2))
                $compressionMethod = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(8, 2))
                $lastModTime = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(10, 2))
                $lastModDate = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(12, 2))
                $crc32 = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(14, 4))
                $compressedSize = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(18, 4))
                $uncompressedSize = [BinaryPrimitives]::ReadInt32LittleEndian($dataView.Slice(22, 4))
                $fileNameLen = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(26, 2))
                $extraFieldLen = [BinaryPrimitives]::ReadInt16LittleEndian($dataView.Slice(28, 2))

                $fileName = $null
                if ($fileNameLen) {
                    $nameEncoding = if ($Encoding) {
                        $Encoding
                    } elseif ($cd.Flags -band [FileFlags]::UTF8Encoding) {
                        # The CentralDirectory is the definitive source so we
                        # use those flags for our check
                        [Encoding]::UTF8
                    } else {
                        [Encoding]::GetEncoding(437)
                    }

                    $fileName = $nameEncoding.GetString($dataView.Slice(30, $fileNameLen).ToArray())
                    Write-ZipInfo "`n  Local Header: $fileName" -ForegroundColor BrightMagenta
                }

                # Log basic LH header info
                Write-ZipInfo "    LH Offset: 0x$($offset.ToString('X16'))" -ForegroundColor BrightWhite
                Write-ZipInfo "    Version Needed: $versionNeeded (v$($versionNeeded / 10))" -ForegroundColor BrightWhite

                $flagsStr = ([FileFlags]$flags).ToString()
                Write-ZipInfo "    Flags: 0x$($flags.ToString('X4')) ($flagsStr)" -ForegroundColor BrightWhite

                $compressionName = Get-CompressionMethodName -Method $compressionMethod
                Write-ZipInfo "    Compression: $compressionName" -ForegroundColor BrightWhite

                $timestamp = ConvertFrom-DosDateTime -DosTime $lastModTime -DosDate $lastModDate
                if ($timestamp) {
                    Write-ZipInfo "    Last Modified: $($timestamp.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor BrightWhite
                }

                Write-ZipInfo "    CRC32: 0x$($crc32.ToString('X8'))" -ForegroundColor BrightWhite
                Write-ZipInfo "    Compressed Size (header): $compressedSize bytes" -ForegroundColor BrightWhite
                Write-ZipInfo "    Uncompressed Size (header): $uncompressedSize bytes" -ForegroundColor BrightWhite

                $extraFields = [Array]::Empty[ExtraField]()
                if ($extraFieldLen) {
                    $extraFieldsView = $dataView.Slice(30 + $fileNameLen, $extraFieldLen)
                    $extraFields = @(Get-ZipExtraField -InputObject $extraFieldsView)
                }

                # Parse ZIP64 extra field if present to get actual 64-bit values
                # For local headers, we don't have LocalHeaderOffset, so we only check sizes
                $zip64Params = @{
                    ExtraFields        = $extraFields
                    UncompressedSize32 = $uncompressedSize
                    CompressedSize32   = $compressedSize
                }
                $zip64Values = Get-Zip64ExtraFieldValues @zip64Params

                $compressedDataOffset = $offset + 30 + $fileNameLen + $extraFieldLen
                Write-ZipInfo "    Compressed Data Offset: 0x$($compressedDataOffset.ToString('X16'))" -ForegroundColor BrightWhite

                # Log final values after ZIP64 parsing
                if ($zip64Values.ActualCompressedSize -ne $compressedSize -or
                    $zip64Values.ActualUncompressedSize -ne $uncompressedSize) {
                    Write-ZipInfo "    ──────────────────────────────────────" -ForegroundColor BrightBlack
                    Write-ZipInfo "    Actual Compressed Size: $($zip64Values.ActualCompressedSize) bytes" -ForegroundColor BrightGreen
                    Write-ZipInfo "    Actual Uncompressed Size: $($zip64Values.ActualUncompressedSize) bytes" -ForegroundColor BrightGreen
                }

                $dataDescriptor = $null
                if ($flags -band [FileFlags]::DataDescriptor) {
                    $descriptorOffset = $compressedDataOffset + $cdCompressedSize

                    # While the descriptor could only be 12 bytes long it could
                    # also be 24 bytes long if the sizes are stored as Zip64.
                    # The EOCD being after would mean that the offset needs to
                    # be + 24 anyway so this is validating the offset is
                    # ok to read from.
                    if ($Stream.Length -lt ($descriptorOffset + 24)) {
                        throw "Not enough data to read Data Descriptor for '$($cd.FileName)'"
                    }

                    $null = $Stream.Seek($descriptorOffset, [SeekOrigin]::Begin)
                    $null = $Stream.Read($buffer, 0, $buffer.Length)
                    $descriptorView = [ArraySegment[byte]]::new($buffer)

                    Write-ZipInfo "    ──────────────────────────────────────" -ForegroundColor BrightBlack
                    Write-ZipInfo "    Data Descriptor found at 0x$($descriptorOffset.ToString('X16'))" -ForegroundColor BrightYellow

                    # The signature is optional so we skip if set by adjusting
                    # our view
                    $descriptorSignature = [BinaryPrimitives]::ReadInt32LittleEndian($descriptorView.Slice(0, 4))
                    if ($descriptorSignature -eq [DataDescriptor]::Signature) {
                        Write-ZipInfo "    DD has signature: 0x$($descriptorSignature.ToString('X8'))" -ForegroundColor BrightYellow
                        $descriptorView = $descriptorView.Slice(4)
                    }

                    $descriptorCRC32 = [BinaryPrimitives]::ReadInt32LittleEndian($descriptorView.Slice(0, 4))

                    if ($cd.CompressedSize -eq -1 -or $cd.UncompressedSize -eq -1) {
                        $descriptorCompressedSize = [BinaryPrimitives]::ReadInt64LittleEndian($descriptorView.Slice(4, 8))
                        $descriptorUncompressedSize = [BinaryPrimitives]::ReadInt64LittleEndian($descriptorView.Slice(12, 8))
                        Write-ZipInfo "    DD Format: ZIP64 (64-bit sizes)" -ForegroundColor BrightYellow
                    }
                    else {
                        $descriptorCompressedSize = [BinaryPrimitives]::ReadInt32LittleEndian($descriptorView.Slice(4, 4))
                        $descriptorUncompressedSize = [BinaryPrimitives]::ReadInt32LittleEndian($descriptorView.Slice(8, 4))
                        Write-ZipInfo "    DD Format: Standard (32-bit sizes)" -ForegroundColor BrightYellow
                    }

                    Write-ZipInfo "    DD CRC32: 0x$($descriptorCRC32.ToString('X8'))" -ForegroundColor BrightYellow
                    Write-ZipInfo "    DD Compressed Size: $descriptorCompressedSize bytes" -ForegroundColor BrightYellow
                    Write-ZipInfo "    DD Uncompressed Size: $descriptorUncompressedSize bytes" -ForegroundColor BrightYellow

                    $dataDescriptor = [DataDescriptor]@{
                        Offset = $descriptorOffset
                        CRC32 = $descriptorCRC32
                        CompressedSize = $descriptorCompressedSize
                        UncompressedSize = $descriptorUncompressedSize
                    }
                }

                [LocalFileHeader]@{
                    Offset = $offset
                    VersionNeeded = $versionNeeded
                    Flags = [FileFlags]$flags
                    CompressionMethod = $compressionMethod
                    LastModTime = $lastModTime
                    LastModDate = $lastModDate
                    CRC32 = $crc32
                    CompressedSize = $zip64Values.ActualCompressedSize
                    UncompressedSize = $zip64Values.ActualUncompressedSize
                    FileNameLength = $fileNameLen
                    ExtraFieldLength = $extraFieldLen
                    FileName = $fileName
                    ExtraFields = $extraFields
                    CompressedDataOffset = $compressedDataOffset
                    DataDescriptor = $dataDescriptor
                }
            }
            catch {
                $PSCmdlet.WriteError($_)
            }
        }
    }
}

function Get-ZipStructure {
    <#
    .SYNOPSIS
    Gets the information Zip structure information.

    .PARAMETER Path
    The path(s) to the ZIP file(s) to analyze.

    .PARAMETER FileNameEncoding
    The encoding to use for file names within the ZIP archive.
    #>
    [OutputType([ZipStructure])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]
        $Path,

        [Parameter()]
        [Encoding]
        $FileNameEncoding
    )

    process {
        foreach ($filePath in $Path) {
            $fs = $null
            try {
                $filePath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($filePath)

                Write-ZipInfo "`nAnalyzing ZIP file: $filePath" -ForegroundColor BrightWhite
                Write-ZipInfo ("=" * 80) -ForegroundColor BrightBlack

                $fs = [File]::OpenRead($filePath)
                Write-ZipInfo "File size: $($fs.Length) bytes ($([math]::Round($fs.Length / 1MB, 2)) MB)" -ForegroundColor BrightWhite

                $eocd = Get-ZipEndOfCentralDirectory -Stream $fs

                $cdOffset = $eocd.CentralDirectoryOffset
                $cdSize = $eocd.CentralDirectorySize
                $cdCount = $eocd.CentralDirectoryCount
                if (
                    $cdOffset -eq -1 -or
                    $cdSize -eq -1 -or
                    $cdCount -eq -1
                ) {
                    Write-ZipInfo "`nZIP64 format detected" -ForegroundColor BrightYellow
                    # If any of the fields are set to -1 we most likely have a Zip64
                    # and need to look for the Zip64 End of Central Directory Locator
                    # which is located just before the EOCD structure.
                    $eocd64Locator = Get-Zip64EndOfCentralDirectoryLocator -Stream $fs -EOCDOffset $eocd.Offset
                    $eocd64 = Get-Zip64EndOfCentralDirectory -Stream $fs -EOCD64Offset $eocd64Locator.EOCD64Offset

                    if ($cdOffset -eq -1) {
                        $cdOffset = $eocd64.CentralDirectoryOffset
                    }
                    if ($cdSize -eq -1) {
                        $cdSize = $eocd64.CentralDirectorySize
                    }
                    if ($cdCount -eq -1) {
                        $cdCount = $eocd64.CentralDirectoryCount
                    }
                }
                else {
                    $eocd64Locator = $null
                    $eocd64 = $null
                }

                $cds = @()
                $cdParams = @{
                    Stream = $fs
                    Offset = $cdOffset
                    Size = $cdSize
                    Count = $cdCount
                }
                $fileHeaders = Get-ZipCentralDirectory @cdParams -OutVariable cds |
                    Get-ZipLocalFileHeader -Stream $fs

                Write-ZipInfo "`nZIP analysis complete" -ForegroundColor BrightGreen
                Write-ZipInfo ("=" * 80) -ForegroundColor BrightBlack

                [ZipStructure]@{
                    EOCD = $eocd
                    EOCD64Locator = $eocd64Locator
                    EOCD64 = $eocd64
                    CentralDirectoryEntries = $cds
                    LocalFileHeaders = $fileHeaders
                }
            }
            catch {
                $PSCmdlet.WriteError($_)
            }
            finally {
                ${fs}?.Dispose()
            }
        }
    }
}

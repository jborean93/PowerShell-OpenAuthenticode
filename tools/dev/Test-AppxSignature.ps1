# Copyright: (c) 2026, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

#Requires -Version 7.4

using namespace System.IO
using namespace System.IO.Compression
using namespace System.Formats.Asn1
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.Pkcs
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Text

$ErrorActionPreference = 'Stop'

# Dot source Get-ZipStructure for parsing functions
. "$PSScriptRoot/Get-ZipStructure.ps1"

class SpcIndirectDataContent {
    [Oid]$DataType
    [byte[]]$Data
    [Oid]$DigestAlgorithm
    [byte[]]$DigestParameters
    [byte[]]$Digest
}

class SpcSipInfo {
    [int]$Version
    [Guid]$Identifier
    [int]$Reserved1
    [int]$Reserved2
    [int]$Reserved3
    [int]$Reserved4
    [int]$Reserved5
}

class AppxDigestInfo {
    [byte[]]$AXPC
    [byte[]]$AXCD
    [byte[]]$AXCT
    [byte[]]$AXBM
    [byte[]]$AXCI
    [System.Security.Cryptography.HashAlgorithmName]$Algorithm
}

function Get-OidName {
    param([string]$Oid)

    $oidMap = @{
        '1.3.6.1.4.1.311.2.1.4'    = 'SPC_INDIRECT_DATA_OBJID'
        '1.3.6.1.4.1.311.2.1.30'   = 'SPC_SIPINFO_OBJID'
        '2.16.840.1.101.3.4.2.1'   = 'SHA-256'
        '2.16.840.1.101.3.4.2.2'   = 'SHA-384'
        '2.16.840.1.101.3.4.2.3'   = 'SHA-512'
    }

    if ($oidMap.ContainsKey($Oid)) {
        return $oidMap[$Oid]
    }

    return $Oid
}

function Get-AppxSignature {
    [OutputType([System.Security.Cryptography.Pkcs.SignedCms])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Stream]
        $AppxSignatureStream,

        [Parameter(Mandatory)]
        [Int64]
        $StreamLength
    )

    Write-Host "[Get-AppxSignature] Reading AppxSignature.p7x ($StreamLength bytes)" -ForegroundColor Cyan

    $buffer = [byte[]]::new(4096)
    $read = $AppxSignatureStream.Read($buffer, 0, 4)
    if ($read -ne 4) {
        throw "Failed to read first 4 bytes of AppxSignature.p7x"
    }

    $magic = [Convert]::ToHexString($buffer, 0, 4)
    Write-Host "  P7X Magic: 0x$magic (PKCX)" -ForegroundColor DarkGray

    if ($buffer[0] -ne 0x50 -or $buffer[1] -ne 0x4B -or $buffer[2] -ne 0x43 -or $buffer[3] -ne 0x58) {
        throw "AppxSignature.p7x does not appear to be a valid PKCS#7 signature"
    }

    $toRead = $StreamLength - 4
    if ($toRead -gt $buffer.Length) {
        $buffer = [byte[]]::new($toRead)
    }

    $bufferRead = 0
    while ($read = $AppxSignatureStream.Read($buffer, $bufferRead, ($toRead - $bufferRead))) {
        $bufferRead += $read
    }

    if ($bufferRead -ne $toRead) {
        throw "Failed to read entire AppxSignature.p7x, expected $toRead bytes but read $bufferRead bytes"
    }

    Write-Host "  PKCS#7 Data: $toRead bytes" -ForegroundColor DarkGray

    $signedCms = [SignedCms]::new()
    $signedCms.Decode([ArraySegment[byte]]::new($buffer, 0, $toRead))

    Write-Host "  SignedCms decoded successfully" -ForegroundColor DarkGray

    $signedCms
}

function Get-SpcIndirectDataContent {
    [OutputType([SpcIndirectDataContent])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Security.Cryptography.Pkcs.ContentInfo]
        $ContentInfo
    )

    <#
    SpcIndirectDataContent ::= SEQUENCE {
        data                    SpcAttributeTypeAndOptionalValue,
        messageDigest           DigestInfo
    } --#public—

    SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
        type                    ObjectID,
        value                   [0] EXPLICIT ANY OPTIONAL
    }

    DigestInfo ::= SEQUENCE {
        digestAlgorithm     AlgorithmIdentifier,
        digest              OCTETSTRING
    }

    AlgorithmIdentifier    ::=    SEQUENCE {
        algorithm           ObjectID,
        parameters          [0] EXPLICIT ANY OPTIONAL
    }
    #>

    $der = [AsnEncodingRules]::DER
    $data = [ArraySegment[byte]]::new($ContentInfo.Content)
    $offset = $length = $consumed = 0

    # SpcIndirectDataContent
    [AsnDecoder]::ReadSequence($data, $der, [ref]$offset, [ref]$length, [ref]$consumed)
    $data = $data.Slice($offset, $length)

    # SpcIndirectDataContent.data
    [AsnDecoder]::ReadSequence($data, $der, [ref]$offset, [ref]$length, [ref]$consumed)
    $attrAndValue = $data.Slice($offset, $length)

    # SpcIndirectDataContent.messageDigest
    $messageDigest = $data.Slice($consumed)
    [AsnDecoder]::ReadSequence($messageDigest, $der, [ref]$offset, [ref]$length, [ref]$consumed)
    $messageDigest = $messageDigest.Slice($offset, $length)

    # SpcAttributeTypeAndOptionalValue.type
    $attrType = [AsnDecoder]::ReadObjectIdentifier($attrAndValue, $der, [ref]$consumed)
    $attrAndValue = $attrAndValue.Slice($consumed)

    # SpcAttributeTypeAndOptionalValue.value
    $attrValue = [Array]::Empty[byte]()
    if ($attrAndValue.Count -and -not (
        $attrAndValue.Count -eq 2 -and
        $attrAndValue[0] -eq 0x05 -and
        $attrAndValue[1] -eq 0x00
    )) {
        # While the ASN.1 spec says this should be a [0] tagged value in reality it seems to just
        # be the raw value without the tag. We also skip reading if it's 05 00 which is ASN.1 DER
        # for NULL.
        $attrValue = $attrAndValue.ToArray()
    }

    # DigestInfo.digestAlgorithm
    [AsnDecoder]::ReadSequence($messageDigest, $der, [ref]$offset, [ref]$length, [ref]$consumed)
    $algorithmIdentifier = $messageDigest.Slice($offset, $length)
    $messageDigest = $messageDigest.Slice($consumed)

    # DigestInfo.digest
    $digest = [AsnDecoder]::ReadOctetString($messageDigest, $der, [ref]$consumed)

    # AlgorithmIdentifier.algorithm
    $digestAlgorithmOid = [AsnDecoder]::ReadObjectIdentifier($algorithmIdentifier, $der, [ref]$consumed)
    $algorithmIdentifier = $algorithmIdentifier.Slice($consumed)

    # AlgorithmIdentifier.parameters
    $digestAlgorithmParams = [Array]::Empty[byte]()
    if ($algorithmIdentifier.Count -and -not (
        $algorithmIdentifier.Count -eq 2 -and
        $algorithmIdentifier[0] -eq 0x05 -and
        $algorithmIdentifier[1] -eq 0x00
    )) {
        $digestAlgorithmParams = $algorithmIdentifier.ToArray()
    }

    $result = [SpcIndirectDataContent]@{
        DataType = [Oid]::new($attrType)
        Data = $attrValue
        DigestAlgorithm = [Oid]::new($digestAlgorithmOid)
        DigestParameters = $digestAlgorithmParams
        Digest = $digest
    }

    Write-Host "[Get-SpcIndirectDataContent] Parsed SpcIndirectData structure" -ForegroundColor Cyan
    $dataTypeName = Get-OidName $result.DataType.Value
    $digestAlgName = Get-OidName $result.DigestAlgorithm.Value
    Write-Host "  DataType OID: $($result.DataType.Value) ($dataTypeName)" -ForegroundColor DarkGray
    Write-Host "  Data Length: $($result.Data.Length) bytes" -ForegroundColor DarkGray
    Write-Host "  DigestAlgorithm OID: $($result.DigestAlgorithm.Value) ($digestAlgName)" -ForegroundColor DarkGray
    Write-Host "  Digest Length: $($result.Digest.Length) bytes" -ForegroundColor DarkGray

    $result
}

filter Get-SpcSipInfo {
    [OutputType([SpcSipInfo])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [SpcIndirectDataContent]
        $InputObject
    )

    <#
    SpcSipInfo ::= SEQUENCE {
        dwSIPversion INTEGER,
        gSIPGuid     OCTET STRING,
        dwReserved1  INTEGER,
        dwReserved2  INTEGER,
        dwReserved3  INTEGER,
        dwReserved4  INTEGER,
        dwReserved5  INTEGER
    }
    #>

    if ($InputObject.DataType.Value -ne "1.3.6.1.4.1.311.2.1.30") {
        throw "SpcIndirectDataContent data is not of type SPC_SIPINFO_OBJID, got $($InputObject.DataType.Value)"
    }

    $der = [AsnEncodingRules]::DER
    $data = [ArraySegment[byte]]::new($InputObject.Data)
    $offset = $length = $consumed = 0

    [AsnDecoder]::ReadSequence($data, $der, [ref]$offset, [ref]$length, [ref]$consumed)
    $data = $data.Slice($offset, $length)

    $version = [int][AsnDecoder]::ReadInteger($data, $der, [ref]$consumed)
    $data = $data.Slice($consumed)

    $sipGuid = [AsnDecoder]::ReadOctetString($data, $der, [ref]$consumed)
    $data = $data.Slice($consumed)

    $reserved = for ($i = 0; $i -lt 5; $i++) {
        [int][AsnDecoder]::ReadInteger($data, $der, [ref]$consumed)
        $data = $data.Slice($consumed)
    }

    $result = [SpcSipInfo]@{
        Version = $version
        Identifier = [Guid]::new($sipGuid)
        Reserved1 = $reserved[0]
        Reserved2 = $reserved[1]
        Reserved3 = $reserved[2]
        Reserved4 = $reserved[3]
        Reserved5 = $reserved[4]
    }

    Write-Host "[Get-SpcSipInfo] Parsed SpcSipInfo structure" -ForegroundColor Cyan
    Write-Host "  Version: 0x$($result.Version.ToString('X8'))" -ForegroundColor DarkGray
    Write-Host "  Identifier: $($result.Identifier)" -ForegroundColor DarkGray

    $appxGuid = [Guid]"0ac5df4b-ce07-4de2-b76e-23c839a09fd1"
    $bundleGuid = [Guid]"0f5f58b3-aade-4b9a-a434-95742d92eceb"

    if ($result.Identifier -eq $appxGuid) {
        Write-Host "  Type: APPX/MSIX Package" -ForegroundColor DarkGray
    }
    elseif ($result.Identifier -eq $bundleGuid) {
        Write-Host "  Type: APPX/MSIX Bundle" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  Type: Unknown" -ForegroundColor Yellow
    }

    $result
}

filter Get-AppxDigestInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [SpcIndirectDataContent]
        $InputObject
    )

    Write-Host "[Get-AppxDigestInfo] Parsing APPX digest blob" -ForegroundColor Cyan

    # Determine hash algorithm and length
    $algorithm = $null
    $hashLength = 0

    switch ($InputObject.DigestAlgorithm.Value) {
        "2.16.840.1.101.3.4.2.1" {
            # SHA-256
            $algorithm = [HashAlgorithmName]::SHA256
            $hashLength = 32
            Write-Host "  Algorithm: SHA-256 (32 bytes per hash)" -ForegroundColor DarkGray
        }
        "2.16.840.1.101.3.4.2.2" {
            # SHA-384
            $algorithm = [HashAlgorithmName]::SHA384
            $hashLength = 48
            Write-Host "  Algorithm: SHA-384 (48 bytes per hash)" -ForegroundColor DarkGray
        }
        "2.16.840.1.101.3.4.2.3" {
            # SHA-512
            $algorithm = [HashAlgorithmName]::SHA512
            $hashLength = 64
            Write-Host "  Algorithm: SHA-512 (64 bytes per hash)" -ForegroundColor DarkGray
        }
        default {
            $name = $InputObject.DigestAlgorithm.FriendlyName
            if (-not $name) {
                $name = $InputObject.DigestAlgorithm.Value
            }
            throw "SpcIndirectDataContent digest algorithm is not supported, got $name (expected SHA-256, SHA-384, or SHA-512)"
        }
    }

    $data = [ArraySegment[byte]]::new($InputObject.Digest)
    Write-Host "  Total digest blob length: $($data.Count) bytes" -ForegroundColor DarkGray

    if ($data.Count -lt (4 + (4 + ($hashLength * 4)))) {
        throw "SpcIndirectDataContent data is too short to contain AppxDigestInfo, expected at least $((4 + (4 + ($hashLength * 4)))) bytes but got $($data.Count) bytes"
    }

    $header = [Encoding]::ASCII.GetString($data.Slice(0, 4))
    Write-Host "  Header: $header" -ForegroundColor DarkGray

    if ($data[0] -ne 0x41 -or $data[1] -ne 0x50 -or $data[2] -ne 0x50 -or $data[3] -ne 0x58) {
        throw "SpcIndirectDataContent data does not appear to be AppxDigestInfo, expected first 4 bytes to be 'APPX'"
    }
    $data = $data.Slice(4)

    $fields = @{}
    $offset = 4  # Start after "APPX" header
    'AXPC', 'AXCD', 'AXCT', 'AXBM', 'AXCI' | ForEach-Object {
        $field = $_

        if ($data.Count -eq 0) {
            if ($field -eq 'AXCI') {
                # AXCI is optional so we can end here if we run out of data
                Write-Host "  $field`: (not present, optional)" -ForegroundColor DarkGray
                return
            }
            else {
                throw "SpcIndirectDataContent data is too short to contain AppxDigestInfo, expected field $field but no more data is available"
            }
        }

        if ($data.Count -lt 4) {
            throw "SpcIndirectDataContent data is too short to contain AppxDigestInfo, expected field $field to have a 4 byte length prefix but only $($data.Count) bytes are available"
        }

        $actualField = [Encoding]::ASCII.GetString($data.Slice(0, 4))
        if ($actualField -ne $field) {
            throw "SpcIndirectDataContent data does not appear to be AppxDigestInfo, expected field $field but got $actualField"
        }

        $data = $data.Slice(4)
        if ($data.Count -lt $hashLength) {
            throw "SpcIndirectDataContent data is too short to contain AppxDigestInfo, expected field $field to have a $hashLength byte value but only $($data.Count) bytes are available"
        }
        $hashValue = $data.Slice(0, $hashLength).ToArray()
        $fields[$field] = $hashValue

        $hashHex = [Convert]::ToHexString($hashValue)
        Write-Host "  $field`: $hashHex (offset $offset)" -ForegroundColor DarkGray

        $offset += 4 + $hashLength
        $data = $data.Slice($hashLength)
     }

     $fields['Algorithm'] = $algorithm
     [AppxDigestInfo]$fields
}

filter Test-AppxAXPC {
    <#
    .SYNOPSIS
    Verifies the AXPC (AppX Package Content) hash.

    .DESCRIPTION
    AXPC is a hash of all local file headers and their compressed data, excluding:
    - The AppxSignature.p7x file record (local header + compressed data + data descriptor)
    - The central directory
    - ZIP64 EOCD structures
    - Standard EOCD structure

    The hash represents the state of the package before signing, as if AppxSignature.p7x
    never existed. This is computed by hashing all file records from offset 0 up to the
    start of the central directory, skipping over the AppxSignature.p7x record.

    Data hashed (in order):
    1. All bytes from file start (offset 0) up to AppxSignature.p7x local file header
    2. All bytes after AppxSignature.p7x record up to start of central directory

    Signature record size calculation (from Central Directory):
    - Local file header: 30 bytes + filename length + extra field length
    - Compressed data: compressed size from CD entry
    - Data descriptor (if present): 16 bytes (standard) or 24 bytes (ZIP64)
      - Standard: sig(4) + crc32(4) + compressed(4) + uncompressed(4) = 16 bytes
      - ZIP64: sig(4) + crc32(4) + compressed(8) + uncompressed(8) = 24 bytes
      - Determined by DataDescriptor flag and whether sizes are 0xFFFFFFFF (-1)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [AppxDigestInfo]
        $InputObject,

        [Parameter(Mandatory)]
        [Stream]
        $FileStream,

        [Parameter(Mandatory)]
        [ZipStructure]
        $ZipStructure
    )

    Write-Host "Verifying AXPC hash..." -ForegroundColor Cyan

    $originalPosition = $FileStream.Position
    $buffer = [byte[]]::new(65536)

    $cdOffset = if ($ZipStructure.EOCD64) {
        $ZipStructure.EOCD64.CentralDirectoryOffset
    } else {
        $ZipStructure.EOCD.CentralDirectoryOffset
    }

    $sigCdEntry = $ZipStructure.CentralDirectoryEntries | Where-Object { $_.FileName -eq "AppxSignature.p7x" }

    $sigOffset = -1
    $sigRecordSize = 0

    if ($sigCdEntry) {
        $sigOffset = $sigCdEntry.LocalHeaderOffset
        $localHeaderSize = 30 + $sigCdEntry.FileNameLength + $sigCdEntry.ExtraFieldLength
        $compressedSize = $sigCdEntry.CompressedSize

        $dataDescriptorSize = 0
        if ($sigCdEntry.Flags -band [FileFlags]::DataDescriptor) {
            $isZip64Descriptor = $sigCdEntry.CompressedSize -eq -1 -or $sigCdEntry.UncompressedSize -eq -1
            $dataDescriptorSize = if ($isZip64Descriptor) { 24 } else { 16 }
        }

        $sigRecordSize = $localHeaderSize + $compressedSize + $dataDescriptorSize
    }

    $hasher = [IncrementalHash]::CreateHash($InputObject.Algorithm)
    $FileStream.Position = 0

    if ($sigOffset -lt 0) {
        $remaining = $cdOffset
        while ($remaining -gt 0) {
            $toRead = [Math]::Min($buffer.Length, $remaining)
            $read = $FileStream.Read($buffer, 0, $toRead)
            if ($read -eq 0) { break }
            $hasher.AppendData($buffer, 0, $read)
            $remaining -= $read
        }
    }
    else {
        $remaining = $sigOffset
        while ($remaining -gt 0) {
            $toRead = [Math]::Min($buffer.Length, $remaining)
            $read = $FileStream.Read($buffer, 0, $toRead)
            if ($read -eq 0) { break }
            $hasher.AppendData($buffer, 0, $read)
            $remaining -= $read
        }

        $FileStream.Position = $sigOffset + $sigRecordSize

        $remaining = $cdOffset - ($sigOffset + $sigRecordSize)
        while ($remaining -gt 0) {
            $toRead = [Math]::Min($buffer.Length, $remaining)
            $read = $FileStream.Read($buffer, 0, $toRead)
            if ($read -eq 0) { break }
            $hasher.AppendData($buffer, 0, $read)
            $remaining -= $read
        }
    }

    $computedHash = $hasher.GetHashAndReset()
    $expectedHash = $InputObject.AXPC

    $match = $computedHash.Length -eq $expectedHash.Length
    if ($match) {
        for ($i = 0; $i -lt $computedHash.Length; $i++) {
            if ($computedHash[$i] -ne $expectedHash[$i]) {
                $match = $false
                break
            }
        }
    }

    if ($match) {
        Write-Host "✓ AXPC hash matches" -ForegroundColor Green
    }
    else {
        Write-Host "✗ AXPC hash mismatch" -ForegroundColor Red
        Write-Host "  Expected: $([Convert]::ToHexString($expectedHash))" -ForegroundColor Yellow
        Write-Host "  Computed: $([Convert]::ToHexString($computedHash))" -ForegroundColor Yellow
    }

    $FileStream.Position = $originalPosition
}

filter Test-AppxAXCD {
    <#
    .SYNOPSIS
    Verifies the AXCD (AppX Central Directory) hash.

    .DESCRIPTION
    AXCD is a hash of the central directory and end-of-central-directory structures,
    adjusted to represent the pre-signature state of the package.

    The hash includes (in order):
    1. Central directory entries (excluding AppxSignature.p7x entry)
    2. ZIP64 EOCD (if present) with adjusted values
    3. ZIP64 EOCD Locator (if present) with adjusted offset
    4. Standard EOCD (first 22 bytes only, no comment) with disk numbers zeroed

    Adjustments made to simulate pre-signature state:
    - Entry count: Decremented by 1 (excludes AppxSignature.p7x)
    - CD size: Reduced by signature entry size
    - CD offset: Set to where AppxSignature.p7x local file header is located
      (this is where CD would have started before the signature was added)
    - ZIP64 EOCD offset: Recalculated as CD offset + adjusted CD size
    - Disk numbers: Set to 0 in standard EOCD (offsets 4-5 and 6-7)

    Why these adjustments?
    Before signing, AppxSignature.p7x doesn't exist, so:
    - Central directory would start where the signature file record is now
    - Central directory would have one fewer entry
    - Central directory would be smaller (no signature entry)
    - ZIP64 EOCD (if present) would be at a different offset

    Central Directory entry structure (46 bytes + variable):
    - Fixed header: 46 bytes
    - File name: FileNameLength bytes
    - Extra field: ExtraFieldLength bytes
    - Comment: FileCommentLength bytes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [AppxDigestInfo]
        $InputObject,

        [Parameter(Mandatory)]
        [Stream]
        $FileStream,

        [Parameter(Mandatory)]
        [ZipStructure]
        $ZipStructure
    )

    Write-Host "Verifying AXCD hash..." -ForegroundColor Cyan

    $originalPosition = $FileStream.Position

    $isZip64 = $null -ne $ZipStructure.EOCD64

    if ($isZip64) {
        $totalEntries = $ZipStructure.EOCD64.CentralDirectoryCount
        $cdSize = $ZipStructure.EOCD64.CentralDirectorySize
        $cdOffset = $ZipStructure.EOCD64.CentralDirectoryOffset
    } else {
        $totalEntries = $ZipStructure.EOCD.CentralDirectoryCount
        $cdSize = $ZipStructure.EOCD.CentralDirectorySize
        $cdOffset = $ZipStructure.EOCD.CentralDirectoryOffset
    }

    $eocdPos = $ZipStructure.EOCD.Offset
    $eocdSize = 22 + $ZipStructure.EOCD.CommentLength
    $FileStream.Position = $eocdPos
    $eocdData = [byte[]]::new($eocdSize)
    $FileStream.Read($eocdData, 0, $eocdSize) | Out-Null

    $z64EocdData = $null
    $z64LocatorData = $null

    if ($isZip64) {
        $z64EocdOffset = $ZipStructure.EOCD64.Offset
        $z64EocdSize = 56 + $ZipStructure.EOCD64.ExtensibleData.Length
        $FileStream.Position = $z64EocdOffset
        $z64EocdData = [byte[]]::new($z64EocdSize)
        $FileStream.Read($z64EocdData, 0, $z64EocdSize) | Out-Null

        $z64LocatorOffset = $ZipStructure.EOCD64Locator.Offset
        $FileStream.Position = $z64LocatorOffset
        $z64LocatorData = [byte[]]::new(20)
        $FileStream.Read($z64LocatorData, 0, 20) | Out-Null
    }

    $FileStream.Position = $cdOffset
    $cdData = [byte[]]::new($cdSize)
    $FileStream.Read($cdData, 0, $cdSize) | Out-Null

    $sigCdEntry = $ZipStructure.CentralDirectoryEntries | Where-Object { $_.FileName -eq "AppxSignature.p7x" }

    $sigCdStart = -1
    $sigEntrySize = 0
    $sigLocalHeaderOffset = [long]-1

    if ($sigCdEntry) {
        $sigCdStart = $sigCdEntry.Offset - $cdOffset
        $sigEntrySize = 46 + $sigCdEntry.FileNameLength + $sigCdEntry.ExtraFieldLength + $sigCdEntry.FileCommentLength
        $sigLocalHeaderOffset = $sigCdEntry.LocalHeaderOffset
    }

    $adjustedEntryCount = $totalEntries - 1
    $adjustedCdSize = $cdSize - $sigEntrySize
    $calculatedCdOffset = $sigLocalHeaderOffset

    $hasher = [IncrementalHash]::CreateHash($InputObject.Algorithm)

    if ($sigCdStart -gt 0) {
        $hasher.AppendData($cdData, 0, $sigCdStart)
    }

    $afterSigPos = $sigCdStart + $sigEntrySize
    if ($afterSigPos -lt $cdData.Length) {
        $hasher.AppendData($cdData, $afterSigPos, $cdData.Length - $afterSigPos)
    }

    if ($isZip64) {
        $adjustedZ64Eocd = [byte[]]::new(56)
        [Array]::Copy($z64EocdData, $adjustedZ64Eocd, 56)

        [Array]::Copy([BitConverter]::GetBytes([long]$adjustedEntryCount), 0, $adjustedZ64Eocd, 24, 8)
        [Array]::Copy([BitConverter]::GetBytes([long]$adjustedEntryCount), 0, $adjustedZ64Eocd, 32, 8)
        [Array]::Copy([BitConverter]::GetBytes([long]$adjustedCdSize), 0, $adjustedZ64Eocd, 40, 8)
        [Array]::Copy([BitConverter]::GetBytes([long]$calculatedCdOffset), 0, $adjustedZ64Eocd, 48, 8)

        $hasher.AppendData($adjustedZ64Eocd)

        $adjustedZ64Locator = [byte[]]::new(20)
        [Array]::Copy($z64LocatorData, $adjustedZ64Locator, 20)

        $z64EocdOffsetValue = $calculatedCdOffset + $adjustedCdSize
        [Array]::Copy([BitConverter]::GetBytes([long]$z64EocdOffsetValue), 0, $adjustedZ64Locator, 8, 8)

        $hasher.AppendData($adjustedZ64Locator)
    }

    $adjustedEocd = [byte[]]::new(22)
    [Array]::Copy($eocdData, 0, $adjustedEocd, 0, 22)

    [Array]::Copy([BitConverter]::GetBytes([ushort]0), 0, $adjustedEocd, 4, 2)
    [Array]::Copy([BitConverter]::GetBytes([ushort]0), 0, $adjustedEocd, 6, 2)

    $hasher.AppendData($adjustedEocd)

    $computedHash = $hasher.GetHashAndReset()
    $expectedHash = $InputObject.AXCD

    $match = $computedHash.Length -eq $expectedHash.Length
    if ($match) {
        for ($i = 0; $i -lt $computedHash.Length; $i++) {
            if ($computedHash[$i] -ne $expectedHash[$i]) {
                $match = $false
                break
            }
        }
    }

    if ($match) {
        Write-Host "✓ AXCD hash matches" -ForegroundColor Green
    }
    else {
        Write-Host "✗ AXCD hash mismatch" -ForegroundColor Red
        Write-Host "  Expected: $([Convert]::ToHexString($expectedHash))" -ForegroundColor Yellow
        Write-Host "  Computed: $([Convert]::ToHexString($computedHash))" -ForegroundColor Yellow
    }

    $FileStream.Position = $originalPosition
}

filter Test-AppxFileHash {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [AppxDigestInfo]
        $InputObject,

        [Parameter(Mandatory)]
        [ZipArchive]
        $ZipArchive,

        [Parameter(Mandatory)]
        [string]
        $DigestName,

        [Parameter(Mandatory)]
        [string]
        $EntryName,

        [Parameter()]
        [switch]
        $Optional
    )

    Write-Host "Verifying $DigestName hash..." -ForegroundColor Cyan

    $expectedHash = $InputObject.$DigestName
    if (-not $expectedHash) {
        if ($Optional) {
            Write-Host "  $DigestName field not present (optional)" -ForegroundColor Gray
            return
        }
        else {
            Write-Host "✗ $DigestName field missing" -ForegroundColor Red
            return
        }
    }

    $entry = $ZipArchive.GetEntry($EntryName)
    if (-not $entry) {
        $message = if ($Optional) { "$EntryName not found but $DigestName hash present" } else { "$EntryName not found" }
        Write-Host "✗ $message" -ForegroundColor Red
        return
    }

    $stream = $entry.Open()
    $ms = [MemoryStream]::new()
    $stream.CopyTo($ms)
    $stream.Dispose()

    $content = $ms.ToArray()
    $ms.Dispose()

    $hasher = [IncrementalHash]::CreateHash($InputObject.Algorithm)
    $hasher.AppendData($content)
    $computedHash = $hasher.GetHashAndReset()

    $match = $computedHash.Length -eq $expectedHash.Length
    if ($match) {
        for ($i = 0; $i -lt $computedHash.Length; $i++) {
            if ($computedHash[$i] -ne $expectedHash[$i]) {
                $match = $false
                break
            }
        }
    }

    if ($match) {
        Write-Host "✓ $DigestName hash matches" -ForegroundColor Green
    }
    else {
        Write-Host "✗ $DigestName hash mismatch" -ForegroundColor Red
        Write-Host "  Expected: $([Convert]::ToHexString($expectedHash))" -ForegroundColor Yellow
        Write-Host "  Computed: $([Convert]::ToHexString($computedHash))" -ForegroundColor Yellow
    }
}

function Test-AppxSignature {
    <#
    .SYNOPSIS
    Tests an Appx Signature.

    .PARAMETER Path
    The path to the appx/msix or appxbundle/msixbundle file to test.

    .NOTES
    This does not validate the certificate trust, just verifies that the digest
    in the Authenticode payload is correct for the package provided. It is
    designed as a POC for understanding how signatures work in Appx packages.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path
    )

    Write-Host "`n===== Testing APPX/MSIX Signature =====" -ForegroundColor Magenta
    Write-Host "File: $Path`n" -ForegroundColor Magenta

    $AppxSip = [Guid]"0ac5df4b-ce07-4de2-b76e-23c839a09fd1"
    $AppxBundleSip = [Guid]"0f5f58b3-aade-4b9a-a434-95742d92eceb"

    $zipFS = $zip = $signatureStream = $null
    try {
        Write-Host "[Test-AppxSignature] Opening ZIP archive" -ForegroundColor Cyan
        $zipFS = [File]::OpenRead($Path)

        # Parse ZIP structure
        Write-Host "[Test-AppxSignature] Parsing ZIP structure" -ForegroundColor Cyan
        $InformationPreference = 'SilentlyContinue'  # Suppress verbose logging from Get-ZipStructure
        $zipStructure = Get-ZipStructure -Path $Path
        $InformationPreference = 'Continue'

        $zip = [ZipArchive]::new($zipFS, [ZipArchiveMode]::Read)

        Write-Host "  Total entries: $($zip.Entries.Count)" -ForegroundColor DarkGray

        $signatureEntry = $zip.GetEntry("AppxSignature.p7x")
        if (-not $signatureEntry) {
            throw "AppxSignature.p7x not found in $Path"
        }

        Write-Host "  Found AppxSignature.p7x`n" -ForegroundColor DarkGray

        if ($signatureEntry.Length -lt 4) {
            throw "AppxSignature.p7x is too small to be valid"
        }

        $signatureStream = $signatureEntry.Open()
        $signedCms = Get-AppxSignature -AppxSignatureStream $signatureStream -StreamLength $signatureEntry.Length
        $signatureStream.Dispose()
        $signatureStream = $null

        Write-Host ""
        Write-Host "[Test-AppxSignature] Validating ContentInfo" -ForegroundColor Cyan
        $ci = $signedCms.ContentInfo
        $ciTypeName = Get-OidName $ci.ContentType.Value
        Write-Host "  ContentType: $($ci.ContentType.Value) ($ciTypeName)" -ForegroundColor DarkGray

        if ($ci.ContentType.Value -ne "1.3.6.1.4.1.311.2.1.4") {
            throw "AppxSignature.p7x ContentInfo is not of type SPC_INDIRECT_DATA_OBJID, got $($ci.ContentType.Value)"
        }

        Write-Host ""
        $spcData = Get-SpcIndirectDataContent -ContentInfo $ci

        Write-Host ""
        $sipInfo = $spcData | Get-SpcSipInfo

        if ($sipInfo.Identifier -ne $AppxSip -and $sipInfo.Identifier -ne $AppxBundleSip) {
            throw "AppxSignature.p7x does not appear to be an MSIX signature, expected SIP GUID $AppxSip or $AppxBundleSip but got $($sipInfo.Identifier)"
        }

        Write-Host ""
        $appxDigestInfo = $spcData | Get-AppxDigestInfo

        # Verify digest fields
        Write-Host "`n===== Verifying Digest Fields =====" -ForegroundColor Magenta
        $appxDigestInfo | Test-AppxAXPC -FileStream $zipFS -ZipStructure $zipStructure
        $appxDigestInfo | Test-AppxAXCD -FileStream $zipFS -ZipStructure $zipStructure
        $appxDigestInfo | Test-AppxFileHash -ZipArchive $zip -DigestName 'AXCT' -EntryName '[Content_Types].xml'
        $appxDigestInfo | Test-AppxFileHash -ZipArchive $zip -DigestName 'AXBM' -EntryName 'AppxBlockMap.xml'
        $appxDigestInfo | Test-AppxFileHash -ZipArchive $zip -DigestName 'AXCI' -EntryName 'AppxMetadata/CodeIntegrity.cat' -Optional
    }
    finally {
        ${signatureStream}?.Dispose()
        ${zip}?.Dispose()
        ${zipFS}?.Dispose()
    }
}

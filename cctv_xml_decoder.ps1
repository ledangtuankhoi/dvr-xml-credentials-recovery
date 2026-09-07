<#
.SYNOPSIS
    CCTV XML Configuration Parser & Decryptor Utility
.DESCRIPTION
    Extracts and decrypts device credentials and network parameters from CCTV XML export files.
#>

param (
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Path,

    [Parameter(Mandatory=$false)]
    [string]$XmlString
)

# 16-byte Static AES Key
$KeyBytes = [byte[]](0x94, 0x01, 0xe1, 0xc7, 0x9a, 0xab, 0x47, 0x9a, 0xad, 0x75, 0xca, 0xb3, 0x13, 0x5f, 0x1f, 0xcd)

function Decrypt-Password {
    param ([string]$CipherBase64)
    if ([string]::IsNullOrWhiteSpace($CipherBase64)) { return "" }
    try {
        $ct = [Convert]::FromBase64String($CipherBase64)
        if ($ct.Length -lt 16) { return $CipherBase64 }

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aes.Key = $KeyBytes

        $decryptor = $aes.CreateDecryptor()
        $decBytes = $decryptor.TransformFinalBlock($ct, 0, $ct.Length)
        $aes.Dispose()

        return [System.Text.Encoding]::UTF8.GetString($decBytes).TrimEnd([char]0)
    }
    catch {
        return "Error: $($_.Exception.Message)"
    }
}

function Parse-RspPayload {
    param ([string]$RspBase64)
    if ([string]::IsNullOrWhiteSpace($RspBase64)) { return @{} }
    try {
        $bytes = [Convert]::FromBase64String($RspBase64)
        $fw = [System.Text.Encoding]::ASCII.GetString($bytes, 4, 32).TrimEnd([char]0)
        $model = [System.Text.Encoding]::ASCII.GetString($bytes, 0x8c, 32).TrimEnd([char]0)
        return @{ Firmware = $fw; Model = $model }
    }
    catch {
        return @{}
    }
}

# Determine source
$xmlData = $null
if ($XmlString) {
    [xml]$xmlData = "<root>$XmlString</root>"
}
elseif ($Path -and (Test-Path $Path)) {
    [xml]$xmlData = Get-Content -Path $Path -Raw -Encoding UTF8
}
else {
    Write-Host "Usage: .\cctv_xml_decoder.ps1 -Path <file.xml>" -ForegroundColor Yellow
    Write-Host "       or pipe XML string via -XmlString" -ForegroundColor Yellow
    exit
}

$nodes = $xmlData.SelectNodes("//NO")
if (-not $nodes -or $nodes.Count -eq 0) {
    Write-Host "No <NO> device elements found in XML." -ForegroundColor Red
    exit
}

$results = @()

foreach ($node in $nodes) {
    $enc = $node.GetAttribute("encode")
    $rawPw = $node.GetAttribute("Password")
    
    if ($enc -eq "1") {
        $plainPw = Decrypt-Password -CipherBase64 $rawPw
    } else {
        $plainPw = $rawPw
    }

    $rspInfo = Parse-RspPayload -RspBase64 $node.rsp

    $results += [PSCustomObject]@{
        DeviceName   = $node.GetAttribute("DeviceName")
        Connection   = $node.GetAttribute("IP")
        User         = $node.GetAttribute("UserName")
        Password     = $plainPw
        Port         = $node.GetAttribute("MediaPort")
        Channels     = $node.GetAttribute("ChannelNum")
        Encrypted    = ($enc -eq "1")
        Firmware     = $rspInfo.Firmware
        Model        = $rspInfo.Model
    }
}

Write-Host "`n=== CCTV DEVICE DECRYPTED CONFIGURATION ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

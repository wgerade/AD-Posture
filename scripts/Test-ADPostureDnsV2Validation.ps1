#Requires -Version 5.1
<#
.SYNOPSIS
    Summarizes DNS parser v2 evidence from an audit payload.
.DESCRIPTION
    Read-only post-audit validation helper. It reads a generated snapshot or dashboard JSON and reports whether
    DNS binary parsing is producing enough evidence to validate the v2 DNS feature in a lab.
.EXAMPLE
    .\scripts\Test-ADPostureDnsV2Validation.ps1

    Reads reports\latest-dashboard.json or dashboard\latest-dashboard.json and prints a validation summary.
.EXAMPLE
    .\scripts\Test-ADPostureDnsV2Validation.ps1 -SnapshotPath .\data\snapshot-20260602-120000.json -RequireParsedDnsRecords
.EXAMPLE
    .\scripts\Test-ADPostureDnsV2Validation.ps1 -OutputJson .\reports\dns-v2-validation.json
#>
[CmdletBinding()]
param(
    [string]$SnapshotPath,
    [Alias('DashboardJsonPath')]
    [string]$PayloadPath,
    [string]$OutputJson,
    [switch]$RequireParsedDnsRecords,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

function Resolve-ADPostureValidationPayloadPath {
    param(
        [string]$SnapshotPath,
        [string]$PayloadPath
    )

    if ($SnapshotPath) { return (Resolve-Path -LiteralPath $SnapshotPath).Path }
    if ($PayloadPath) { return (Resolve-Path -LiteralPath $PayloadPath).Path }

    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    $candidates = @(
        (Join-Path $repoRoot 'reports\latest-dashboard.json'),
        (Join-Path $repoRoot 'dashboard\latest-dashboard.json')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
    }

    throw "No payload path was provided and no latest dashboard JSON was found. Pass -SnapshotPath or -PayloadPath."
}

function Get-ADPostureValidationArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    @($Value)
}

function ConvertFrom-ADPostureValidationJson {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Json)

    try {
        return ($Json | ConvertFrom-Json)
    }
    catch {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            return ($Json | ConvertFrom-Json -AsHashtable)
        }
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $serializer = [System.Web.Script.Serialization.JavaScriptSerializer]::new()
        $serializer.MaxJsonLength = [int]::MaxValue
        try {
            return $serializer.DeserializeObject($Json)
        }
        catch {
            throw
        }
    }
}

function Get-ADPostureValidationProperty {
    param(
        $Object,
        [Parameter(Mandatory)][string[]]$Names
    )

    if ($null -eq $Object) { return $null }

    foreach ($name in $Names) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.ContainsKey($name)) { return $Object[$name] }
            $match = @($Object.Keys | Where-Object { [string]$_ -ieq $name } | Select-Object -First 1)
            if ($match.Count) { return $Object[$match[0]] }
            continue
        }

        $property = $Object.PSObject.Properties[$name]
        if ($property) { return $property.Value }
        $property = @($Object.PSObject.Properties | Where-Object { $_.Name -ieq $name } | Select-Object -First 1)
        if ($property.Count) { return $property[0].Value }
    }

    $null
}

function Test-ADPostureValidationPropertyEquals {
    param($Object, [string]$Name, $Value)
    (Get-ADPostureValidationProperty -Object $Object -Names @($Name)) -eq $Value
}

function Select-ADPostureValidationProperty {
    param($Object, [string]$Name)
    Get-ADPostureValidationProperty -Object $Object -Names @($Name)
}

function ConvertTo-ADPostureValidationSample {
    param($Object, [string[]]$Names)

    $sample = [ordered]@{}
    foreach ($name in $Names) {
        $sample[$name] = Get-ADPostureValidationProperty -Object $Object -Names @($name)
    }
    [pscustomobject]$sample
}

function New-ADPostureDnsV2ValidationSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Payload,
        [Parameter(Mandatory)][string]$SourcePath,
        [switch]$RequireParsedDnsRecords
    )

    $dnsRecords = Get-ADPostureValidationArray (Get-ADPostureValidationProperty -Object $Payload -Names @('DnsRecords', 'dnsRecords'))
    $dnsFindings = Get-ADPostureValidationArray (Get-ADPostureValidationProperty -Object $Payload -Names @('DnsFindings', 'dnsFindings'))

    $parsedDnsRecords = @($dnsRecords | Where-Object { Test-ADPostureValidationPropertyEquals -Object $_ -Name 'RecordParseStatus' -Value 'Parsed' })
    $parseFailedRecords = @($dnsRecords | Where-Object { (Select-ADPostureValidationProperty -Object $_ -Name 'RecordParseStatus') -in @('ParseFailed', 'TooShort') })
    $unknownRecords = @($dnsRecords | Where-Object { Test-ADPostureValidationPropertyEquals -Object $_ -Name 'RecordParseStatus' -Value 'UnknownBinaryRecord' })
    $binaryRecords = @($dnsRecords | Where-Object {
        $length = Select-ADPostureValidationProperty -Object $_ -Name 'RawRecordLength'
        $length -and [int]$length -gt 0
    })
    $parsedTypes = @($dnsRecords | ForEach-Object { Select-ADPostureValidationProperty -Object $_ -Name 'ParsedRecordType' } | Where-Object { $_ } | Sort-Object -Unique)

    $dnsFindingTypes = @(
        'DnsExternalAliasCandidate',
        'DnsSrvPrivilegedServiceRecord',
        'DnsRecordParseFailure'
    )

    $warnings = [System.Collections.Generic.List[string]]::new()
    if ($RequireParsedDnsRecords -and -not $parsedDnsRecords.Count) {
        $warnings.Add('No parsed DNS binary records were found. Confirm the audit collected raw dnsRecord byte arrays from AD-integrated DNS nodes.')
    }
    if ($binaryRecords.Count -and $parseFailedRecords.Count -gt $parsedDnsRecords.Count) {
        $warnings.Add('More DNS binary records failed parsing than parsed successfully. Review record classes and parser coverage.')
    }

    $dnsV2Findings = @($dnsFindings | Where-Object { $dnsFindingTypes -contains (Select-ADPostureValidationProperty -Object $_ -Name 'FindingType') })
    $status = if ($warnings.Count) { 'Warning' } else { 'ReadyForLabReview' }
    $meta = Get-ADPostureValidationProperty -Object $Payload -Names @('Meta', 'meta')

    [pscustomobject]@{
        SourcePath = $SourcePath
        Domain = if ($meta) { Get-ADPostureValidationProperty -Object $meta -Names @('Domain', 'domain') } else { Get-ADPostureValidationProperty -Object $Payload -Names @('Domain', 'domain') }
        Timestamp = if ($meta) { Get-ADPostureValidationProperty -Object $meta -Names @('Timestamp', 'timestamp') } else { Get-ADPostureValidationProperty -Object $Payload -Names @('Timestamp', 'timestamp') }
        Status = $status
        Warnings = @($warnings)
        Dns = [pscustomobject]@{
            TotalRecords = $dnsRecords.Count
            BinaryRecords = $binaryRecords.Count
            ParsedRecords = $parsedDnsRecords.Count
            ParseFailedRecords = $parseFailedRecords.Count
            UnknownBinaryRecords = $unknownRecords.Count
            ParsedTypes = @($parsedTypes)
            V2FindingCount = $dnsV2Findings.Count
            V2FindingTypes = @($dnsV2Findings | ForEach-Object { Select-ADPostureValidationProperty -Object $_ -Name 'FindingType' } | Sort-Object -Unique)
            SampleParsedRecords = @($parsedDnsRecords | Select-Object -First 10 | ForEach-Object { ConvertTo-ADPostureValidationSample -Object $_ -Names @('RecordName', 'ZoneName', 'RecordType', 'ParsedRecordType', 'ParsedRecordData', 'RecordTtl', 'RecordParseStatus') })
        }
    }
}

$sourcePath = Resolve-ADPostureValidationPayloadPath -SnapshotPath $SnapshotPath -PayloadPath $PayloadPath
$payload = ConvertFrom-ADPostureValidationJson -Json (Get-Content -LiteralPath $sourcePath -Raw -Encoding UTF8)
$summary = New-ADPostureDnsV2ValidationSummary -Payload $payload -SourcePath $sourcePath -RequireParsedDnsRecords:$RequireParsedDnsRecords

if ($OutputJson) {
    $parent = Split-Path -Parent $OutputJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputJson -Encoding UTF8
}

if ($PassThru -or -not $OutputJson) {
    $summary
}

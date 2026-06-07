$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$scriptPath = Join-Path $repoRoot 'scripts\Test-ADPostureDnsV2Validation.ps1'

Describe 'DNS v2 lab validation helper' {
    It 'summarizes parsed DNS evidence from a payload' {
        $path = Join-Path $TestDrive 'payload.json'
        $payload = [pscustomobject]@{
            meta = [pscustomobject]@{ domain = 'corp.example'; timestamp = '2026-06-02T12:00:00Z' }
            dnsRecords = @(
                [pscustomobject]@{
                    RecordName = 'app'
                    ZoneName = 'corp.example'
                    RecordType = 'CNAME'
                    ParsedRecordType = 'CNAME'
                    ParsedRecordData = 'unused.azurewebsites.net'
                    RecordTtl = 3600
                    RecordParseStatus = 'Parsed'
                    RawRecordLength = 48
                },
                [pscustomobject]@{
                    RecordName = 'opaque'
                    ZoneName = 'corp.example'
                    RecordType = 'TYPE99'
                    ParsedRecordType = 'UnknownBinaryRecord'
                    RecordParseStatus = 'UnknownBinaryRecord'
                    RawRecordLength = 32
                }
            )
            dnsFindings = @(
                [pscustomobject]@{ FindingType = 'DnsExternalAliasCandidate' },
                [pscustomobject]@{ FindingType = 'DnsSrvPrivilegedServiceRecord' }
            )
        }
        $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8

        $summary = & $scriptPath -PayloadPath $path -RequireParsedDnsRecords -PassThru

        $summary.Status | Should Be 'ReadyForLabReview'
        $summary.Dns.ParsedRecords | Should Be 1
        $summary.Dns.UnknownBinaryRecords | Should Be 1
        $summary.Dns.V2FindingCount | Should Be 2
    }

    It 'warns when required DNS parser evidence is missing' {
        $path = Join-Path $TestDrive 'empty-payload.json'
        [pscustomobject]@{
            meta = [pscustomobject]@{ domain = 'corp.example' }
            dnsRecords = @()
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $path -Encoding UTF8

        $summary = & $scriptPath -PayloadPath $path -RequireParsedDnsRecords -PassThru

        $summary.Status | Should Be 'Warning'
        @($summary.Warnings).Count | Should Be 1
    }

    It 'writes a JSON summary when requested' {
        $path = Join-Path $TestDrive 'payload-for-output.json'
        $output = Join-Path $TestDrive 'summary.json'
        [pscustomobject]@{
            meta = [pscustomobject]@{ domain = 'corp.example' }
            dnsRecords = @([pscustomobject]@{ RecordParseStatus = 'Parsed'; ParsedRecordType = 'A'; RawRecordLength = 28 })
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding UTF8

        & $scriptPath -PayloadPath $path -OutputJson $output
        $written = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json

        $written.Status | Should Be 'ReadyForLabReview'
        $written.Dns.ParsedRecords | Should Be 1
    }

    It 'loads Windows PowerShell payloads with duplicate keys that differ only by case' {
        $path = Join-Path $TestDrive 'duplicate-case-payload.json'
        @'
{
  "meta": { "domain": "corp.example" },
  "dnsRecords": [
    {
      "RecordName": "app",
      "DistinguishedName": "DC=app,DC=corp,DC=example",
      "distinguishedName": "dc=app,dc=corp,dc=example",
      "RecordParseStatus": "Parsed",
      "ParsedRecordType": "A",
      "RawRecordLength": 28
    }
  ]
}
'@ | Set-Content -LiteralPath $path -Encoding UTF8

        $summary = & $scriptPath -PayloadPath $path -RequireParsedDnsRecords -PassThru

        $summary.Status | Should Be 'ReadyForLabReview'
        $summary.Dns.ParsedRecords | Should Be 1
        $summary.Dns.ParsedTypes[0] | Should Be 'A'
    }
}

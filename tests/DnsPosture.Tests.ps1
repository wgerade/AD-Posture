BeforeAll {
    $repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
    . (Join-Path $repoRoot 'src\Private\Get-ADPostureDnsPosture.ps1')

    function New-TestDnsNameBytes {
        param([string]$Name)

        $bytes = [System.Collections.Generic.List[byte]]::new()
        foreach ($label in $Name.TrimEnd('.').Split('.')) {
            $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)
            $bytes.Add([byte]$labelBytes.Length)
            foreach ($b in $labelBytes) { $bytes.Add($b) }
        }
        $bytes.Add([byte]0)
        [byte[]]$bytes.ToArray()
    }

    function New-TestDnsRecordBinary {
        param(
            [int]$Type,
            [byte[]]$Payload,
            [uint32]$Ttl = 3600,
            [uint32]$Serial = 10,
            [uint32]$Timestamp = 0
        )

        $bytes = [System.Collections.Generic.List[byte]]::new()
        foreach ($b in [BitConverter]::GetBytes([uint16]$Payload.Length)) { $bytes.Add($b) }
        foreach ($b in [BitConverter]::GetBytes([uint16]$Type)) { $bytes.Add($b) }
        $bytes.Add([byte]5)
        $bytes.Add([byte]240)
        foreach ($b in [BitConverter]::GetBytes([uint16]0)) { $bytes.Add($b) }
        foreach ($b in [BitConverter]::GetBytes($Serial)) { $bytes.Add($b) }
        foreach ($b in [BitConverter]::GetBytes($Ttl)) { $bytes.Add($b) }
        foreach ($b in [BitConverter]::GetBytes([uint32]0)) { $bytes.Add($b) }
        foreach ($b in [BitConverter]::GetBytes($Timestamp)) { $bytes.Add($b) }
        foreach ($b in $Payload) { $bytes.Add($b) }
        [byte[]]$bytes.ToArray()
    }

    function Join-TestBytes {
        param([byte[][]]$Parts)

        $bytes = [System.Collections.Generic.List[byte]]::new()
        foreach ($part in $Parts) {
            foreach ($b in $part) { $bytes.Add($b) }
        }
        [byte[]]$bytes.ToArray()
    }

}

Describe 'DNS binary record parser' {
    It 'parses A records from dnsRecord bytes' {
        $record = ConvertFrom-ADPostureDnsRecordBinary -Value (New-TestDnsRecordBinary -Type 1 -Payload ([byte[]](10, 1, 2, 3)))

        $record.ParsedRecordType | Should -Be 'A'
        $record.ParsedRecordData | Should -Be '10.1.2.3'
        $record.RecordTtl | Should -Be 3600
        $record.RecordParseStatus | Should -Be 'Parsed'
    }

    It 'parses AAAA, CNAME, NS, MX, SRV, and TXT records' {
        (ConvertFrom-ADPostureDnsRecordBinary -Value (New-TestDnsRecordBinary -Type 28 -Payload ([System.Net.IPAddress]::Parse('2001:db8::1').GetAddressBytes()))).ParsedRecordType | Should -Be 'AAAA'
        (ConvertFrom-ADPostureDnsRecordBinary -Value (New-TestDnsRecordBinary -Type 5 -Payload (New-TestDnsNameBytes 'unused.azurewebsites.net'))).ParsedRecordData | Should -Be 'unused.azurewebsites.net'
        (ConvertFrom-ADPostureDnsRecordBinary -Value (New-TestDnsRecordBinary -Type 2 -Payload (New-TestDnsNameBytes 'ns1.corp.example'))).ParsedRecordData | Should -Be 'ns1.corp.example'
        (ConvertFrom-ADPostureDnsRecordBinary -Value (New-TestDnsRecordBinary -Type 15 -Payload (Join-TestBytes @([BitConverter]::GetBytes([uint16]10), (New-TestDnsNameBytes 'mail.corp.example'))))).ParsedRecordData | Should -Be 'preference=10 exchange=mail.corp.example'
        (ConvertFrom-ADPostureDnsRecordBinary -Value (New-TestDnsRecordBinary -Type 33 -Payload (Join-TestBytes @([BitConverter]::GetBytes([uint16]0), [BitConverter]::GetBytes([uint16]100), [BitConverter]::GetBytes([uint16]389), (New-TestDnsNameBytes 'dc01.corp.example'))))).ParsedRecordData | Should -Be 'priority=0 weight=100 port=389 target=dc01.corp.example'
        (ConvertFrom-ADPostureDnsRecordBinary -Value (New-TestDnsRecordBinary -Type 16 -Payload ([byte[]](3) + [System.Text.Encoding]::UTF8.GetBytes('txt')))).ParsedRecordData | Should -Be 'txt'
    }

    It 'returns UnknownBinaryRecord for unsupported binary record types' {
        $record = ConvertFrom-ADPostureDnsRecordBinary -Value (New-TestDnsRecordBinary -Type 99 -Payload ([byte[]](1, 2, 3)))

        $record.ParsedRecordType | Should -Be 'UnknownBinaryRecord'
        $record.RecordParseStatus | Should -Be 'UnknownBinaryRecord'
    }
}

Describe 'DNS posture risk model' {
    It 'reports insecure dynamic updates and missing scavenging on AD-integrated zones' {
        $zone = [pscustomobject]@{
            ZoneName = 'corp.example'
            IsADIntegrated = $true
            DynamicUpdate = 'NonsecureAndSecure'
            AgingEnabled = $false
            DistinguishedName = 'DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example'
        }

        $model = ConvertTo-ADPostureDnsRiskModel -Domain 'corp.example' -Zones @($zone)

        @($model.DnsFindings | Where-Object FindingType -eq 'DnsZoneInsecureDynamicUpdate').Count | Should -Be 1
        @($model.DnsFindings | Where-Object FindingType -eq 'DnsZoneNoAgingScavenging').Count | Should -Be 1
    }

    It 'reports wildcard, dangling, and stale records' {
        $records = @(
            [pscustomobject]@{ RecordName = '*'; ZoneName = 'corp.example'; RecordType = 'A'; RecordData = '10.0.0.1' },
            [pscustomobject]@{ RecordName = 'oldapp'; ZoneName = 'corp.example'; RecordType = 'CNAME'; RecordData = 'unused.azurewebsites.net' },
            [pscustomobject]@{ RecordName = 'stale'; ZoneName = 'corp.example'; RecordType = 'A'; RecordData = '10.0.0.2'; Timestamp = (Get-Date).AddDays(-400) }
        )

        $model = ConvertTo-ADPostureDnsRiskModel -Domain 'corp.example' -Records $records -StaleRecordDays 180

        @($model.DnsFindings | Where-Object FindingType -eq 'DnsWildcardRecord').Count | Should -Be 1
        @($model.DnsFindings | Where-Object FindingType -eq 'DnsDanglingRecordCandidate').Count | Should -Be 1
        @($model.DnsFindings | Where-Object FindingType -eq 'DnsStaleRecord').Count | Should -Be 1
    }

    It 'correlates DNS ACL evidence without changing raw ACL semantics' {
        $acl = [pscustomobject]@{
            TargetName = 'corp.example'
            TargetDistinguishedName = 'DC=corp.example,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example'
            TargetObjectClass = 'dnsZone'
            TrusteeName = 'Helpdesk DNS'
            NormalizedRight = 'GenericAll'
            RiskScore = 8
            Reason = 'Raw ACL evidence'
        }

        $model = ConvertTo-ADPostureDnsRiskModel -Domain 'corp.example' -AclFindings @($acl)

        @($model.DnsFindings | Where-Object FindingType -eq 'DnsAclControlDelegation').Count | Should -Be 1
        ($model.DnsFindings | Where-Object FindingType -eq 'DnsAclControlDelegation').Principal | Should -Be 'Helpdesk DNS'
    }

    It 'uses parsed CNAME and SRV data for DNS v2 findings' {
        $records = @(
            [pscustomobject]@{ RecordName = 'oldalias'; ZoneName = 'corp.example'; dnsRecord = New-TestDnsRecordBinary -Type 5 -Payload (New-TestDnsNameBytes 'unused.azurewebsites.net') },
            [pscustomobject]@{ RecordName = '_ldap._tcp'; ZoneName = 'corp.example'; dnsRecord = New-TestDnsRecordBinary -Type 33 -Payload (Join-TestBytes @([BitConverter]::GetBytes([uint16]0), [BitConverter]::GetBytes([uint16]100), [BitConverter]::GetBytes([uint16]389), (New-TestDnsNameBytes 'dc01.corp.example'))) }
        )

        $model = ConvertTo-ADPostureDnsRiskModel -Domain 'corp.example' -Records $records

        @($model.DnsFindings | Where-Object FindingType -eq 'DnsExternalAliasCandidate').Count | Should -Be 1
        @($model.DnsFindings | Where-Object FindingType -eq 'DnsSrvPrivilegedServiceRecord').Count | Should -Be 1
        ($model.DnsRecords | Where-Object RecordName -eq 'oldalias').ParsedRecordData | Should -Be 'unused.azurewebsites.net'
    }
}

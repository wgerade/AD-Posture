function Get-ADPostureDnsValue {
    param(
        [Parameter(Mandatory)]
        $Object,
        [string[]]$Names = @()
    )

    foreach ($name in $Names) {
        if ($Object.PSObject.Properties[$name] -and $null -ne $Object.$name -and -not [string]::IsNullOrWhiteSpace([string]$Object.$name)) {
            return $Object.$name
        }
    }

    $null
}

function ConvertTo-ADPostureDnsBool {
    param($Value, [bool]$Default = $false)

    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return [bool]$Value }
    $text = ([string]$Value).Trim()
    if ($text -match '^(?i:true|yes|1|enabled|secure)$') { return $true }
    if ($text -match '^(?i:false|no|0|disabled|none)$') { return $false }
    $Default
}

function ConvertFrom-ADPostureDnsRecordName {
    param(
        [byte[]]$Bytes,
        [int]$Offset = 0
    )

    if (-not $Bytes -or $Offset -ge $Bytes.Length) { return $null }

    $labels = [System.Collections.Generic.List[string]]::new()
    $cursor = $Offset
    while ($cursor -lt $Bytes.Length) {
        $length = [int]$Bytes[$cursor]
        $cursor++
        if ($length -eq 0) { break }
        if ($length -gt 63 -or ($cursor + $length) -gt $Bytes.Length) { return $null }
        $labels.Add([System.Text.Encoding]::ASCII.GetString($Bytes, $cursor, $length))
        $cursor += $length
    }

    if (-not $labels.Count) { return $null }
    ($labels -join '.').TrimEnd('.')
}

function ConvertTo-ADPostureDnsUInt16 {
    param([byte[]]$Bytes, [int]$Offset)
    if (-not $Bytes -or ($Offset + 1) -ge $Bytes.Length) { return $null }
    [BitConverter]::ToUInt16($Bytes, $Offset)
}

function ConvertTo-ADPostureDnsUInt32 {
    param([byte[]]$Bytes, [int]$Offset)
    if (-not $Bytes -or ($Offset + 3) -ge $Bytes.Length) { return $null }
    [BitConverter]::ToUInt32($Bytes, $Offset)
}

function ConvertTo-ADPostureDnsTtl {
    param([byte[]]$Bytes, [int]$Offset)

    if (-not $Bytes -or ($Offset + 3) -ge $Bytes.Length) { return $null }
    $little = [BitConverter]::ToUInt32($Bytes, $Offset)
    $big = ([uint32]$Bytes[$Offset] -shl 24) -bor ([uint32]$Bytes[$Offset + 1] -shl 16) -bor ([uint32]$Bytes[$Offset + 2] -shl 8) -bor [uint32]$Bytes[$Offset + 3]
    if ($little -gt 315360000 -and $big -le 315360000) { return [uint32]$big }
    [uint32]$little
}

function ConvertTo-ADPostureDnsRecordTypeName {
    param([int]$RecordType)

    switch ($RecordType) {
        1 { 'A' }
        2 { 'NS' }
        5 { 'CNAME' }
        15 { 'MX' }
        16 { 'TXT' }
        28 { 'AAAA' }
        33 { 'SRV' }
        default { 'TYPE{0}' -f $RecordType }
    }
}

function ConvertFrom-ADPostureDnsRecordBinary {
    [CmdletBinding()]
    param($Value)

    $bytes = $null
    if ($Value -is [byte[]]) {
        $bytes = [byte[]]$Value
    }
    elseif ($Value -and $Value -is [array] -and @($Value | Where-Object { $_ -isnot [byte] }).Count -eq 0) {
        $bytes = [byte[]]$Value
    }

    if (-not $bytes) {
        return [pscustomobject]@{
            ParsedRecordType = $null
            ParsedRecordData = $null
            RecordTtl = $null
            RecordSerial = $null
            RecordTimestamp = $null
            RecordParseStatus = 'NotBinary'
            RawRecordLength = 0
        }
    }

    $result = [ordered]@{
        ParsedRecordType = 'UnknownBinaryRecord'
        ParsedRecordData = $null
        RecordTtl = $null
        RecordSerial = $null
        RecordTimestamp = $null
        RecordParseStatus = 'ParseFailed'
        RawRecordLength = $bytes.Length
    }

    try {
        if ($bytes.Length -lt 24) {
            $result.RecordParseStatus = 'TooShort'
            return [pscustomobject]$result
        }

        $dataLength = ConvertTo-ADPostureDnsUInt16 -Bytes $bytes -Offset 0
        $recordTypeValue = ConvertTo-ADPostureDnsUInt16 -Bytes $bytes -Offset 2
        $recordType = ConvertTo-ADPostureDnsRecordTypeName -RecordType $recordTypeValue
        $serial = ConvertTo-ADPostureDnsUInt32 -Bytes $bytes -Offset 8
        $ttl = ConvertTo-ADPostureDnsTtl -Bytes $bytes -Offset 12
        $timestamp = ConvertTo-ADPostureDnsUInt32 -Bytes $bytes -Offset 20
        $dataOffset = 24
        $availableLength = [Math]::Max(0, $bytes.Length - $dataOffset)
        $payloadLength = if ($dataLength -and $dataLength -gt 0 -and $dataLength -le $availableLength) { [int]$dataLength } else { $availableLength }
        $payload = New-Object byte[] $payloadLength
        if ($payloadLength -gt 0) { [Array]::Copy($bytes, $dataOffset, $payload, 0, $payloadLength) }

        $result.ParsedRecordType = $recordType
        $result.RecordTtl = $ttl
        $result.RecordSerial = $serial
        $result.RecordTimestamp = $timestamp

        switch ($recordType) {
            'A' {
                if ($payload.Length -ge 4) {
                    $result.ParsedRecordData = ([System.Net.IPAddress]::new($payload[0..3])).ToString()
                    $result.RecordParseStatus = 'Parsed'
                }
            }
            'AAAA' {
                if ($payload.Length -ge 16) {
                    $addr = New-Object byte[] 16
                    [Array]::Copy($payload, 0, $addr, 0, 16)
                    $result.ParsedRecordData = ([System.Net.IPAddress]::new($addr)).ToString()
                    $result.RecordParseStatus = 'Parsed'
                }
            }
            { $_ -in @('CNAME', 'NS') } {
                $name = ConvertFrom-ADPostureDnsRecordName -Bytes $payload
                if ($name) {
                    $result.ParsedRecordData = $name
                    $result.RecordParseStatus = 'Parsed'
                }
            }
            'MX' {
                if ($payload.Length -ge 3) {
                    $preference = ConvertTo-ADPostureDnsUInt16 -Bytes $payload -Offset 0
                    $exchange = ConvertFrom-ADPostureDnsRecordName -Bytes $payload -Offset 2
                    if ($exchange) {
                        $result.ParsedRecordData = "preference=$preference exchange=$exchange"
                        $result.RecordParseStatus = 'Parsed'
                    }
                }
            }
            'SRV' {
                if ($payload.Length -ge 7) {
                    $priority = ConvertTo-ADPostureDnsUInt16 -Bytes $payload -Offset 0
                    $weight = ConvertTo-ADPostureDnsUInt16 -Bytes $payload -Offset 2
                    $port = ConvertTo-ADPostureDnsUInt16 -Bytes $payload -Offset 4
                    $target = ConvertFrom-ADPostureDnsRecordName -Bytes $payload -Offset 6
                    if ($target) {
                        $result.ParsedRecordData = "priority=$priority weight=$weight port=$port target=$target"
                        $result.RecordParseStatus = 'Parsed'
                    }
                }
            }
            'TXT' {
                $parts = [System.Collections.Generic.List[string]]::new()
                $cursor = 0
                while ($cursor -lt $payload.Length) {
                    $length = [int]$payload[$cursor]
                    $cursor++
                    if ($length -eq 0) { continue }
                    if (($cursor + $length) -gt $payload.Length) { break }
                    $parts.Add([System.Text.Encoding]::UTF8.GetString($payload, $cursor, $length))
                    $cursor += $length
                }
                if ($parts.Count) {
                    $result.ParsedRecordData = $parts -join ' '
                    $result.RecordParseStatus = 'Parsed'
                }
            }
            default {
                $result.ParsedRecordType = 'UnknownBinaryRecord'
                $result.ParsedRecordData = [BitConverter]::ToString($payload)
                $result.RecordParseStatus = 'UnknownBinaryRecord'
            }
        }

        [pscustomobject]$result
    }
    catch {
        $result.RecordParseStatus = 'ParseFailed'
        $result.ParsedRecordData = $_.Exception.Message
        [pscustomobject]$result
    }
}

function ConvertTo-ADPostureDnsZoneObject {
    param(
        [Parameter(Mandatory)]$InputObject,
        [string]$Domain
    )

    $name = Get-ADPostureDnsValue -Object $InputObject -Names @('ZoneName', 'Name', 'DC', 'name')
    $dynamicUpdate = Get-ADPostureDnsValue -Object $InputObject -Names @('DynamicUpdate', 'AllowUpdate', 'SecureSecondaries')
    $aging = Get-ADPostureDnsValue -Object $InputObject -Names @('AgingEnabled', 'ScavengingEnabled')

    [pscustomobject]@{
        Domain = $Domain
        ZoneName = if ($name) { [string]$name } else { 'Unknown zone' }
        DistinguishedName = Get-ADPostureDnsValue -Object $InputObject -Names @('DistinguishedName')
        ObjectGuid = Get-ADPostureDnsValue -Object $InputObject -Names @('ObjectGuid')
        ObjectClass = if (Get-ADPostureDnsValue -Object $InputObject -Names @('ObjectClass')) { [string](Get-ADPostureDnsValue -Object $InputObject -Names @('ObjectClass')) } else { 'dnsZone' }
        IsAdIntegrated = ConvertTo-ADPostureDnsBool -Value (Get-ADPostureDnsValue -Object $InputObject -Names @('IsDsIntegrated', 'IsADIntegrated', 'DsIntegrated')) -Default:$true
        DynamicUpdate = if ($dynamicUpdate) { [string]$dynamicUpdate } else { 'Unknown' }
        AgingEnabled = ConvertTo-ADPostureDnsBool -Value $aging -Default:$false
        ScavengingEnabled = ConvertTo-ADPostureDnsBool -Value (Get-ADPostureDnsValue -Object $InputObject -Names @('ScavengingEnabled', 'AgingEnabled')) -Default:$false
        IsReverseLookupZone = ConvertTo-ADPostureDnsBool -Value (Get-ADPostureDnsValue -Object $InputObject -Names @('IsReverseLookupZone')) -Default:([string]$name -match '(?i)in-addr\.arpa|ip6\.arpa')
        WhenChanged = Get-ADPostureDnsValue -Object $InputObject -Names @('WhenChanged', 'Modified')
    }
}

function ConvertTo-ADPostureDnsRecordObject {
    param(
        [Parameter(Mandatory)]$InputObject,
        [string]$Domain
    )

    $name = Get-ADPostureDnsValue -Object $InputObject -Names @('RecordName', 'Name', 'DC', 'name')
    $zone = Get-ADPostureDnsValue -Object $InputObject -Names @('ZoneName', 'Zone', 'ParentZone')
    $rawDnsRecord = Get-ADPostureDnsValue -Object $InputObject -Names @('dnsRecord')
    $parsedRecord = ConvertFrom-ADPostureDnsRecordBinary -Value $rawDnsRecord
    $data = Get-ADPostureDnsValue -Object $InputObject -Names @('RecordData', 'Data', 'Target', 'HostNameAlias')
    $type = Get-ADPostureDnsValue -Object $InputObject -Names @('RecordType', 'Type', 'RRType')
    $timestamp = Get-ADPostureDnsValue -Object $InputObject -Names @('Timestamp', 'TimeStamp', 'WhenChanged')
    $recordData = if ($parsedRecord.RecordParseStatus -in @('Parsed', 'UnknownBinaryRecord') -and $parsedRecord.ParsedRecordData) { [string]$parsedRecord.ParsedRecordData } elseif ($data) { [string](@($data) -join '; ') } else { $null }
    $recordType = if ($parsedRecord.RecordParseStatus -ne 'NotBinary' -and $parsedRecord.ParsedRecordType) { [string]$parsedRecord.ParsedRecordType } elseif ($type) { [string]$type } else { 'Unknown' }
    $parsedTimestamp = if ($parsedRecord.RecordTimestamp -and [uint32]$parsedRecord.RecordTimestamp -gt 0) { [string]$parsedRecord.RecordTimestamp } else { $null }

    [pscustomobject]@{
        Domain = $Domain
        RecordName = if ($name) { [string]$name } else { 'Unknown record' }
        ZoneName = if ($zone) { [string]$zone } else { $null }
        RecordType = $recordType
        RecordData = $recordData
        ParsedRecordType = $parsedRecord.ParsedRecordType
        ParsedRecordData = $parsedRecord.ParsedRecordData
        RecordTtl = $parsedRecord.RecordTtl
        RecordSerial = $parsedRecord.RecordSerial
        RecordTimestamp = $parsedTimestamp
        RecordParseStatus = $parsedRecord.RecordParseStatus
        RawRecordLength = $parsedRecord.RawRecordLength
        DistinguishedName = Get-ADPostureDnsValue -Object $InputObject -Names @('DistinguishedName')
        ObjectGuid = Get-ADPostureDnsValue -Object $InputObject -Names @('ObjectGuid')
        Timestamp = if ($timestamp -is [datetime]) { $timestamp.ToString('o') } elseif ($timestamp) { [string]$timestamp } else { $null }
        IsWildcard = ([string]$name -eq '*' -or [string]$name -match '^\*\.' -or [string]$recordData -match '^\*\.')
        IsDanglingCandidate = ([string]$recordData -match '(?i)(azurewebsites\.net|cloudapp\.net|trafficmanager\.net|github\.io|herokuapp\.com|amazonaws\.com|cloudfront\.net)$')
    }
}

function Get-ADPostureDnsSeverity {
    param([double]$RiskScore)

    if ($RiskScore -ge 10) { return 'Critical' }
    if ($RiskScore -ge 7) { return 'High' }
    if ($RiskScore -ge 4) { return 'Medium' }
    if ($RiskScore -gt 0) { return 'Low' }
    'Informational'
}

function New-ADPostureDnsFinding {
    param(
        [Parameter(Mandatory)][int]$Index,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$FindingType,
        [Parameter(Mandatory)][string]$RiskPattern,
        [Parameter(Mandatory)][double]$RiskScore,
        [string]$ZoneName,
        [string]$RecordName,
        [string]$RecordType,
        [string]$RecordData,
        [string]$ParsedRecordType,
        [string]$ParsedRecordData,
        [string]$RecordParseStatus,
        [string]$DistinguishedName,
        [string]$Principal,
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][string]$Remediation,
        [Parameter(Mandatory)][string]$ScoreFormula,
        [object[]]$ScoreComponents = @(),
        [object[]]$AttackTechniques = @(),
        [string[]]$Tags = @()
    )

    [pscustomobject]@{
        DnsFindingId = 'dns-{0:000000}' -f $Index
        Domain = $Domain
        FindingType = $FindingType
        RiskPattern = $RiskPattern
        Severity = Get-ADPostureDnsSeverity -RiskScore $RiskScore
        RiskScore = [Math]::Round($RiskScore, 2)
        ZoneName = $ZoneName
        RecordName = $RecordName
        RecordType = $RecordType
        RecordData = $RecordData
        ParsedRecordType = $ParsedRecordType
        ParsedRecordData = $ParsedRecordData
        RecordParseStatus = $RecordParseStatus
        DistinguishedName = $DistinguishedName
        Principal = $Principal
        Reason = $Reason
        Remediation = $Remediation
        ScoreFormula = $ScoreFormula
        ScoreComponents = @($ScoreComponents)
        AttackTechniques = @($AttackTechniques)
        Tags = @($Tags + 'DnsPosture' | Sort-Object -Unique)
    }
}

function ConvertTo-ADPostureDnsRiskModel {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [object[]]$Zones = @(),
        [object[]]$Records = @(),
        [object[]]$DnsAdmins = @(),
        [object[]]$AclFindings = @(),
        [int]$StaleRecordDays = 180
    )

    $zones = @($Zones | ForEach-Object { ConvertTo-ADPostureDnsZoneObject -InputObject $_ -Domain $Domain })
    $records = @($Records | ForEach-Object { ConvertTo-ADPostureDnsRecordObject -InputObject $_ -Domain $Domain })
    $findings = [System.Collections.Generic.List[object]]::new()
    $index = 0
    $staleCutoff = (Get-Date).AddDays(-1 * [Math]::Max(1, $StaleRecordDays))

    foreach ($zone in $zones) {
        if ($zone.IsAdIntegrated -and $zone.DynamicUpdate -notmatch '^(?i:secure|secureonly|secure updates only)$') {
            $index++
            $findings.Add((New-ADPostureDnsFinding -Index $index -Domain $Domain -FindingType 'DnsZoneInsecureDynamicUpdate' -RiskPattern 'Insecure dynamic update' -RiskScore 8.0 -ZoneName $zone.ZoneName -DistinguishedName $zone.DistinguishedName -Reason "AD-integrated zone '$($zone.ZoneName)' does not show secure-only dynamic updates." -Remediation 'Require secure dynamic updates for AD-integrated zones and review DHCP/DNS registration flows.' -ScoreFormula 'DNS score = AD-integrated zone + non-secure dynamic update' -ScoreComponents @([pscustomobject]@{ Name = 'DynamicUpdate'; Value = $zone.DynamicUpdate; Reason = 'Untrusted updates can poison service discovery' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1557'; Name = 'Adversary-in-the-Middle'; Tactic = 'Credential Access, Collection' }) -Tags @('DnsZone', 'DynamicUpdate', 'Tier0Exposure')))
        }

        if ($zone.IsAdIntegrated -and -not $zone.AgingEnabled -and -not $zone.ScavengingEnabled) {
            $index++
            $findings.Add((New-ADPostureDnsFinding -Index $index -Domain $Domain -FindingType 'DnsZoneNoAgingScavenging' -RiskPattern 'Stale DNS retention' -RiskScore 4.0 -ZoneName $zone.ZoneName -DistinguishedName $zone.DistinguishedName -Reason "AD-integrated zone '$($zone.ZoneName)' does not show aging/scavenging evidence." -Remediation 'Enable and tune DNS aging/scavenging where operationally safe; review stale records before deletion.' -ScoreFormula 'DNS score = AD-integrated zone + no aging/scavenging evidence' -ScoreComponents @([pscustomobject]@{ Name = 'Aging'; Value = $zone.AgingEnabled; Reason = 'Stale records can become takeover or misrouting opportunities' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1584.008'; Name = 'Stage Capabilities: Malvertising'; Tactic = 'Resource Development' }) -Tags @('DnsZone', 'StaleRecords')))
        }
    }

    foreach ($record in $records) {
        if ($record.IsWildcard) {
            $index++
            $findings.Add((New-ADPostureDnsFinding -Index $index -Domain $Domain -FindingType 'DnsWildcardRecord' -RiskPattern 'Wildcard DNS record' -RiskScore 6.0 -ZoneName $record.ZoneName -RecordName $record.RecordName -RecordType $record.RecordType -RecordData $record.RecordData -ParsedRecordType $record.ParsedRecordType -ParsedRecordData $record.ParsedRecordData -RecordParseStatus $record.RecordParseStatus -DistinguishedName $record.DistinguishedName -Reason "DNS record '$($record.RecordName)' in zone '$($record.ZoneName)' behaves like a wildcard." -Remediation 'Remove wildcard records unless explicitly required; document owner and scope if retained.' -ScoreFormula 'DNS score = wildcard record + AD service discovery risk' -ScoreComponents @([pscustomobject]@{ Name = 'Wildcard'; Value = $true; Reason = 'Wildcard records can mask mistakes and route unexpected names' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1557'; Name = 'Adversary-in-the-Middle'; Tactic = 'Credential Access, Collection' }) -Tags @('Wildcard', 'DnsRecord')))
        }

        if ($record.IsDanglingCandidate) {
            $index++
            $findingType = if ($record.ParsedRecordData -and $record.RecordType -eq 'CNAME') { 'DnsExternalAliasCandidate' } else { 'DnsDanglingRecordCandidate' }
            $aliasTags = @('DanglingRecord', 'ExternalDependency')
            if ($record.RecordParseStatus -eq 'Parsed') { $aliasTags += 'Parsed' }
            $findings.Add((New-ADPostureDnsFinding -Index $index -Domain $Domain -FindingType $findingType -RiskPattern 'Dangling external DNS target' -RiskScore 7.2 -ZoneName $record.ZoneName -RecordName $record.RecordName -RecordType $record.RecordType -RecordData $record.RecordData -ParsedRecordType $record.ParsedRecordType -ParsedRecordData $record.ParsedRecordData -RecordParseStatus $record.RecordParseStatus -DistinguishedName $record.DistinguishedName -Reason "DNS record '$($record.RecordName)' points to an external cloud/SaaS hostname that should be ownership-validated." -Remediation 'Validate the external target is still owned, remove stale CNAMEs, and require owner metadata for public/cloud aliases.' -ScoreFormula 'DNS score = external alias pattern + takeover candidate' -ScoreComponents @([pscustomobject]@{ Name = 'Record data'; Value = $record.RecordData; Reason = 'Known external hosting suffix can be takeover-prone if unclaimed' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1584.001'; Name = 'Domains'; Tactic = 'Resource Development' }) -Tags $aliasTags))
        }

        if ($record.RecordType -eq 'SRV' -and $record.ParsedRecordData -and $record.RecordName -match '(?i)^_?(ldap|kerberos|kpasswd|gc|msdcs|winrm|termsrv)') {
            $index++
            $findings.Add((New-ADPostureDnsFinding -Index $index -Domain $Domain -FindingType 'DnsSrvPrivilegedServiceRecord' -RiskPattern 'Privileged service discovery record' -RiskScore 3.5 -ZoneName $record.ZoneName -RecordName $record.RecordName -RecordType $record.RecordType -RecordData $record.RecordData -ParsedRecordType $record.ParsedRecordType -ParsedRecordData $record.ParsedRecordData -RecordParseStatus $record.RecordParseStatus -DistinguishedName $record.DistinguishedName -Reason "SRV record '$($record.RecordName)' advertises privileged service discovery target '$($record.RecordData)'." -Remediation 'Validate SRV targets, ownership, and lifecycle for privileged AD service discovery records.' -ScoreFormula 'DNS score = parsed SRV record + privileged service name' -ScoreComponents @([pscustomobject]@{ Name = 'Parsed SRV'; Value = $record.RecordData; Reason = 'Privileged service discovery records should point only to expected managed hosts' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1018'; Name = 'Remote System Discovery'; Tactic = 'Discovery' }) -Tags @('SRV', 'DnsRecord', 'Parsed')))
        }

        if ($record.RecordParseStatus -in @('ParseFailed', 'TooShort')) {
            $index++
            $findings.Add((New-ADPostureDnsFinding -Index $index -Domain $Domain -FindingType 'DnsRecordParseFailure' -RiskPattern 'DNS record parser context' -RiskScore 0.0 -ZoneName $record.ZoneName -RecordName $record.RecordName -RecordType $record.RecordType -RecordData $record.RecordData -ParsedRecordType $record.ParsedRecordType -ParsedRecordData $record.ParsedRecordData -RecordParseStatus $record.RecordParseStatus -DistinguishedName $record.DistinguishedName -Reason "DNS record '$($record.RecordName)' had binary dnsRecord data that could not be fully parsed." -Remediation 'Review raw DNS record evidence manually if this object is security-sensitive.' -ScoreFormula 'DNS score = parser context only' -ScoreComponents @([pscustomobject]@{ Name = 'Parse status'; Value = $record.RecordParseStatus; Reason = 'Parser failures are informational and do not raise risk by themselves' }) -Tags @('ParseFailed', 'DnsRecord', 'Context')))
        }

        if ($record.Timestamp) {
            $recordTime = $null
            try { $recordTime = [datetime]$record.Timestamp } catch { $recordTime = $null }
            if ($recordTime -and $recordTime -lt $staleCutoff) {
                $index++
                $findings.Add((New-ADPostureDnsFinding -Index $index -Domain $Domain -FindingType 'DnsStaleRecord' -RiskPattern 'Stale DNS record' -RiskScore 3.0 -ZoneName $record.ZoneName -RecordName $record.RecordName -RecordType $record.RecordType -RecordData $record.RecordData -ParsedRecordType $record.ParsedRecordType -ParsedRecordData $record.ParsedRecordData -RecordParseStatus $record.RecordParseStatus -DistinguishedName $record.DistinguishedName -Reason "DNS record '$($record.RecordName)' has timestamp older than $StaleRecordDays days." -Remediation 'Validate the host/service owner and remove or refresh stale DNS records.' -ScoreFormula 'DNS score = DNS timestamp older than stale threshold' -ScoreComponents @([pscustomobject]@{ Name = 'Days since timestamp'; Value = [int]((Get-Date) - $recordTime).TotalDays; Reason = 'Old DNS records create drift and takeover risk' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1584.001'; Name = 'Domains'; Tactic = 'Resource Development' }) -Tags @('StaleRecord')))
            }
        }
    }

    foreach ($admin in @($DnsAdmins)) {
        $name = if ($admin.SamAccountName) { [string]$admin.SamAccountName } elseif ($admin.Name) { [string]$admin.Name } else { [string]$admin }
        $index++
        $findings.Add((New-ADPostureDnsFinding -Index $index -Domain $Domain -FindingType 'DnsAdminsExposure' -RiskPattern 'Privileged DNS administration' -RiskScore 7.5 -Principal $name -Reason "Principal '$name' is a member of DnsAdmins or equivalent DNS administration scope." -Remediation 'Keep DnsAdmins empty or tightly governed; require named owner, PAW/admin workflow, and expiry for every member.' -ScoreFormula 'DNS score = DnsAdmins membership' -ScoreComponents @([pscustomobject]@{ Name = 'DnsAdmins member'; Value = $name; Reason = 'DnsAdmins can alter DNS server behavior and records' }) -AttackTechniques @([pscustomobject]@{ Id = 'T1098'; Name = 'Account Manipulation'; Tactic = 'Persistence, Privilege Escalation' }) -Tags @('DnsAdmins', 'Tier0Exposure')))
    }

    foreach ($acl in @($AclFindings | Where-Object { $_.TargetDistinguishedName -match '(?i)DC=DomainDnsZones|DC=ForestDnsZones|CN=MicrosoftDNS' -or $_.TargetObjectClass -match '(?i)dns' })) {
        $index++
        $findings.Add((New-ADPostureDnsFinding -Index $index -Domain $Domain -FindingType 'DnsAclControlDelegation' -RiskPattern 'DNS object ACL control' -RiskScore ([Math]::Max(5.0, [double]$acl.RiskScore)) -ZoneName $acl.TargetName -DistinguishedName $acl.TargetDistinguishedName -Principal $acl.TrusteeName -Reason "Principal '$($acl.TrusteeName)' has $($acl.NormalizedRight) over DNS object '$($acl.TargetName)'." -Remediation 'Remove broad or stale DNS object delegation and keep DNS ACL changes under change control.' -ScoreFormula 'DNS score = raw ACL evidence on DNS object' -ScoreComponents @([pscustomobject]@{ Name = 'ACL right'; Value = $acl.NormalizedRight; Reason = $acl.Reason }) -AttackTechniques @($acl.AttackTechniques) -Tags @('DnsAcl', 'Delegation', 'Tier0Exposure')))
    }

    [pscustomobject]@{
        DnsZones = @($zones)
        DnsRecords = @($records)
        DnsAdmins = @($DnsAdmins)
        DnsFindings = @($findings)
    }
}

function Get-ADPostureDnsPosture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Domain,
        [hashtable]$DomainParams = @{},
        [object[]]$AclFindings = @(),
        [string]$LogPath
    )

    Write-Host 'DNS posture collection: reading AD-integrated DNS zones, records, and DnsAdmins.'
    if ($LogPath) { Write-ADPostureLog -Message 'DNS posture collection: reading AD-integrated DNS zones, records, and DnsAdmins.' -Path $LogPath }

    $domainName = if ($Domain.DNSRoot) { $Domain.DNSRoot } else { [string]$Domain }
    $zones = @()
    $records = @()
    $dnsAdmins = @()
    $searchBases = @(
        "CN=MicrosoftDNS,DC=DomainDnsZones,$($Domain.DistinguishedName)",
        "CN=MicrosoftDNS,DC=ForestDnsZones,$($Domain.DistinguishedName)"
    )

    foreach ($base in $searchBases) {
        try {
            $zones += @(Get-ADObject -LDAPFilter '(objectClass=dnsZone)' -SearchBase $base -Properties * @DomainParams -ErrorAction Stop)
            $records += @(Get-ADObject -LDAPFilter '(objectClass=dnsNode)' -SearchBase $base -Properties * @DomainParams -ErrorAction Stop)
        }
        catch {
            Write-Verbose "DNS AD partition query skipped for $base. $($_.Exception.Message)"
        }
    }

    try {
        $group = Get-ADGroup -Filter "Name -eq 'DnsAdmins'" @DomainParams -ErrorAction Stop
        $dnsAdmins = @(Get-ADGroupMember -Identity $group.DistinguishedName -Recursive @DomainParams -ErrorAction Stop)
    }
    catch {
        Write-Verbose "DnsAdmins enumeration skipped. $($_.Exception.Message)"
    }

    $model = ConvertTo-ADPostureDnsRiskModel -Domain $domainName -Zones @($zones) -Records @($records) -DnsAdmins @($dnsAdmins) -AclFindings @($AclFindings)
    $message = "DNS posture collection complete: $(@($model.DnsZones).Count) zones, $(@($model.DnsRecords).Count) records, $(@($model.DnsFindings).Count) findings."
    Write-Host $message
    if ($LogPath) { Write-ADPostureLog -Message $message -Path $LogPath }
    $model
}

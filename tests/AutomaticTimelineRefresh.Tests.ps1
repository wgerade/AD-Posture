$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

function Update-ADPostureSnapshotV12 {
    param($Snapshot)
    $Snapshot | Add-Member -NotePropertyName SchemaVersion -NotePropertyValue '1.2' -Force
    $Snapshot
}

function Update-ADPosturePrimarySnapshotArtifact {
    param($Snapshot)
    $script:PrimarySnapshotUpdates++
}

function Get-ModuleConfig {
    [pscustomobject]@{ DataPath = $TestDrive }
}

function Compare-ADPostureSnapshots {
    param([switch]$UseLatestTwo, [string]$DataDirectory)
    if ($script:ComparisonShouldFail) { throw 'Synthetic comparison failure' }
    $script:ComparisonCalls++
}

function Write-ADPostureAtomicTextFile {
    param([string]$Path, [string]$Value)
    Set-Content -LiteralPath $Path -Value $Value -Encoding UTF8
}

function Protect-ADPostureSensitiveFile {
    param([string]$Path)
}

function Get-ADPostureDashboardPayload {
    param($Snapshot, [switch]$RedactSensitiveAclEvidence)
    [pscustomobject]@{ meta = [pscustomobject]@{ schemaVersion = $Snapshot.SchemaVersion } }
}

function Write-ADPostureDashboardData {
    param($DashboardData, [string]$SerializedJson)
    $script:DashboardWriteCalls++
}

. (Join-Path $repoRoot 'src\Public\Export-ADPostureReport.ps1')

function New-AutomaticTimelineSnapshot {
    [pscustomobject]@{
        Findings = @()
        GroupSummaries = @()
        AclFindings = @()
        GpoFindings = @()
        AdcsFindings = @()
        AdcsCas = @()
        KerberosAuthFindings = @()
        KerberosAuthPrincipals = @()
        TrustFindings = @()
        Trusts = @()
        DnsFindings = @()
        DnsZones = @()
        DnsRecords = @()
    }
}

Describe 'Automatic timeline refresh' {
    BeforeEach {
        $script:DashboardWriteCalls = 0
        $script:PrimarySnapshotUpdates = 0
        $script:ComparisonCalls = 0
        $script:ComparisonShouldFail = $false
        $script:ADPostureSkipTimelineRefresh = $false
        Set-Content -LiteralPath (Join-Path $TestDrive 'snapshot-1.json') -Value '{}'
        Set-Content -LiteralPath (Join-Path $TestDrive 'snapshot-2.json') -Value '{}'
    }

    It 'refreshes after two snapshots and honors SkipTimelineRefresh' {
        $snapshot = New-AutomaticTimelineSnapshot

        Export-ADPostureReport -Snapshot $snapshot -OutputBasePath (Join-Path $TestDrive 'audit')
        $script:ComparisonCalls | Should Be 1
        $snapshot.SchemaVersion | Should Be '1.2'

        $script:ADPostureSkipTimelineRefresh = $true
        Export-ADPostureReport -Snapshot $snapshot -OutputBasePath (Join-Path $TestDrive 'audit-skip')

        $script:ComparisonCalls | Should Be 1
        $script:DashboardWriteCalls | Should Be 2
        $script:PrimarySnapshotUpdates | Should Be 2
    }

    It 'does not fail the audit when timeline refresh fails' {
        $script:ComparisonShouldFail = $true

        { Export-ADPostureReport -Snapshot (New-AutomaticTimelineSnapshot) -OutputBasePath (Join-Path $TestDrive 'audit') -WarningAction SilentlyContinue } |
            Should Not Throw

        $script:DashboardWriteCalls | Should Be 1
        $script:PrimarySnapshotUpdates | Should Be 1
    }
}

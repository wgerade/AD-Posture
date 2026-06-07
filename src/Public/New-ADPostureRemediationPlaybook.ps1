function New-ADPostureRemediationPlaybook {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][object] $Finding)

    process {
        $domain = Get-ADPostureFindingDomain -Finding $Finding
        $findingId = if ([string]::IsNullOrWhiteSpace([string]$Finding.FindingId)) { [guid]::NewGuid().ToString('N') } else { [string]$Finding.FindingId }
        $script = $null
        $blocked = $null
        $canGenerate = $false

        if ($domain -eq 'DNS') {
            $zone = [string]$Finding.ZoneName
            $record = [string]$Finding.RecordName
            $recordType = [string]$Finding.RecordType
            if ($zone -and $record -and $recordType) {
                $qZone = $zone.Replace("'", "''")
                $qRecord = $record.Replace("'", "''")
                $qType = $recordType.Replace("'", "''")
                $script = "`$record = Get-DnsServerResourceRecord -ZoneName '$qZone' -Name '$qRecord' -RRType '$qType' -ErrorAction Stop`r`nif (-not `$record) { throw 'DNS record is no longer present; aborting.' }`r`nRemove-DnsServerResourceRecord -ZoneName '$qZone' -InputObject `$record -WhatIf -ErrorAction Stop"
                $canGenerate = $true
            }
            else { $blocked = 'A deterministic DNS change requires proven ZoneName, RecordName, and RecordType.' }
        }
        elseif ($domain -eq 'SensitiveGroups') {
            $blocked = if ([string]$Finding.FindingType -eq 'OrphanedSensitiveGroup') { 'Empty privileged groups require ownership and dependency review; deletion is never scripted automatically.' } elseif ($Finding.RemediationBlockedReason) { [string]$Finding.RemediationBlockedReason } else { 'Use the membership remediation command only for a proven direct membership target.' }
        }
        else {
            $blocked = switch ($domain) {
                'ACL' { 'ACL mutation is blocked until trustee, object, access mask, inheritance, and rollback evidence are all proven.' }
                'GPO' { 'GPO mutation is blocked until the exact setting, current value, scope, and backup are proven.' }
                'ADCS' { 'ADCS mutation is blocked until template, CA publication state, enrollment paths, and rollback evidence are proven.' }
                default { 'This finding has a review playbook but no deterministic safe mutation script.' }
            }
        }

        [pscustomobject]@{
            PlaybookId           = "playbook-$findingId"
            FindingId            = $findingId
            FindingDomain        = $domain
            FindingType          = [string]$Finding.FindingType
            Title                = "Review and remediate $domain finding"
            CanGenerateScript    = $canGenerate
            CanExecuteMutation   = $false
            BlockedReason        = $blocked
            ValidationSteps      = @('Re-run the relevant posture collection immediately before remediation.', 'Confirm the finding still exists and its identifying evidence is unchanged.', 'Obtain change approval and preserve a rollback path.')
            WhatIfScript         = $script
            WhatIfRequired       = $true
            ExpectedImpact       = if ($canGenerate) { 'Removes only the proven insecure configuration after explicit operator review.' } else { 'Provides a governed review path without making an unproven change.' }
            EvidenceRequirements = @('Capture the pre-change finding and collector output.', 'Run validation commands after the approved change.', 'Attach post-change collector output and audit timestamp.')
        }
    }
}

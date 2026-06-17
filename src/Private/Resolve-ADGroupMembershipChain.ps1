function Get-ADPostureMembershipRemediationMetadataKey {
    param(
        [AllowNull()][string]$SensitiveGroup,
        [AllowNull()][string]$MemberDn,
        [AllowNull()][string]$MembershipChain
    )

    "$SensitiveGroup|$MemberDn|$MembershipChain".ToLowerInvariant()
}

function Get-ADPostureGroupMemberWithFallback {
    <#
    .SYNOPSIS
    Enumerates direct group members, falling back to the member attribute when Get-ADGroupMember fails.
    .DESCRIPTION
    Get-ADGroupMember fails on groups that contain foreign security principals or orphaned members and on
    very large groups. Dropping the whole group silently would hide privileged exposure, so this helper
    retries through the member attribute and resolves each DN individually. Members resolved through the
    fallback path are real directory objects; unresolvable DNs are kept as minimal named entries so the
    finding is reported instead of lost.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupDn,

        [hashtable]$DomainParams = @{}
    )

    try {
        return [pscustomobject]@{
            Members = @(Get-ADGroupMember -Identity $GroupDn @DomainParams -ErrorAction Stop)
            EnumerationMode = 'Standard'
        }
    }
    catch {
        $standardError = $_.Exception.Message
        try {
            $group = Get-ADGroup -Identity $GroupDn -Properties member @DomainParams -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not enumerate members of '$GroupDn'. Standard enumeration failed ($standardError) and the member attribute could not be read: $($_.Exception.Message)"
            return [pscustomobject]@{ Members = @(); EnumerationMode = 'Failed' }
        }

        Write-Warning "Get-ADGroupMember failed for '$GroupDn' ($standardError). Falling back to member-attribute enumeration; primaryGroupID-only members are not visible through this path."

        $members = [System.Collections.Generic.List[object]]::new()
        foreach ($memberDn in @($group.member)) {
            if ([string]::IsNullOrWhiteSpace($memberDn)) { continue }
            $resolved = $null
            try {
                $resolved = Get-ADObject -Identity $memberDn -Properties objectClass, objectSid, sAMAccountName, name @DomainParams -ErrorAction Stop
            }
            catch {
                Write-Verbose "Member DN '$memberDn' in '$GroupDn' could not be resolved: $($_.Exception.Message)"
            }

            if ($resolved) {
                $members.Add([pscustomobject]@{
                    Name = $resolved.Name
                    SamAccountName = $resolved.sAMAccountName
                    DistinguishedName = $resolved.DistinguishedName
                    objectClass = $resolved.ObjectClass
                    SID = $resolved.objectSid
                })
            }
            else {
                $leafName = ($memberDn -split ',')[0] -replace '^CN=', ''
                $members.Add([pscustomobject]@{
                    Name = $leafName
                    SamAccountName = $leafName
                    DistinguishedName = $memberDn
                    objectClass = 'unknown'
                    SID = $null
                })
            }
        }

        [pscustomobject]@{
            Members = @($members)
            EnumerationMode = 'MemberAttributeFallback'
        }
    }
}

function Resolve-ADGroupMembershipChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupIdentity,
        [int]$MaxDepth = 32,
        [hashtable]$DomainParams = @{}
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $visitedPaths = @{}
    if (-not $script:ADPostureMembershipRemediationMap) {
        $script:ADPostureMembershipRemediationMap = @{}
    }

    function Add-MembershipRow {
        param(
            $Member,
            $Chain,
            $IsDirect,
            [string]$DirectParentGroupName,
            [string]$DirectParentGroupDn,
            [bool]$TruncatedNesting = $false,
            [string]$EnumerationMode = 'Standard'
        )

        $pathKey = ($Chain + $Member.DistinguishedName) -join '|'
        if ($visitedPaths.ContainsKey($pathKey)) { return }
        $visitedPaths[$pathKey] = $true

        $blockedReason = $null
        if ($TruncatedNesting) {
            $blockedReason = 'Membership chain is truncated, cyclic, or incomplete.'
        }
        elseif ([string]::IsNullOrWhiteSpace($DirectParentGroupDn)) {
            $blockedReason = 'Direct parent group could not be proven.'
        }

        $row = [pscustomobject]@{
            Member                       = $Member
            Chain                        = $Chain
            ChainDisplay                 = ($Chain -join ' -> ')
            NestingDepth                 = [Math]::Max(0, $Chain.Count - 2)
            IsDirectMembership           = $IsDirect
            TruncatedNesting             = $TruncatedNesting
            MembershipEnumerationMode    = $EnumerationMode
            DirectParentGroupName        = $DirectParentGroupName
            DirectParentGroupDn          = $DirectParentGroupDn
            CanGenerateRemediationScript = [string]::IsNullOrWhiteSpace($blockedReason)
            RemediationBlockedReason     = $blockedReason
        }
        $results.Add($row)

        $metadataKey = Get-ADPostureMembershipRemediationMetadataKey `
            -SensitiveGroup $rootGroup.Name `
            -MemberDn $Member.DistinguishedName `
            -MembershipChain $row.ChainDisplay
        $script:ADPostureMembershipRemediationMap[$metadataKey] = $row
    }

    function Expand-Group {
        param([string]$GroupDn, [string[]]$Chain, [string[]]$GroupDnPath, [int]$Depth)

        if ($Depth -ge $MaxDepth) { return }

        $enumeration = Get-ADPostureGroupMemberWithFallback -GroupDn $GroupDn -DomainParams $DomainParams
        if ($enumeration.EnumerationMode -eq 'Failed') { return }

        foreach ($member in @($enumeration.Members)) {
            $newChain = $Chain + @($member.Name)
            $isGroup = $member.objectClass -eq 'group'
            $nextDepth = $Depth + 1
            $isCycle = $isGroup -and $GroupDnPath -contains $member.DistinguishedName
            $isTruncated = $isGroup -and ($isCycle -or $nextDepth -ge $MaxDepth)
            Add-MembershipRow `
                -Member $member `
                -Chain $newChain `
                -IsDirect:($Chain.Count -eq 1) `
                -DirectParentGroupName $Chain[-1] `
                -DirectParentGroupDn $GroupDn `
                -TruncatedNesting:$isTruncated `
                -EnumerationMode $enumeration.EnumerationMode

            if ($isGroup -and -not $isCycle -and $nextDepth -lt $MaxDepth) {
                Expand-Group -GroupDn $member.DistinguishedName -Chain $newChain -GroupDnPath ($GroupDnPath + @($member.DistinguishedName)) -Depth $nextDepth
            }
        }
    }

    $rootGroup = Get-ADGroup -Identity $GroupIdentity -Properties DistinguishedName, Name @DomainParams -ErrorAction SilentlyContinue
    if (-not $rootGroup) { return @() }

    Expand-Group -GroupDn $rootGroup.DistinguishedName -Chain @($rootGroup.Name) -GroupDnPath @($rootGroup.DistinguishedName) -Depth 0
    return $results
}

# Loaded after the base resolver so safe-remediation metadata is available without changing its public contract.
function Get-ADPostureMembershipRemediationMetadataKey {
    param(
        [AllowNull()][string]$SensitiveGroup,
        [AllowNull()][string]$MemberDn,
        [AllowNull()][string]$MembershipChain
    )

    "$SensitiveGroup|$MemberDn|$MembershipChain".ToLowerInvariant()
}

function Resolve-ADGroupMembershipChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupIdentity,
        [int]$MaxDepth = 32
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
            [bool]$TruncatedNesting = $false
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

        try {
            $members = Get-ADGroupMember -Identity $GroupDn -ErrorAction Stop
        }
        catch {
            return
        }

        foreach ($member in $members) {
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
                -TruncatedNesting:$isTruncated

            if ($isGroup -and -not $isCycle -and $nextDepth -lt $MaxDepth) {
                Expand-Group -GroupDn $member.DistinguishedName -Chain $newChain -GroupDnPath ($GroupDnPath + @($member.DistinguishedName)) -Depth $nextDepth
            }
        }
    }

    $rootGroup = Get-ADGroup -Identity $GroupIdentity -Properties DistinguishedName, Name -ErrorAction SilentlyContinue
    if (-not $rootGroup) { return @() }

    Expand-Group -GroupDn $rootGroup.DistinguishedName -Chain @($rootGroup.Name) -GroupDnPath @($rootGroup.DistinguishedName) -Depth 0
    return $results
}

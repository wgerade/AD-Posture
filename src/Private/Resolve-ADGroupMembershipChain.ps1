function Resolve-ADGroupMembershipChain {
    <#
    .SYNOPSIS
    Resolve members of a sensitive group with full nesting chain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupIdentity,
        [int]$MaxDepth = 32
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $visitedPaths = @{}

    function Add-MembershipRow {
        param($Member, $Chain, $IsDirect, [bool]$TruncatedNesting = $false)
        $pathKey = ($Chain + $Member.DistinguishedName) -join '|'
        if ($visitedPaths.ContainsKey($pathKey)) { return }
        $visitedPaths[$pathKey] = $true

        $results.Add([PSCustomObject]@{
            Member              = $Member
            Chain               = $Chain
            ChainDisplay        = ($Chain -join ' -> ')
            NestingDepth        = [Math]::Max(0, $Chain.Count - 2)
            IsDirectMembership  = $IsDirect
            TruncatedNesting    = $TruncatedNesting
        })
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

        foreach ($m in $members) {
            $newChain = $Chain + @($m.Name)
            $isGroup = $m.objectClass -eq 'group'
            $nextDepth = $Depth + 1
            $isCycle = $isGroup -and $GroupDnPath -contains $m.DistinguishedName
            $isTruncated = $isGroup -and ($isCycle -or $nextDepth -ge $MaxDepth)
            Add-MembershipRow -Member $m -Chain $newChain -IsDirect:($Chain.Count -eq 1) -TruncatedNesting:$isTruncated

            if ($isGroup -and -not $isCycle -and $nextDepth -lt $MaxDepth) {
                Expand-Group -GroupDn $m.DistinguishedName -Chain $newChain -GroupDnPath ($GroupDnPath + @($m.DistinguishedName)) -Depth $nextDepth
            }
        }
    }

    $group = Get-ADGroup -Identity $GroupIdentity -Properties DistinguishedName, Name -ErrorAction SilentlyContinue
    if (-not $group) { return @() }

    $rootChain = @($group.Name)
    Expand-Group -GroupDn $group.DistinguishedName -Chain $rootChain -GroupDnPath @($group.DistinguishedName) -Depth 0

    return $results
}

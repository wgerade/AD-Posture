function Resolve-ADNativeIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Principal,
        [string]$AccountType = 'Unknown'
    )

    $sid = if ($Principal.SID -and $Principal.SID.Value) { $Principal.SID.Value } else { $null }
    $name = (($Principal.Name -as [string]), ($Principal.SamAccountName -as [string]) | Where-Object { $_ }) -join ' '

    $category = 'Custom'
    $isNative = $false
    $isRemediable = $true
    $reason = $null

    if ($sid -eq 'S-1-5-9' -or $name -match 'ENTERPRISE DOMAIN CONTROLLERS') {
        $category = 'Native AD authority'
        $isNative = $true
        $isRemediable = $false
        $reason = 'Enterprise Domain Controllers is a well-known AD authority principal managed by Windows/AD architecture'
    }
    elseif ($sid -match '^S-1-5-32-') {
        $category = 'Built-in local domain group'
        $isNative = $true
        $isRemediable = $false
        $reason = 'Built-in group created by Windows/AD'
    }
    elseif ($sid -match '^S-1-5-21-.+-(500|501|502|512|513|514|515|516|517|518|519|520|521|522|525|526|527|548|549|550|551|553|571|572)$') {
        $category = 'Built-in domain principal'
        $isNative = $true
        $isRemediable = $false
        $reason = 'Well-known domain RID created by AD'
    }
    elseif ($AccountType -eq 'Computer' -and ($Principal.SamAccountName -as [string]) -match '\$$') {
        $category = 'AD computer account'
        $reason = 'Computer account object'
    }

    [PSCustomObject]@{
        IsNativeIdentity       = $isNative
        NativeIdentityCategory = $category
        NativeIdentityReason   = $reason
        IsRemediableIdentity   = $isRemediable
    }
}

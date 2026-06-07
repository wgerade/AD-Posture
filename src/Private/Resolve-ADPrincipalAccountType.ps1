function Resolve-ADPrincipalAccountType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Principal
    )

    $classes = @($Principal.objectClass) | Where-Object { $_ } | ForEach-Object { $_.ToString().ToLowerInvariant() }
    $category = ($Principal.objectCategory -as [string])
    $categoryLower = if ($category) { $category.ToLowerInvariant() } else { '' }
    $sam = ($Principal.SamAccountName -as [string])

    $isGmsa =
        $classes -contains 'msds-groupmanagedserviceaccount' -or
        $classes -contains 'ms-ds-group-managed-service-account' -or
        $categoryLower -like '*cn=ms-ds-group-managed-service-account,*'

    if ($isGmsa) {
        return [PSCustomObject]@{
            Kind        = 'GroupManagedServiceAccount'
            AccountType = 'ServiceAccount (gMSA)'
        }
    }

    $isSmsa =
        $classes -contains 'msds-managedserviceaccount' -or
        $classes -contains 'ms-ds-managed-service-account' -or
        $categoryLower -like '*cn=ms-ds-managed-service-account,*'

    if ($isSmsa) {
        return [PSCustomObject]@{
            Kind        = 'ManagedServiceAccount'
            AccountType = 'ServiceAccount (sMSA)'
        }
    }

    if ($classes -contains 'group') {
        return [PSCustomObject]@{
            Kind        = 'Group'
            AccountType = 'Group'
        }
    }

    if ($classes -contains 'computer') {
        return [PSCustomObject]@{
            Kind        = 'Computer'
            AccountType = 'Computer'
        }
    }

    if ($classes -contains 'user') {
        if ($sam -match '\$$') {
            return [PSCustomObject]@{
                Kind        = 'Computer'
                AccountType = 'Computer'
            }
        }

        return [PSCustomObject]@{
            Kind        = 'User'
            AccountType = 'User'
        }
    }

    [PSCustomObject]@{
        Kind        = 'Unknown'
        AccountType = 'Unknown'
    }
}

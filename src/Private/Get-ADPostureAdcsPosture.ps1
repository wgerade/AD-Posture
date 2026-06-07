function Test-ADPostureAdcsBroadPrincipal {
    param([string]$Principal)

    if ([string]::IsNullOrWhiteSpace($Principal)) { return $false }
    if ($Principal -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546')) { return $true }
    if ($Principal -match '(?i)(^|\\)(Everyone|Todos|Authenticated Users|Usu[aÃ¡]rios autenticados|Domain Users|Usu[aÃ¡]rios do dom[iÃ­]nio|Users|Guests)$') { return $true }
    $false
}

function Get-ADPostureAdcsSeverity {
    param([double]$RiskScore)

    if ($RiskScore -ge 10) { return 'Critical' }
    if ($RiskScore -ge 7) { return 'High' }
    if ($RiskScore -ge 3) { return 'Medium' }
    if ($RiskScore -gt 0) { return 'Low' }
    'Informational'
}

function ConvertTo-ADPostureAdcsArray {
    param($Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [array]) { return @($Value) }
    @($Value)
}

function ConvertTo-ADPostureAdcsTemplateObject {
    param([object]$InputObject)

    $properties = $InputObject.PSObject.Properties
    $nameFlags = if ($properties['msPKI-Certificate-Name-Flag']) { [int]$properties['msPKI-Certificate-Name-Flag'].Value } else { 0 }
    $enrollmentFlags = if ($properties['msPKI-Enrollment-Flag']) { [int]$properties['msPKI-Enrollment-Flag'].Value } else { 0 }
    $privateKeyFlags = if ($properties['msPKI-Private-Key-Flag']) { [int]$properties['msPKI-Private-Key-Flag'].Value } else { 0 }
    $signatureCount = if ($properties['msPKI-RA-Signature']) { [int]$properties['msPKI-RA-Signature'].Value } else { 0 }
    $eku = if ($properties['pKIExtendedKeyUsage']) { @(ConvertTo-ADPostureAdcsArray $properties['pKIExtendedKeyUsage'].Value) } else { @() }
    $schemaVersion = if ($properties['msPKI-Template-Schema-Version']) { [int]$properties['msPKI-Template-Schema-Version'].Value } else { $null }
    $enrollmentPrincipals = if ($properties['EnrollmentPrincipals']) { @(ConvertTo-ADPostureAdcsArray $properties['EnrollmentPrincipals'].Value) } else { @() }
    $autoEnrollmentPrincipals = if ($properties['AutoEnrollmentPrincipals']) { @(ConvertTo-ADPostureAdcsArray $properties['AutoEnrollmentPrincipals'].Value) } else { @() }
    $controlPrincipals = if ($properties['ControlPrincipals']) { @(ConvertTo-ADPostureAdcsArray $properties['ControlPrincipals'].Value) } else { @() }

    [pscustomobject]@{
        Name = if ($properties['Name']) { [string]$properties['Name'].Value } else { $null }
        DisplayName = if ($properties['DisplayName']) { [string]$properties['DisplayName'].Value } elseif ($properties['Name']) { [string]$properties['Name'].Value } else { $null }
        DistinguishedName = if ($properties['DistinguishedName']) { [string]$properties['DistinguishedName'].Value } else { $null }
        ObjectGuid = if ($properties['ObjectGUID']) { [string]$properties['ObjectGUID'].Value } else { $null }
        SchemaVersion = $schemaVersion
        CertificateNameFlags = $nameFlags
        EnrollmentFlags = $enrollmentFlags
        PrivateKeyFlags = $privateKeyFlags
        RequiredRaSignatures = $signatureCount
        ExtendedKeyUsage = @($eku)
        EnrollmentPrincipals = @($enrollmentPrincipals)
        AutoEnrollmentPrincipals = @($autoEnrollmentPrincipals)
        ControlPrincipals = @($controlPrincipals)
        EnrolleeSuppliesSubject = (($nameFlags -band 0x1) -eq 0x1)
        ManagerApprovalRequired = (($enrollmentFlags -band 0x2) -eq 0x2)
        ExportablePrivateKey = (($privateKeyFlags -band 0x10) -eq 0x10)
        PublishedCas = @()
    }
}

function ConvertTo-ADPostureAdcsCaObject {
    param([object]$InputObject)

    $properties = $InputObject.PSObject.Properties
    $templates = if ($properties['certificateTemplates']) { @(ConvertTo-ADPostureAdcsArray $properties['certificateTemplates'].Value) } else { @() }
    $controlPrincipals = if ($properties['ControlPrincipals']) { @(ConvertTo-ADPostureAdcsArray $properties['ControlPrincipals'].Value) } else { @() }
    $configuration = if ($properties['Configuration']) { $properties['Configuration'].Value } else { $null }

    [pscustomobject]@{
        Name = if ($properties['Name']) { [string]$properties['Name'].Value } else { $null }
        DisplayName = if ($properties['DisplayName']) { [string]$properties['DisplayName'].Value } elseif ($properties['Name']) { [string]$properties['Name'].Value } else { $null }
        DistinguishedName = if ($properties['DistinguishedName']) { [string]$properties['DistinguishedName'].Value } else { $null }
        ObjectGuid = if ($properties['ObjectGUID']) { [string]$properties['ObjectGUID'].Value } else { $null }
        DnsHostName = if ($properties['dNSHostName']) { [string]$properties['dNSHostName'].Value } else { $null }
        CertificateTemplates = @($templates)
        ControlPrincipals = @($controlPrincipals)
        Configuration = $configuration
        AcceptsRequestSubjectAltName = if ($configuration -and $configuration.PSObject.Properties['AcceptsRequestSubjectAltName']) { [bool]$configuration.AcceptsRequestSubjectAltName } else { $false }
        RequestDisposition = if ($configuration -and $configuration.PSObject.Properties['RequestDisposition']) { $configuration.RequestDisposition } else { $null }
        ConfigurationSource = if ($configuration -and $configuration.PSObject.Properties['Source']) { $configuration.Source } else { $null }
        ConfigurationReadError = if ($configuration -and $configuration.PSObject.Properties['ReadError']) { $configuration.ReadError } else { $null }
    }
}

function ConvertTo-ADPostureAdcsNtAuthObject {
    param([object]$InputObject)

    $properties = $InputObject.PSObject.Properties
    $certificates = if ($properties['cACertificate']) { @(ConvertTo-ADPostureAdcsArray $properties['cACertificate'].Value) } else { @() }
    $controlPrincipals = if ($properties['ControlPrincipals']) { @(ConvertTo-ADPostureAdcsArray $properties['ControlPrincipals'].Value) } else { @() }

    [pscustomobject]@{
        Name = if ($properties['Name']) { [string]$properties['Name'].Value } else { 'NTAuthCertificates' }
        DisplayName = if ($properties['DisplayName']) { [string]$properties['DisplayName'].Value } elseif ($properties['Name']) { [string]$properties['Name'].Value } else { 'NTAuthCertificates' }
        DistinguishedName = if ($properties['DistinguishedName']) { [string]$properties['DistinguishedName'].Value } else { $null }
        ObjectGuid = if ($properties['ObjectGUID']) { [string]$properties['ObjectGUID'].Value } else { $null }
        CertificateCount = @($certificates).Count
        ControlPrincipals = @($controlPrincipals)
    }
}

function New-ADPostureAdcsFinding {
    param(
        [int]$Index,
        [string]$Domain,
        [string]$FindingType,
        [string]$RiskPattern,
        [double]$RiskScore,
        [string]$Reason,
        [string]$Remediation,
        [object]$Template,
        [object]$Ca,
        [object]$TargetObject,
        [string]$Principal,
        [string]$EscTechnique,
        [string[]]$AttackPath = @(),
        [string[]]$Tags = @(),
        [string]$ScoreFormula,
        [object[]]$ScoreComponents = @()
    )

    $publishedCas = if ($Template -and $Template.PSObject.Properties['PublishedCas']) { @($Template.PublishedCas) } elseif ($Ca) { @($Ca.DisplayName) } else { @() }
    $publishedCaNames = if ($Template -and $Template.PSObject.Properties['PublishedCas']) { @($Template.PublishedCas | ForEach-Object { if ($_.PSObject.Properties['DisplayName']) { $_.DisplayName } else { $_ } }) } elseif ($Ca) { @($Ca.DisplayName) } else { @() }

    [pscustomobject]@{
        AdcsFindingId = ('adcs-{0:d6}' -f $Index)
        Domain = $Domain
        FindingType = $FindingType
        RiskPattern = $RiskPattern
        Severity = Get-ADPostureAdcsSeverity -RiskScore $RiskScore
        RiskScore = [Math]::Round($RiskScore, 2)
        TemplateName = if ($Template) { $Template.DisplayName } else { $null }
        TemplateShortName = if ($Template) { $Template.Name } else { $null }
        TemplateDistinguishedName = if ($Template) { $Template.DistinguishedName } else { $null }
        TemplateSchemaVersion = if ($Template) { $Template.SchemaVersion } else { $null }
        PublishedCas = [object[]]$publishedCas
        PublishedCaNames = [string[]]$publishedCaNames
        CaName = if ($Ca) { $Ca.DisplayName } else { $null }
        CaDistinguishedName = if ($Ca) { $Ca.DistinguishedName } else { $null }
        TargetObjectName = if ($TargetObject) { $TargetObject.DisplayName } elseif ($Ca) { $Ca.DisplayName } elseif ($Template) { $Template.DisplayName } else { $null }
        TargetDistinguishedName = if ($TargetObject) { $TargetObject.DistinguishedName } elseif ($Ca) { $Ca.DistinguishedName } elseif ($Template) { $Template.DistinguishedName } else { $null }
        Principal = $Principal
        EscTechnique = $EscTechnique
        AttackPath = [string[]]@($AttackPath)
        EnrolleeSuppliesSubject = if ($Template) { [bool]$Template.EnrolleeSuppliesSubject } else { $false }
        ManagerApprovalRequired = if ($Template) { [bool]$Template.ManagerApprovalRequired } else { $false }
        RequiredRaSignatures = if ($Template) { [int]$Template.RequiredRaSignatures } else { 0 }
        ExportablePrivateKey = if ($Template) { [bool]$Template.ExportablePrivateKey } else { $false }
        ExtendedKeyUsage = if ($Template) { @($Template.ExtendedKeyUsage) } else { @() }
        Reason = $Reason
        Remediation = $Remediation
        ScoreFormula = $ScoreFormula
        ScoreComponents = @($ScoreComponents)
        Tags = @($Tags | Where-Object { $_ } | Sort-Object -Unique)
    }
}

function New-ADPostureAdcsAttackPath {
    param(
        [string]$Principal,
        [object]$Template,
        [object]$Ca,
        [string]$Technique,
        [string]$Impact
    )

    $parts = @($Principal)
    if ($Template) { $parts += "Enrolls via template '$($Template.DisplayName)'" }
    if ($Ca) { $parts += "Issued by CA '$($Ca.DisplayName)'" }
    if ($Technique) { $parts += $Technique }
    if ($Impact) { $parts += $Impact }
    @($parts | Where-Object { $_ })
}

function Test-ADPostureAdcsAuthenticationEku {
    param([string[]]$ExtendedKeyUsage = @())

    if (-not @($ExtendedKeyUsage).Count) { return $true }
    $authEkus = @(
        '1.3.6.1.5.5.7.3.2',
        '1.3.6.1.4.1.311.20.2.2',
        '1.3.6.1.5.2.3.4',
        '2.5.29.37.0'
    )
    @($ExtendedKeyUsage | Where-Object { $authEkus -contains [string]$_ }).Count -gt 0
}

function Test-ADPostureAdcsEnrollmentAgentEku {
    param([string[]]$ExtendedKeyUsage = @())

    @($ExtendedKeyUsage | Where-Object { [string]$_ -eq '1.3.6.1.4.1.311.20.2.1' }).Count -gt 0
}

function Test-ADPostureAdcsAnyPurposeEku {
    param([string[]]$ExtendedKeyUsage = @())

    @($ExtendedKeyUsage | Where-Object { [string]$_ -eq '2.5.29.37.0' }).Count -gt 0
}

function Get-ADPostureAdcsCaRegistryConfiguration {
    [CmdletBinding()]
    param([object]$Ca)

    $computerName = if ($Ca.DnsHostName) { [string]$Ca.DnsHostName } else { $env:COMPUTERNAME }
    $caName = [string]$Ca.Name
    if ([string]::IsNullOrWhiteSpace($caName)) {
        return [pscustomobject]@{ Source = 'Unavailable'; ReadError = 'CA name is empty.'; AcceptsRequestSubjectAltName = $false }
    }

    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $computerName)
        try {
            $caKey = $baseKey.OpenSubKey("SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName")
            if (-not $caKey) {
                return [pscustomobject]@{ Source = "RemoteRegistry:$computerName"; ReadError = "CA registry key not found for '$caName'."; AcceptsRequestSubjectAltName = $false }
            }

            $policyKey = $caKey.OpenSubKey('PolicyModules\CertificateAuthority_MicrosoftDefault.Policy')
            $editFlags = if ($policyKey) { $policyKey.GetValue('EditFlags', 0) } else { 0 }
            $requestDisposition = if ($policyKey) { $policyKey.GetValue('RequestDisposition', $null) } else { $null }
            $interfaceFlags = $caKey.GetValue('InterfaceFlags', $null)

            [pscustomobject]@{
                Source = "RemoteRegistry:$computerName"
                EditFlags = [int]$editFlags
                RequestDisposition = $requestDisposition
                InterfaceFlags = $interfaceFlags
                AcceptsRequestSubjectAltName = (([int]$editFlags -band 0x00040000) -eq 0x00040000)
                ReadError = $null
            }
        }
        finally {
            if ($baseKey) { $baseKey.Close() }
        }
    }
    catch {
        [pscustomobject]@{
            Source = "RemoteRegistry:$computerName"
            ReadError = $_.Exception.Message
            AcceptsRequestSubjectAltName = $false
        }
    }
}

function ConvertFrom-ADPostureAdcsTemplateAccessRules {
    [CmdletBinding()]
    param(
        [object[]]$AccessRules = @()
    )

    $enrollGuid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoEnrollGuid = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    $enrollment = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $autoEnrollment = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $control = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($ace in @($AccessRules)) {
        if ([string]$ace.AccessControlType -ne 'Allow') { continue }
        $principal = [string]$ace.IdentityReference
        if ([string]::IsNullOrWhiteSpace($principal)) { continue }

        $rights = [string]$ace.ActiveDirectoryRights
        $objectType = ([string]$ace.ObjectType).Trim('{}').ToLowerInvariant()
        if ($objectType -eq $enrollGuid) { [void]$enrollment.Add($principal) }
        if ($objectType -eq $autoEnrollGuid) { [void]$autoEnrollment.Add($principal) }
        if ($rights -match '(?i)(GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty)') { [void]$control.Add($principal) }
    }

    [pscustomobject]@{
        EnrollmentPrincipals = @($enrollment)
        AutoEnrollmentPrincipals = @($autoEnrollment)
        ControlPrincipals = @($control)
    }
}

function ConvertFrom-ADPostureAdcsObjectAccessRules {
    [CmdletBinding()]
    param(
        [object[]]$AccessRules = @()
    )

    $control = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ace in @($AccessRules)) {
        if ([string]$ace.AccessControlType -ne 'Allow') { continue }
        $principal = [string]$ace.IdentityReference
        if ([string]::IsNullOrWhiteSpace($principal)) { continue }

        $rights = [string]$ace.ActiveDirectoryRights
        if ($rights -match '(?i)(GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty)') {
            [void]$control.Add($principal)
        }
    }

    [pscustomobject]@{ ControlPrincipals = @($control) }
}

function Get-ADPostureAdcsObjectAccess {
    [CmdletBinding()]
    param([string]$DistinguishedName)

    if (-not $DistinguishedName) { return [pscustomobject]@{ ControlPrincipals = @() } }

    try {
        $acl = Get-Acl -LiteralPath "AD:\$DistinguishedName" -ErrorAction Stop
        return ConvertFrom-ADPostureAdcsObjectAccessRules -AccessRules @($acl.Access)
    }
    catch {
        $providerError = $_.Exception.Message
        try {
            $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$DistinguishedName")
            $rules = @($entry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]))
            return ConvertFrom-ADPostureAdcsObjectAccessRules -AccessRules $rules
        }
        catch {
            Write-Verbose "Could not read ADCS object ACL for '$DistinguishedName'. AD provider failed: $providerError. LDAP fallback failed: $($_.Exception.Message)"
        }
    }

    [pscustomobject]@{ ControlPrincipals = @() }
}

function ConvertTo-ADPostureAdcsRiskModel {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [object[]]$Templates = @(),
        [object[]]$Cas = @(),
        [object]$NtAuth = $null
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $index = 0

    $publishedByTemplate = @{}
    foreach ($ca in @($Cas)) {
        foreach ($templateName in @($ca.CertificateTemplates)) {
            if ([string]::IsNullOrWhiteSpace([string]$templateName)) { continue }
            if (-not $publishedByTemplate.ContainsKey([string]$templateName)) {
                $publishedByTemplate[[string]$templateName] = @()
            }
            $publishedByTemplate[[string]$templateName] = @($publishedByTemplate[[string]$templateName]) + $ca
        }
    }

    foreach ($template in @($Templates)) {
        $publishedCas = if ($template.Name -and $publishedByTemplate.ContainsKey([string]$template.Name)) { @($publishedByTemplate[[string]$template.Name]) } else { @() }
        $template | Add-Member -NotePropertyName PublishedCas -NotePropertyValue @($publishedCas) -Force
        $enrollmentPrincipals = @(@($template.EnrollmentPrincipals) + @($template.AutoEnrollmentPrincipals) | Where-Object { $_ } | Sort-Object -Unique)
        $autoEnrollmentPrincipals = @($template.AutoEnrollmentPrincipals)
        $controlPrincipals = @($template.ControlPrincipals)
        $broadEnrollment = @($enrollmentPrincipals | Where-Object { Test-ADPostureAdcsBroadPrincipal -Principal ([string]$_) })
        $broadAutoEnrollment = @($autoEnrollmentPrincipals | Where-Object { Test-ADPostureAdcsBroadPrincipal -Principal ([string]$_) })
        $broadControl = @($controlPrincipals | Where-Object { Test-ADPostureAdcsBroadPrincipal -Principal ([string]$_) })
        $authEku = Test-ADPostureAdcsAuthenticationEku -ExtendedKeyUsage @($template.ExtendedKeyUsage)
        $agentEku = Test-ADPostureAdcsEnrollmentAgentEku -ExtendedKeyUsage @($template.ExtendedKeyUsage)
        $anyPurposeEku = Test-ADPostureAdcsAnyPurposeEku -ExtendedKeyUsage @($template.ExtendedKeyUsage)
        $noEku = -not @($template.ExtendedKeyUsage).Count
        $noIssuanceGate = -not $template.ManagerApprovalRequired -and [int]$template.RequiredRaSignatures -le 0
        $publishedTags = if (@($publishedCas).Count) { @('PublishedToCA') } else { @('UnpublishedTemplate') }
        $sanEnabledCas = @($publishedCas | Where-Object { $_.PSObject.Properties['AcceptsRequestSubjectAltName'] -and $_.AcceptsRequestSubjectAltName })

        if ($authEku -and @($broadEnrollment).Count) {
            foreach ($principal in $broadEnrollment) {
                $index++
                $findings.Add((New-ADPostureAdcsFinding `
                    -Index $index `
                    -Domain $Domain `
                    -FindingType 'AdcsBroadAuthenticationEnrollment' `
                    -RiskPattern 'BroadEnrollment' `
                    -RiskScore 5.2 `
                    -Template $template `
                    -Principal ([string]$principal) `
                    -EscTechnique 'ESC template enrollment exposure' `
                    -AttackPath (New-ADPostureAdcsAttackPath -Principal ([string]$principal) -Template $template -Ca ($publishedCas | Select-Object -First 1) -Technique 'Authentication-capable certificate enrollment' -Impact 'Can request certificates usable for authentication') `
                    -Reason "Certificate template '$($template.DisplayName)' allows broad enrollment for '$principal' and can issue authentication-capable certificates." `
                    -Remediation 'Restrict enrollment on authentication-capable certificate templates to the smallest approved group and document why each broad principal requires access.' `
                    -ScoreFormula 'ADCS broad enrollment score = authentication EKU + broad enrollment principal' `
                    -Tags @(@('ADCS', 'CertificateTemplate', 'AuthenticationExposure', 'BroadEnrollment') + $publishedTags)))
            }
        }

        if ($authEku -and @($broadAutoEnrollment).Count) {
            foreach ($principal in $broadAutoEnrollment) {
                $index++
                $findings.Add((New-ADPostureAdcsFinding `
                    -Index $index `
                    -Domain $Domain `
                    -FindingType 'AdcsBroadAuthenticationAutoEnrollment' `
                    -RiskPattern 'BroadAutoEnrollment' `
                    -RiskScore 7.4 `
                    -Template $template `
                    -Principal ([string]$principal) `
                    -EscTechnique 'ESC template autoenrollment exposure' `
                    -AttackPath (New-ADPostureAdcsAttackPath -Principal ([string]$principal) -Template $template -Ca ($publishedCas | Select-Object -First 1) -Technique 'Authentication-capable certificate autoenrollment' -Impact 'Can automatically receive certificates usable for authentication') `
                    -Reason "Certificate template '$($template.DisplayName)' allows broad autoenrollment for '$principal' and can automatically issue authentication-capable certificates." `
                    -Remediation 'Remove broad autoenrollment from authentication-capable templates; keep autoenrollment scoped to managed device/user populations with explicit ownership.' `
                    -ScoreFormula 'ADCS broad autoenrollment score = authentication EKU + broad autoenrollment principal' `
                    -Tags @(@('ADCS', 'CertificateTemplate', 'AuthenticationExposure', 'BroadEnrollment', 'BroadAutoEnrollment') + $publishedTags)))
            }
        }

        if ($template.EnrolleeSuppliesSubject -and $authEku -and $noIssuanceGate -and @($broadEnrollment).Count) {
            foreach ($principal in $broadEnrollment) {
                $index++
                $findings.Add((New-ADPostureAdcsFinding `
                    -Index $index `
                    -Domain $Domain `
                    -FindingType 'AdcsEsc1LikeTemplate' `
                    -RiskPattern 'ESC1-like' `
                    -RiskScore 12.0 `
                    -Template $template `
                    -Principal ([string]$principal) `
                    -EscTechnique 'ESC1' `
                    -AttackPath (New-ADPostureAdcsAttackPath -Principal ([string]$principal) -Template $template -Ca ($publishedCas | Select-Object -First 1) -Technique 'ESC1: requester supplies subject/SAN on auth-capable template' -Impact 'Potential certificate-based impersonation path') `
                    -Reason "Certificate template '$($template.DisplayName)' allows a broad principal to enroll, lets the requester supply subject/SAN data, has authentication-capable EKU, and does not require manager approval or authorized signatures." `
                    -Remediation 'Restrict enrollment to a governed group, disable enrollee-supplied subject/SAN unless explicitly required, and require issuance approval or authorized signatures for authentication-capable templates.' `
                    -ScoreFormula 'ADCS ESC1-like score = broad enrollment + subject/SAN supply + auth EKU + no issuance gate' `
                    -ScoreComponents @(
                        [pscustomobject]@{ Name = 'Enrollment scope'; Value = $principal; Weight = 3.0 },
                        [pscustomobject]@{ Name = 'Subject supply'; Value = 'Enrollee supplies subject'; Weight = 3.0 },
                        [pscustomobject]@{ Name = 'Authentication EKU'; Value = (@($template.ExtendedKeyUsage) -join ', '); Weight = 3.0 },
                        [pscustomobject]@{ Name = 'Issuance gate'; Value = 'No manager approval or RA signature'; Weight = 3.0 }
                    ) `
                    -Tags @(@('ADCS', 'CertificateTemplate', 'ESC1Like', 'AuthenticationExposure', 'BroadEnrollment', 'Tier0Exposure') + $publishedTags)))
            }
        }

        if ($anyPurposeEku -and $noIssuanceGate -and @($broadEnrollment).Count) {
            foreach ($principal in $broadEnrollment) {
                $index++
                $findings.Add((New-ADPostureAdcsFinding `
                    -Index $index `
                    -Domain $Domain `
                    -FindingType 'AdcsAnyPurposeBroadEnrollment' `
                    -RiskPattern 'AnyPurpose' `
                    -RiskScore 11.0 `
                    -Template $template `
                    -Principal ([string]$principal) `
                    -EscTechnique 'ESC2' `
                    -AttackPath (New-ADPostureAdcsAttackPath -Principal ([string]$principal) -Template $template -Ca ($publishedCas | Select-Object -First 1) -Technique 'ESC2: Any Purpose EKU with broad enrollment' -Impact 'Certificate can be valid for broad application purposes including authentication abuse paths') `
                    -Reason "Certificate template '$($template.DisplayName)' has Any Purpose EKU and allows broad enrollment for '$principal' without issuance approval." `
                    -Remediation 'Remove Any Purpose EKU from broadly enrollable templates or restrict enrollment and require explicit issuance approval.' `
                    -ScoreFormula 'ADCS Any Purpose score = Any Purpose EKU + broad enrollment + no issuance gate' `
                    -Tags @(@('ADCS', 'CertificateTemplate', 'AnyPurpose', 'AuthenticationExposure', 'BroadEnrollment', 'Tier0Exposure') + $publishedTags)))
            }
        }

        if ($noEku -and $noIssuanceGate -and @($broadEnrollment).Count) {
            foreach ($principal in $broadEnrollment) {
                $index++
                $findings.Add((New-ADPostureAdcsFinding `
                    -Index $index `
                    -Domain $Domain `
                    -FindingType 'AdcsNoEkuBroadEnrollment' `
                    -RiskPattern 'NoEKU' `
                    -RiskScore 11.0 `
                    -Template $template `
                    -Principal ([string]$principal) `
                    -EscTechnique 'ESC2' `
                    -AttackPath (New-ADPostureAdcsAttackPath -Principal ([string]$principal) -Template $template -Ca ($publishedCas | Select-Object -First 1) -Technique 'ESC2: no EKU restriction with broad enrollment' -Impact 'Certificate is not constrained to a narrow intended purpose') `
                    -Reason "Certificate template '$($template.DisplayName)' has no EKU restriction and allows broad enrollment for '$principal' without issuance approval." `
                    -Remediation 'Avoid broadly enrollable templates with no EKU restriction; define explicit EKUs, restrict enrollment, and require issuance approval for sensitive templates.' `
                    -ScoreFormula 'ADCS no-EKU score = no EKU restriction + broad enrollment + no issuance gate' `
                    -Tags @(@('ADCS', 'CertificateTemplate', 'NoEKU', 'AuthenticationExposure', 'BroadEnrollment', 'Tier0Exposure') + $publishedTags)))
            }
        }

        if ($agentEku -and @($broadEnrollment).Count -and $noIssuanceGate) {
            foreach ($principal in $broadEnrollment) {
                $index++
                $findings.Add((New-ADPostureAdcsFinding `
                    -Index $index `
                    -Domain $Domain `
                    -FindingType 'AdcsEnrollmentAgentBroadEnrollment' `
                    -RiskPattern 'EnrollmentAgent' `
                    -RiskScore 10.0 `
                    -Template $template `
                    -Principal ([string]$principal) `
                    -EscTechnique 'ESC3' `
                    -AttackPath (New-ADPostureAdcsAttackPath -Principal ([string]$principal) -Template $template -Ca ($publishedCas | Select-Object -First 1) -Technique 'ESC3: enrollment-agent certificate issuance' -Impact 'Can enable certificate request-on-behalf-of abuse when paired with vulnerable issuance paths') `
                    -Reason "Certificate template '$($template.DisplayName)' can issue enrollment-agent certificates to a broad principal without issuance approval." `
                    -Remediation 'Restrict enrollment-agent templates to a tightly governed CA administration group and require explicit issuance approval.' `
                    -ScoreFormula 'ADCS enrollment-agent score = broad enrollment + enrollment agent EKU + no issuance gate' `
                    -Tags @(@('ADCS', 'CertificateTemplate', 'EnrollmentAgent', 'BroadEnrollment', 'Tier0Exposure') + $publishedTags)))
            }
        }

        if ($template.ExportablePrivateKey -and $authEku -and @($broadEnrollment).Count) {
            foreach ($principal in $broadEnrollment) {
                $index++
                $findings.Add((New-ADPostureAdcsFinding `
                    -Index $index `
                    -Domain $Domain `
                    -FindingType 'AdcsExportableAuthPrivateKey' `
                    -RiskPattern 'ExportablePrivateKey' `
                    -RiskScore 6.5 `
                    -Template $template `
                    -Principal ([string]$principal) `
                    -Reason "Certificate template '$($template.DisplayName)' issues authentication-capable certificates with exportable private keys to a broad enrollment principal." `
                    -Remediation 'Disable private-key export for authentication templates unless there is a documented operational requirement, and scope enrollment to approved identities.' `
                    -ScoreFormula 'ADCS exportable-key score = auth EKU + exportable key + broad enrollment' `
                    -Tags @(@('ADCS', 'CertificateTemplate', 'ExportablePrivateKey', 'AuthenticationExposure', 'BroadEnrollment') + $publishedTags)))
            }
        }

        if (@($broadControl).Count) {
            foreach ($principal in $broadControl) {
                $index++
                $findings.Add((New-ADPostureAdcsFinding `
                    -Index $index `
                    -Domain $Domain `
                    -FindingType 'AdcsTemplateControlDelegation' `
                    -RiskPattern 'TemplateControl' `
                    -RiskScore 8.5 `
                    -Template $template `
                    -Principal ([string]$principal) `
                    -EscTechnique 'ESC4' `
                    -AttackPath (New-ADPostureAdcsAttackPath -Principal ([string]$principal) -Template $template -Ca ($publishedCas | Select-Object -First 1) -Technique 'ESC4: principal can modify template settings/security' -Impact 'Can turn template configuration into an issuance abuse path') `
                    -Reason "Certificate template '$($template.DisplayName)' has broad template-control delegation for '$principal', allowing template settings or security to be changed." `
                    -Remediation 'Remove broad write/control rights from certificate templates and delegate template administration only to a governed PKI administration group.' `
                    -ScoreFormula 'ADCS template-control score = broad control principal on certificate template' `
                    -Tags @(@('ADCS', 'CertificateTemplate', 'TemplateControl', 'BroadTrustee', 'Tier0Exposure') + $publishedTags)))
            }
        }

        if ($authEku -and $noIssuanceGate -and @($broadEnrollment).Count -and @($sanEnabledCas).Count) {
            foreach ($principal in $broadEnrollment) {
                foreach ($ca in $sanEnabledCas) {
                    $index++
                    $findings.Add((New-ADPostureAdcsFinding `
                        -Index $index `
                        -Domain $Domain `
                        -FindingType 'AdcsEsc6RequestSanChain' `
                        -RiskPattern 'ESC6' `
                        -RiskScore 12.5 `
                        -Template $template `
                        -Ca $ca `
                        -Principal ([string]$principal) `
                        -EscTechnique 'ESC6' `
                        -AttackPath (New-ADPostureAdcsAttackPath -Principal ([string]$principal) -Template $template -Ca $ca -Technique 'ESC6: CA accepts SAN supplied through request attributes' -Impact 'Potential certificate-based impersonation path through CA-level SAN acceptance') `
                        -Reason "CA '$($ca.DisplayName)' accepts request-supplied SAN attributes and publishes authentication-capable template '$($template.DisplayName)' for broad principal '$principal' without issuance approval." `
                        -Remediation 'Disable CA-level request-supplied SAN acceptance unless explicitly required, restrict affected template enrollment, and require approval or authorized signatures on authentication-capable issuance paths.' `
                        -ScoreFormula 'ADCS ESC6 chain score = CA accepts request SAN + published authentication template + broad enrollment + no issuance gate' `
                        -Tags @(@('ADCS', 'CertificateTemplate', 'EnrollmentService', 'ESC6', 'AuthenticationExposure', 'BroadEnrollment', 'Tier0Exposure') + $publishedTags)))
                }
            }
        }
    }

    foreach ($ca in @($Cas)) {
        if ($ca.PSObject.Properties['AcceptsRequestSubjectAltName'] -and $ca.AcceptsRequestSubjectAltName) {
            $index++
            $findings.Add((New-ADPostureAdcsFinding `
                -Index $index `
                -Domain $Domain `
                -FindingType 'AdcsCaAcceptsRequestSan' `
                -RiskPattern 'ESC6Config' `
                -RiskScore 9.0 `
                -Ca $ca `
                -TargetObject $ca `
                -EscTechnique 'ESC6' `
                -AttackPath (New-ADPostureAdcsAttackPath -Principal 'Any enrolled requester on affected templates' -Ca $ca -Technique 'ESC6: CA accepts request-supplied SAN attributes' -Impact 'Can amplify vulnerable templates into certificate impersonation paths') `
                -Reason "Enrollment Services CA '$($ca.DisplayName)' has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled, allowing request-supplied SAN attributes at the CA policy layer." `
                -Remediation 'Disable EDITF_ATTRIBUTESUBJECTALTNAME2 unless formally required, then review every published authentication-capable template for broad enrollment and missing issuance gates.' `
                -ScoreFormula 'ADCS ESC6 configuration score = CA policy accepts request-supplied SAN attributes' `
                -Tags @('ADCS', 'EnrollmentService', 'ESC6', 'CAConfiguration', 'AuthenticationExposure', 'Tier0Exposure')))
        }

        $broadControl = @($ca.ControlPrincipals | Where-Object { Test-ADPostureAdcsBroadPrincipal -Principal ([string]$_) })
        foreach ($principal in $broadControl) {
            $index++
            $findings.Add((New-ADPostureAdcsFinding `
                -Index $index `
                -Domain $Domain `
                -FindingType 'AdcsCaObjectControlDelegation' `
                -RiskPattern 'CAControl' `
                -RiskScore 10.5 `
                -Ca $ca `
                -TargetObject $ca `
                -Principal ([string]$principal) `
                -EscTechnique 'ESC7' `
                -AttackPath (New-ADPostureAdcsAttackPath -Principal ([string]$principal) -Ca $ca -Technique 'ESC7: principal controls Enrollment Services CA object' -Impact 'Can alter CA publication/control plane configuration') `
                -Reason "Enrollment Services CA object '$($ca.DisplayName)' has broad control delegation for '$principal'." `
                -Remediation 'Remove broad write/control rights from Enrollment Services CA objects and delegate CA administration only to governed PKI administrators.' `
                -ScoreFormula 'ADCS CA-control score = broad control principal on Enrollment Services object' `
                -Tags @('ADCS', 'EnrollmentService', 'CAControl', 'BroadTrustee', 'Tier0Exposure')))
        }
    }

    if ($NtAuth) {
        $broadControl = @($NtAuth.ControlPrincipals | Where-Object { Test-ADPostureAdcsBroadPrincipal -Principal ([string]$_) })
        foreach ($principal in $broadControl) {
            $index++
            $findings.Add((New-ADPostureAdcsFinding `
                -Index $index `
                -Domain $Domain `
                -FindingType 'AdcsNtAuthControlDelegation' `
                -RiskPattern 'NTAuthControl' `
                -RiskScore 12.0 `
                -TargetObject $NtAuth `
                -Principal ([string]$principal) `
                -EscTechnique 'ESC5' `
                -AttackPath (New-ADPostureAdcsAttackPath -Principal ([string]$principal) -Technique 'ESC5: principal controls NTAuthCertificates object' -Impact 'Can affect enterprise certificate trust') `
                -Reason "NTAuthCertificates object has broad control delegation for '$principal', which can affect enterprise certificate trust." `
                -Remediation 'Remove broad write/control rights from NTAuthCertificates and restrict enterprise PKI trust administration to governed PKI administrators.' `
                -ScoreFormula 'ADCS NTAuth-control score = broad control principal on NTAuthCertificates' `
                -Tags @('ADCS', 'NTAuth', 'CAControl', 'BroadTrustee', 'Tier0Exposure')))
        }
    }

    [pscustomobject]@{
        AdcsTemplates = @($Templates)
        AdcsCas = @($Cas)
        AdcsNtAuth = $NtAuth
        AdcsFindings = @($findings)
    }
}

function Get-ADPostureAdcsTemplateAccess {
    [CmdletBinding()]
    param([string]$DistinguishedName)

    if (-not $DistinguishedName) { return [pscustomobject]@{ EnrollmentPrincipals = @(); AutoEnrollmentPrincipals = @(); ControlPrincipals = @() } }

    try {
        $acl = Get-Acl -LiteralPath "AD:\$DistinguishedName" -ErrorAction Stop
        return ConvertFrom-ADPostureAdcsTemplateAccessRules -AccessRules @($acl.Access)
    }
    catch {
        $providerError = $_.Exception.Message
        try {
            $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$DistinguishedName")
            $rules = @($entry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]))
            return ConvertFrom-ADPostureAdcsTemplateAccessRules -AccessRules $rules
        }
        catch {
            Write-Verbose "Could not read certificate template ACL for '$DistinguishedName'. AD provider failed: $providerError. LDAP fallback failed: $($_.Exception.Message)"
        }
    }

    [pscustomobject]@{
        EnrollmentPrincipals = @()
        AutoEnrollmentPrincipals = @()
        ControlPrincipals = @()
    }
}

function Get-ADPostureAdcsPosture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Domain,
        [hashtable]$DomainParams,
        [string]$LogPath
    )

    $queryParams = if ($DomainParams) { $DomainParams } else { @{} }
    $configDn = $Domain.ConfigurationNamingContext
    if (-not $configDn) {
        try {
            $rootDse = Get-ADRootDSE @queryParams -ErrorAction Stop
            $configDn = $rootDse.ConfigurationNamingContext
        }
        catch {
            Write-Warning "Could not read AD configuration naming context for ADCS posture: $($_.Exception.Message)"
            return [pscustomobject]@{ AdcsTemplates = @(); AdcsCas = @(); AdcsNtAuth = $null; AdcsFindings = @() }
        }
    }

    $publicKeyServicesDn = "CN=Public Key Services,CN=Services,$configDn"
    $templatesDn = "CN=Certificate Templates,$publicKeyServicesDn"
    $enrollmentServicesDn = "CN=Enrollment Services,$publicKeyServicesDn"
    $ntAuthDn = "CN=NTAuthCertificates,$publicKeyServicesDn"
    Write-Host 'ADCS posture collection: reading certificate templates.'
    if ($LogPath -and (Get-Command Write-ADPostureLog -ErrorAction SilentlyContinue)) {
        Write-ADPostureLog -Message 'ADCS posture collection: reading certificate templates.' -Path $LogPath
    }

    $templates = @()
    try {
        $templates = @(Get-ADObject -SearchBase $templatesDn -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties DisplayName,pKIExtendedKeyUsage,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-Private-Key-Flag,msPKI-RA-Signature,msPKI-Template-Schema-Version @queryParams -ErrorAction Stop | ForEach-Object {
            $template = ConvertTo-ADPostureAdcsTemplateObject -InputObject $_
            $access = Get-ADPostureAdcsTemplateAccess -DistinguishedName $template.DistinguishedName
            $template | Add-Member -NotePropertyName EnrollmentPrincipals -NotePropertyValue @($access.EnrollmentPrincipals) -Force
            $template | Add-Member -NotePropertyName AutoEnrollmentPrincipals -NotePropertyValue @($access.AutoEnrollmentPrincipals) -Force
            $template | Add-Member -NotePropertyName ControlPrincipals -NotePropertyValue @($access.ControlPrincipals) -Force
            $template
        })
    }
    catch {
        Write-Warning "Could not enumerate ADCS certificate templates under '$templatesDn': $($_.Exception.Message)"
        $templates = @()
    }

    $cas = @()
    try {
        $cas = @(Get-ADObject -SearchBase $enrollmentServicesDn -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties DisplayName,dNSHostName,certificateTemplates @queryParams -ErrorAction Stop | ForEach-Object {
            $ca = ConvertTo-ADPostureAdcsCaObject -InputObject $_
            $access = Get-ADPostureAdcsObjectAccess -DistinguishedName $ca.DistinguishedName
            $configuration = Get-ADPostureAdcsCaRegistryConfiguration -Ca $ca
            $ca | Add-Member -NotePropertyName ControlPrincipals -NotePropertyValue @($access.ControlPrincipals) -Force
            $ca | Add-Member -NotePropertyName Configuration -NotePropertyValue $configuration -Force
            $ca | Add-Member -NotePropertyName AcceptsRequestSubjectAltName -NotePropertyValue ([bool]$configuration.AcceptsRequestSubjectAltName) -Force
            $ca | Add-Member -NotePropertyName RequestDisposition -NotePropertyValue $configuration.RequestDisposition -Force
            $ca | Add-Member -NotePropertyName ConfigurationSource -NotePropertyValue $configuration.Source -Force
            $ca | Add-Member -NotePropertyName ConfigurationReadError -NotePropertyValue $configuration.ReadError -Force
            $ca
        })
    }
    catch {
        Write-Verbose "Could not enumerate ADCS Enrollment Services objects under '$enrollmentServicesDn': $($_.Exception.Message)"
        $cas = @()
    }

    $ntAuth = $null
    try {
        $ntAuthObject = Get-ADObject -Identity $ntAuthDn -Properties cACertificate @queryParams -ErrorAction Stop
        $ntAuth = ConvertTo-ADPostureAdcsNtAuthObject -InputObject $ntAuthObject
        $access = Get-ADPostureAdcsObjectAccess -DistinguishedName $ntAuth.DistinguishedName
        $ntAuth | Add-Member -NotePropertyName ControlPrincipals -NotePropertyValue @($access.ControlPrincipals) -Force
    }
    catch {
        Write-Verbose "Could not read ADCS NTAuthCertificates object '$ntAuthDn': $($_.Exception.Message)"
        $ntAuth = $null
    }

    $message = "ADCS posture collection complete: $(@($templates).Count) certificate templates, $(@($cas).Count) enrollment services."
    Write-Host $message
    if ($LogPath -and (Get-Command Write-ADPostureLog -ErrorAction SilentlyContinue)) {
        Write-ADPostureLog -Message $message -Path $LogPath
    }

    ConvertTo-ADPostureAdcsRiskModel -Domain $Domain.DNSRoot -Templates @($templates) -Cas @($cas) -NtAuth $ntAuth
}

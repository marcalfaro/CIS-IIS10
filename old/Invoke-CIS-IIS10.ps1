<#
.SYNOPSIS
    CIS Microsoft IIS 10 Benchmark v1.2.1 structured audit evidence collector.

.DESCRIPTION
    This script returns structured PSCustomObject rows only. It does not generate HTML and does not write host output. The wrapper script runs this script remotely 
    and generates the combined HTML report.

    Status values:
      Pass, Fail, ManualReview, NotApplicable, Error

    This script follows the CIS IIS 10 Benchmark v1.2.1 audit/remediation command style where PowerShell commands are provided by CIS. Manual CIS controls are
    returned as Pass/Fail where the CIS PDF provides a clear PowerShell-verifiable value; otherwise returned as ManualReview when human judgement is required.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ServerName = $env:COMPUTERNAME
$script:Results    = New-Object System.Collections.Generic.List[object]

function Add-CisResult {
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Automated','Manual')][string]$AuditType,
        [Parameter(Mandatory)][ValidateSet('Pass','Fail','ManualReview','NotApplicable','Error')][string]$Status,
        [string]$Scope = 'Server',
        [string]$Evidence = '',
        [string]$Expected = '',
        [string]$Remediation = '',
        [string]$CisAuditCommand = '',
        [string]$CisRemediationCommand = ''
    )

    $script:Results.Add([pscustomobject]@{
        Server                = $script:ServerName
        ControlId             = $ControlId
        Level                 = $Level
        AuditType             = $AuditType
        Status                = $Status
        Scope                 = $Scope
        Title                 = $Title
        Evidence              = $Evidence
        Expected              = $Expected
        Remediation           = $Remediation
        CisAuditCommand       = $CisAuditCommand
        CisRemediationCommand = $CisRemediationCommand
    }) | Out-Null
}

function Invoke-CisCheck {
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Automated','Manual')][string]$AuditType,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    try {
        & $ScriptBlock
    }
    catch {
        Add-CisResult `
            -ControlId $ControlId `
            -Level $Level `
            -Title $Title `
            -AuditType $AuditType `
            -Status Error `
            -Evidence $_.Exception.Message `
            -Expected 'The check should complete successfully.' `
            -Remediation 'Review permissions, IIS feature availability, and the exact CIS command for this control.'
    }
}

function Get-CisWebProperty {
    param(
        [Parameter(Mandatory)][string]$PSPath,
        [Parameter(Mandatory)][string]$Filter,
        [Parameter(Mandatory)][string]$Name,
        [string]$Location
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Location)) {
            return (Get-WebConfigurationProperty -PSPath $PSPath -Filter $Filter -Name $Name -ErrorAction Stop).Value
        }

        return (Get-WebConfigurationProperty -PSPath $PSPath -Location $Location -Filter $Filter -Name $Name -ErrorAction Stop).Value
    }
    catch {
        return $null
    }
}

function Get-CisWebConfiguration {
    param(
        [Parameter(Mandatory)][string]$Filter,
        [string]$PSPath = 'MACHINE/WEBROOT/APPHOST',
        [switch]$Recurse
    )

    try {
        if ($Recurse) {
            return @(Get-WebConfiguration -PSPath $PSPath -Filter $Filter -Recurse -ErrorAction Stop)
        }

        return @(Get-WebConfiguration -PSPath $PSPath -Filter $Filter -ErrorAction Stop)
    }
    catch {
        return @()
    }
}

function Get-CisConfigValue {
    param(
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return ''
    }

    $valueProperty = $InputObject.PSObject.Properties['Value']

    if ($null -ne $valueProperty) {
        return [string]$valueProperty.Value
    }

    return [string]$InputObject
}

function Get-ExpandedPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $Path
    }

    return [Environment]::ExpandEnvironmentVariables($Path)
}

function Get-DriveRootSafe {
    param([string]$Path)

    try {
        return [System.IO.Path]::GetPathRoot((Get-ExpandedPath -Path $Path))
    }
    catch {
        return $null
    }
}

function Get-SystemDriveRoot {
    return (Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))).Root
}

function Get-RegistryDword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

function Test-WindowsFeatureInstalled {
    param([Parameter(Mandatory)][string]$Name)

    try {
        $feature = Get-WindowsFeature -Name $Name -ErrorAction Stop
        return [bool]$feature.Installed
    }
    catch {
        return $null
    }
}

function Test-SchannelProtocolDisabled {
    param([Parameter(Mandatory)][string]$Protocol)

    $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"
    $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client"

    $serverEnabled           = Get-RegistryDword -Path $serverPath -Name 'Enabled'
    $serverDisabledByDefault = Get-RegistryDword -Path $serverPath -Name 'DisabledByDefault'
    $clientEnabled           = Get-RegistryDword -Path $clientPath -Name 'Enabled'
    $clientDisabledByDefault = Get-RegistryDword -Path $clientPath -Name 'DisabledByDefault'

    [pscustomobject]@{
        IsCompliant = ($serverEnabled -eq 0 -and $serverDisabledByDefault -eq 1 -and $clientEnabled -eq 0 -and $clientDisabledByDefault -eq 1)
        Evidence    = "Server Enabled=$serverEnabled; Server DisabledByDefault=$serverDisabledByDefault; Client Enabled=$clientEnabled; Client DisabledByDefault=$clientDisabledByDefault"
    }
}

function Test-SchannelProtocolEnabled {
    param([Parameter(Mandatory)][string]$Protocol)

    $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"

    $serverEnabled           = Get-RegistryDword -Path $serverPath -Name 'Enabled'
    $serverDisabledByDefault = Get-RegistryDword -Path $serverPath -Name 'DisabledByDefault'

    [pscustomobject]@{
        IsCompliant = ($serverEnabled -eq 1 -and $serverDisabledByDefault -eq 0)
        Evidence    = "Server Enabled=$serverEnabled; Server DisabledByDefault=$serverDisabledByDefault"
    }
}

function Test-CipherRegistryValue {
    param(
        [Parameter(Mandatory)][string[]]$CipherNames,
        [Parameter(Mandatory)][int]$ExpectedEnabledValue
    )

    $evidenceParts = New-Object System.Collections.Generic.List[string]
    $isCompliant = $true

    foreach ($cipherName in $CipherNames) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipherName"
        $enabled = Get-RegistryDword -Path $path -Name 'Enabled'
        $evidenceParts.Add("$cipherName Enabled=$enabled") | Out-Null

        if ($enabled -ne $ExpectedEnabledValue) {
            $isCompliant = $false
        }
    }

    [pscustomobject]@{
        IsCompliant = $isCompliant
        Evidence    = ($evidenceParts -join '; ')
    }
}

# -----------------------------------------------------------------------------
# Prerequisites
# -----------------------------------------------------------------------------
try {
    Import-Module WebAdministration -ErrorAction Stop
}
catch {
    Add-CisResult -ControlId 'Prerequisite' -Level '' -Title 'WebAdministration module is available' -AuditType Automated -Status Error -Evidence $_.Exception.Message -Expected 'WebAdministration module must load.' -Remediation 'Install IIS Management Scripts and Tools.'
    $script:Results
    return
}

try {
    $script:Sites    = @(Get-Website -ErrorAction Stop)
    $script:AppPools = @(Get-ChildItem -Path IIS:\AppPools -ErrorAction Stop)
}
catch {
    Add-CisResult -ControlId 'Prerequisite' -Level '' -Title 'IIS configuration is readable' -AuditType Automated -Status Error -Evidence $_.Exception.Message -Expected 'IIS provider must be readable.' -Remediation 'Run as administrator on an IIS server with IIS management tools installed.'
    $script:Results
    return
}

# -----------------------------------------------------------------------------
# 1 Basic Configurations
# -----------------------------------------------------------------------------
Invoke-CisCheck -ControlId '1.1' -Level 'L1' -AuditType Manual -Title "Ensure 'Web content' is on non-system partition" -ScriptBlock {
    $auditCommand = 'Get-Website | Format-List Name, PhysicalPath'
    $systemRoot = Get-SystemDriveRoot

    if ($script:Sites.Count -eq 0) {
        Add-CisResult -ControlId '1.1' -Level 'L1' -Title "Ensure 'Web content' is on non-system partition" -AuditType Manual -Status NotApplicable -Evidence 'No IIS websites found.' -Expected 'Web content should not be mapped to the system drive.' -CisAuditCommand $auditCommand
        return
    }

    foreach ($site in $script:Sites) {
        $root = Get-DriveRootSafe -Path $site.PhysicalPath
        $status = if ($root -and $root -ne $systemRoot) { 'Pass' } else { 'Fail' }

        Add-CisResult -ControlId '1.1' -Level 'L1' -Title "Ensure 'Web content' is on non-system partition" -AuditType Manual -Status $status -Scope "Site: $($site.Name)" -Evidence "PhysicalPath=$($site.PhysicalPath); ResolvedRoot=$root; SystemDrive=$systemRoot" -Expected 'No virtual directories or website content mapped to the system drive unless formally accepted.' -Remediation 'Move web content to a dedicated non-system drive, for example D:\webroot, and update IIS mappings.' -CisAuditCommand $auditCommand
    }
}

Invoke-CisCheck -ControlId '1.2' -Level 'L1' -AuditType Automated -Title "Ensure 'Host headers' are on all sites" -ScriptBlock {
    $auditCommand = 'Get-WebBinding -Port * | Format-List bindingInformation'
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name='<website name>']/bindings/binding[@protocol='http' and @bindingInformation='*:80:']" -name 'bindingInformation' -value '*:80:<host header value>'
'@
    $bindings = @(Get-WebBinding -Port * -ErrorAction Stop | Where-Object { $_.protocol -in @('http','https') })

    if ($bindings.Count -eq 0) {
        Add-CisResult -ControlId '1.2' -Level 'L1' -Title "Ensure 'Host headers' are on all sites" -AuditType Automated -Status NotApplicable -Evidence 'No HTTP/HTTPS bindings found.' -Expected 'All HTTP/HTTPS bindings should include a host name.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($binding in $bindings) {
        $parts = $binding.bindingInformation -split ':', 3
        $bindingHostName = if ($parts.Count -ge 3) { $parts[2] } else { '' }
        $status = if ([string]::IsNullOrWhiteSpace($bindingHostName)) { 'Fail' } else { 'Pass' }

        Add-CisResult -ControlId '1.2' -Level 'L1' -Title "Ensure 'Host headers' are on all sites" -AuditType Automated -Status $status -Scope "Binding: $($binding.ItemXPath)" -Evidence "Protocol=$($binding.protocol); BindingInformation=$($binding.bindingInformation); HostName=$bindingHostName" -Expected 'The IP:port:host binding triplet should contain a host name.' -Remediation 'Configure a host header for each HTTP/HTTPS binding.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '1.3' -Level 'L1' -AuditType Automated -Title "Ensure 'Directory browsing' is set to Disabled" -ScriptBlock {
    $auditCommand = "Get-WebConfigurationProperty -Filter system.webserver/directorybrowse -PSPath iis:\ -Name Enabled | Select-Object Value"
    $remediationCommand = "Set-WebConfigurationProperty -Filter system.webserver/directorybrowse -PSPath iis:\ -Name Enabled -Value False"
    $value = Get-CisWebProperty -PSPath 'IIS:\' -Filter 'system.webServer/directoryBrowse' -Name 'enabled'
    $status = if ($value -eq $false) { 'Pass' } else { 'Fail' }

    Add-CisResult -ControlId '1.3' -Level 'L1' -Title "Ensure 'Directory browsing' is set to Disabled" -AuditType Automated -Status $status -Evidence "directoryBrowse.enabled=$value" -Expected 'False' -Remediation 'Disable Directory Browsing at server level.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '1.4' -Level 'L1' -AuditType Automated -Title "Ensure 'application pool identity' is configured for all application pools" -ScriptBlock {
    $auditCommand = "Get-ChildItem -Path IIS:\AppPools\ | Select-Object name, state, @{e={`$_.processModel.identityType};l='identityType'}"
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/applicationPools/add[@name='<apppool name>']/processModel" -name 'identityType' -value 'ApplicationPoolIdentity'
'@

    foreach ($pool in $script:AppPools) {
        $identityType = [string]$pool.processModel.identityType
        $status = if ($identityType -eq 'ApplicationPoolIdentity') { 'Pass' } else { 'Fail' }

        Add-CisResult -ControlId '1.4' -Level 'L1' -Title "Ensure 'application pool identity' is configured for all application pools" -AuditType Automated -Status $status -Scope "AppPool: $($pool.Name)" -Evidence "identityType=$identityType" -Expected 'ApplicationPoolIdentity or a documented unique least-privilege identity.' -Remediation 'Set each application pool identity to ApplicationPoolIdentity unless a documented service account is required.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '1.5' -Level 'L1' -AuditType Automated -Title "Ensure 'unique application pools' is set for sites" -ScriptBlock {
    $auditCommand = 'Get-Website | Select-Object Name, applicationPool'
    $remediationCommand = "Set-ItemProperty -Path 'IIS:\Sites\<website name>' -Name applicationPool -Value <apppool name>"
    $groups = @($script:Sites | Group-Object -Property applicationPool)

    foreach ($group in $groups) {
        $siteNames = @($group.Group | ForEach-Object { $_.Name })
        $status = if ($group.Count -eq 1) { 'Pass' } else { 'Fail' }

        Add-CisResult -ControlId '1.5' -Level 'L1' -Title "Ensure 'unique application pools' is set for sites" -AuditType Automated -Status $status -Scope "AppPool: $($group.Name)" -Evidence "Sites=$($siteNames -join ', ')" -Expected 'Each site should use a unique, dedicated application pool.' -Remediation 'Create and assign a unique application pool for each site.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '1.6' -Level 'L1' -AuditType Automated -Title "Ensure 'application pool identity' is configured for anonymous user identity" -ScriptBlock {
    $auditCommand = "Get-WebConfiguration system.webServer/security/authentication/anonymousAuthentication -Recurse | where {`$_.enabled -eq `$true} | format-list location"
    $remediationCommand = "Set-ItemProperty -Path IIS:\AppPools\<apppool name> -Name passAnonymousToken -Value True"
    $anonymousConfigs = @(Get-WebConfiguration 'system.webServer/security/authentication/anonymousAuthentication' -Recurse -ErrorAction Stop | Where-Object { $_.enabled -eq $true })

    if ($anonymousConfigs.Count -eq 0) {
        Add-CisResult -ControlId '1.6' -Level 'L1' -Title "Ensure 'application pool identity' is configured for anonymous user identity" -AuditType Automated -Status NotApplicable -Evidence 'No enabled anonymousAuthentication entries found.' -Expected 'Anonymous authentication userName should be blank when enabled.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($config in $anonymousConfigs) {
        $userName = [string]$config.userName
        $status = if ([string]::IsNullOrEmpty($userName)) { 'Pass' } else { 'Fail' }

        Add-CisResult -ControlId '1.6' -Level 'L1' -Title "Ensure 'application pool identity' is configured for anonymous user identity" -AuditType Automated -Status $status -Scope "Location: $($config.location)" -Evidence "enabled=$($config.enabled); userName=$userName" -Expected 'anonymousAuthentication userName should be blank.' -Remediation 'Set Anonymous Authentication to use Application Pool Identity.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '1.7' -Level 'L1' -AuditType Automated -Title "Ensure 'WebDav' feature is disabled" -ScriptBlock {
    $auditCommand = 'Install-WindowsFeature Web-DAV-Publishing; verify Install State is Available'
    $remediationCommand = 'Uninstall-WindowsFeature Web-DAV-Publishing'
    $installed = Test-WindowsFeatureInstalled -Name 'Web-DAV-Publishing'
    $status = if ($installed -eq $false) { 'Pass' } elseif ($installed -eq $true) { 'Fail' } else { 'Error' }

    Add-CisResult -ControlId '1.7' -Level 'L1' -Title "Ensure 'WebDav' feature is disabled" -AuditType Automated -Status $status -Evidence "Web-DAV-Publishing installed=$installed" -Expected 'Web-DAV-Publishing should not be installed.' -Remediation 'Uninstall WebDAV Publishing unless formally required.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

# -----------------------------------------------------------------------------
# 2 Configure Authentication and Authorization
# -----------------------------------------------------------------------------
Invoke-CisCheck -ControlId '2.1' -Level 'L1' -AuditType Manual -Title "Ensure 'global authorization rule' is set to restrict access" -ScriptBlock {
    $auditCommand = "Get-WebConfiguration -pspath 'IIS:\' -filter 'system.webServer/security/authorization'"
    $remediationCommand = @'
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/authorization" -name '.' -AtElement @{users='*';roles='';verbs=''}
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/authorization" -name '.' -value @{accessType='Allow';roles='Administrators'}
'@
    $authorizationSection = Get-WebConfiguration -PSPath 'IIS:\' -Filter 'system.webServer/security/authorization' -ErrorAction Stop
    $rules = @($authorizationSection.Collection)

    $unrestrictedAllowRules = @(
        $rules | Where-Object {
            [string]$_.accessType -eq 'Allow' -and
            [string]$_.users -eq '*' -and
            [string]$_.roles -eq ''
        }
    )

    $administratorAllowRules = @(
        $rules | Where-Object {
            [string]$_.accessType -eq 'Allow' -and
            [string]$_.roles -match '(^|[,;\s])Administrators([,;\s]|$)'
        }
    )

    $status = if ($unrestrictedAllowRules.Count -eq 0 -and $administratorAllowRules.Count -gt 0) { 'Pass' } else { 'Fail' }

    Add-CisResult -ControlId '2.1' -Level 'L1' -Title "Ensure 'global authorization rule' is set to restrict access" -AuditType Manual -Status $status -Evidence "Authorization rules=$($rules.Count); unrestricted Allow All Users rules=$($unrestrictedAllowRules.Count); Administrators Allow rules=$($administratorAllowRules.Count)." -Expected 'No unrestricted Allow All Users rule at global scope, and an approved Allow rule such as Administrators must exist.' -Remediation 'Remove the Allow All Users rule and add approved Allow rules such as Administrators, adjusted for your environment.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '2.2' -Level 'L1' -AuditType Manual -Title 'Ensure access to sensitive site features is restricted to authenticated principals only' -ScriptBlock {
    $auditCommand = "Get-WebConfiguration system.webServer/security/authentication/* -Recurse | Where-Object {`$_.enabled -eq `$true} | Format-Table"
    $remediationCommand = "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location '<website location>' -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -value 'False'; Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location '<website location>' -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -value 'True'"
    $enabledAuthentication = @(Get-WebConfiguration 'system.webServer/security/authentication/*' -Recurse -ErrorAction Stop | Where-Object { $_.enabled -eq $true })

    Add-CisResult -ControlId '2.2' -Level 'L1' -Title 'Ensure access to sensitive site features is restricted to authenticated principals only' -AuditType Manual -Status ManualReview -Evidence "Enabled authentication entries=$($enabledAuthentication.Count). Determine which locations contain sensitive content and confirm anonymous access is not used for those locations." -Expected 'Sensitive site features should require authenticated access.' -Remediation 'Disable anonymous authentication and enable an approved authentication mechanism for sensitive locations.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '2.3' -Level 'L1' -AuditType Automated -Title "Ensure 'forms authentication' require SSL" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms' -name 'requireSSL' | Format-Table Name, Value
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms' -name 'requireSSL' -value 'True'
'@

    if ($script:Sites.Count -eq 0) {
        Add-CisResult -ControlId '2.3' -Level 'L1' -Title "Ensure 'forms authentication' require SSL" -AuditType Automated -Status NotApplicable -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' -Expected 'For each website/application using Forms Authentication, requireSSL should be True.' -Remediation 'No action required unless IIS websites/applications exist.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($site in $script:Sites) {
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($site.Name)"
        $requireSsl = Get-CisWebProperty -PSPath $sitePath -Filter 'system.web/authentication/forms' -Name 'requireSSL'
        $status = if ($requireSsl -eq $true) { 'Pass' } else { 'Fail' }
        Add-CisResult -ControlId '2.3' -Level 'L1' -Title "Ensure 'forms authentication' require SSL" -AuditType Automated -Status $status -Scope "Site: $($site.Name)" -Evidence "PSPath=$sitePath; forms.requireSSL=$requireSsl" -Expected 'True' -Remediation 'Set forms authentication requireSSL to True for each affected website/application.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '2.4' -Level 'L2' -AuditType Automated -Title "Ensure 'forms authentication' is set to use cookies" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms' -Recurse -name 'cookieless'
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms' -name 'cookieless' -value 'UseCookies'
'@

    if ($script:Sites.Count -eq 0) {
        Add-CisResult -ControlId '2.4' -Level 'L2' -Title "Ensure 'forms authentication' is set to use cookies" -AuditType Automated -Status NotApplicable -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' -Expected 'For each website/application using Forms Authentication, cookieless should be UseCookies.' -Remediation 'No action required unless IIS websites/applications exist.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($site in $script:Sites) {
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($site.Name)"
        $cookieless = Get-CisWebProperty -PSPath $sitePath -Filter 'system.web/authentication/forms' -Name 'cookieless'
        $status = if ([string]$cookieless -eq 'UseCookies') { 'Pass' } else { 'Fail' }
        Add-CisResult -ControlId '2.4' -Level 'L2' -Title "Ensure 'forms authentication' is set to use cookies" -AuditType Automated -Status $status -Scope "Site: $($site.Name)" -Evidence "PSPath=$sitePath; forms.cookieless=$cookieless" -Expected 'UseCookies' -Remediation 'Set Forms Authentication cookie mode to UseCookies for each affected website/application.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '2.5' -Level 'L1' -AuditType Automated -Title "Ensure 'cookie protection mode' is configured for forms authentication" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms' -name 'protection'
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms' -name 'protection' -value 'All'
'@

    if ($script:Sites.Count -eq 0) {
        Add-CisResult -ControlId '2.5' -Level 'L1' -Title "Ensure 'cookie protection mode' is configured for forms authentication" -AuditType Automated -Status NotApplicable -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' -Expected 'For each website/application using Forms Authentication, protection should be All.' -Remediation 'No action required unless IIS websites/applications exist.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($site in $script:Sites) {
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($site.Name)"
        $protection = Get-CisWebProperty -PSPath $sitePath -Filter 'system.web/authentication/forms' -Name 'protection'
        $status = if ([string]$protection -eq 'All') { 'Pass' } else { 'Fail' }
        Add-CisResult -ControlId '2.5' -Level 'L1' -Title "Ensure 'cookie protection mode' is configured for forms authentication" -AuditType Automated -Status $status -Scope "Site: $($site.Name)" -Evidence "PSPath=$sitePath; forms.protection=$protection" -Expected 'All' -Remediation 'Set Forms Authentication cookie protection to All for each affected website/application.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '2.6' -Level 'L1' -AuditType Automated -Title "Ensure transport layer security for 'basic authentication' is configured" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location '<website name>' -filter 'system.webServer/security/access' -name 'sslFlags'
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location '<website name>' -filter 'system.webServer/security/access' -name 'sslFlags' -value 'Ssl'
'@

    if ($script:Sites.Count -eq 0) {
        Add-CisResult -ControlId '2.6' -Level 'L1' -Title "Ensure transport layer security for 'basic authentication' is configured" -AuditType Automated -Status NotApplicable -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' -Expected 'For each website/application using Basic Authentication, SSL should be required.' -Remediation 'No action required unless IIS websites/applications exist.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($site in $script:Sites) {
        $basicEnabled = Get-CisWebProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter 'system.webServer/security/authentication/basicAuthentication' -Name 'enabled'
        $sslFlags = Get-CisWebProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $site.Name -Filter 'system.webServer/security/access' -Name 'sslFlags'

        if ($basicEnabled -ne $true) {
            $status = 'NotApplicable'
            $expected = 'Basic Authentication is not enabled.'
        }
        else {
            $status = if ([string]$sslFlags -match 'Ssl') { 'Pass' } else { 'Fail' }
            $expected = 'If Basic Authentication is enabled, sslFlags should require Ssl.'
        }

        Add-CisResult -ControlId '2.6' -Level 'L1' -Title "Ensure transport layer security for 'basic authentication' is configured" -AuditType Automated -Status $status -Scope "Site: $($site.Name)" -Evidence "Location=$($site.Name); basicAuthentication.enabled=$basicEnabled; sslFlags=$sslFlags" -Expected $expected -Remediation 'Require SSL for sites/applications using Basic Authentication.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '2.7' -Level 'L1' -AuditType Automated -Title "Ensure 'passwordFormat' is not set to clear" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms/credentials' -name 'passwordFormat'
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms/credentials' -name 'passwordFormat' -value 'SHA1'
'@

    if ($script:Sites.Count -eq 0) {
        Add-CisResult -ControlId '2.7' -Level 'L1' -Title "Ensure 'passwordFormat' is not set to clear" -AuditType Automated -Status NotApplicable -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' -Expected 'For each website/application using forms credentials, passwordFormat should not be Clear.' -Remediation 'No action required unless IIS websites/applications exist.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($site in $script:Sites) {
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($site.Name)"
        $credentialSection = Get-WebConfiguration -PSPath $sitePath -Filter 'system.web/authentication/forms/credentials' -ErrorAction SilentlyContinue
        $format = if ($null -ne $credentialSection) { [string]$credentialSection.passwordFormat } else { $null }
        $users = @()
        if ($null -ne $credentialSection -and $null -ne $credentialSection.Collection) {
            $users = @($credentialSection.Collection | Where-Object { $_.ElementTagName -eq 'user' })
        }

        if ($users.Count -eq 0) {
            $status = 'NotApplicable'
            $evidence = "PSPath=$sitePath; no forms credential user entries found. passwordFormat=$format"
        }
        else {
            $status = if ($format -eq 'Clear') { 'Fail' } else { 'Pass' }
            $evidence = "PSPath=$sitePath; passwordFormat=$format; credential user entries=$($users.Count)"
        }

        Add-CisResult -ControlId '2.7' -Level 'L1' -Title "Ensure 'passwordFormat' is not set to clear" -AuditType Automated -Status $status -Scope "Site: $($site.Name)" -Evidence $evidence -Expected 'When forms credential user entries exist, passwordFormat should not be Clear, e.g. SHA1.' -Remediation 'Change passwordFormat to SHA1 and replace clear text passwords with hashed values.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '2.8' -Level 'L2' -AuditType Automated -Title "Ensure 'credentials' are not stored in configuration files" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms/credentials' -name 'passwordFormat'
'@
    $remediationCommand = @'
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms/credentials' -name '.'
'@

    if ($script:Sites.Count -eq 0) {
        Add-CisResult -ControlId '2.8' -Level 'L2' -Title "Ensure 'credentials' are not stored in configuration files" -AuditType Automated -Status NotApplicable -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' -Expected 'No forms authentication credential user entries should be stored in IIS/application configuration files.' -Remediation 'No action required unless IIS websites/applications exist.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($site in $script:Sites) {
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($site.Name)"
        $credentialSection = Get-WebConfiguration -PSPath $sitePath -Filter 'system.web/authentication/forms/credentials' -ErrorAction SilentlyContinue
        $users = @()
        if ($null -ne $credentialSection -and $null -ne $credentialSection.Collection) {
            $users = @($credentialSection.Collection | Where-Object { $_.ElementTagName -eq 'user' })
        }

        if ($users.Count -eq 0) {
            $status = 'Pass'
            $evidence = "PSPath=$sitePath; no stored forms credential user entries found."
        }
        else {
            $status = 'Fail'
            $userNames = @($users | ForEach-Object { [string]$_.Attributes['name'].Value }) -join ', '
            $evidence = "PSPath=$sitePath; stored forms credential user entries=$($users.Count); users=$userNames"
        }

        Add-CisResult -ControlId '2.8' -Level 'L2' -Title "Ensure 'credentials' are not stored in configuration files" -AuditType Automated -Status $status -Scope "Site: $($site.Name)" -Evidence $evidence -Expected 'No forms authentication credential user entries should be stored in IIS/application configuration files.' -Remediation 'Remove the credentials element from the relevant application-level web.config or configuration scope.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

# -----------------------------------------------------------------------------
# 3 ASP.NET Configuration Recommendations
# -----------------------------------------------------------------------------
Invoke-CisCheck -ControlId '3.1' -Level 'L1' -AuditType Manual -Title "Ensure 'deployment method retail' is set" -ScriptBlock {
    $auditCommand = "Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter 'system.web/deployment' -name 'retail'"
    $remediationCommand = "Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter 'system.web/deployment' -name 'retail' -value 'True'"
    $retail = Get-CisWebProperty -PSPath 'MACHINE/WEBROOT' -Filter 'system.web/deployment' -Name 'retail'
    $status = if ($retail -eq $true) { 'Pass' } else { 'Fail' }

    Add-CisResult -ControlId '3.1' -Level 'L1' -Title "Ensure 'deployment method retail' is set" -AuditType Manual -Status $status -Evidence "deployment.retail=$retail" -Expected 'True' -Remediation 'Set deployment retail to True at MACHINE/WEBROOT.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '3.2' -Level 'L2' -AuditType Automated -Title "Ensure 'debug' is turned off" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/compilation" -name "debug" | Format-List Name, Value
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/compilation" -name "debug" -value "False"
'@

    if ($script:Sites.Count -eq 0) {
        Add-CisResult -ControlId '3.2' -Level 'L2' -Title "Ensure 'debug' is turned off" -AuditType Automated -Status NotApplicable -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' -Expected 'For each website/application, compilation debug should be False.' -Remediation 'No action required unless IIS websites/applications exist.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($site in $script:Sites) {
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($site.Name)"
        $debug = Get-CisWebProperty -PSPath $sitePath -Filter 'system.web/compilation' -Name 'debug'
        $status = if ($debug -eq $false) { 'Pass' } else { 'Fail' }
        Add-CisResult -ControlId '3.2' -Level 'L2' -Title "Ensure 'debug' is turned off" -AuditType Automated -Status $status -Scope "Site: $($site.Name)" -Evidence "PSPath=$sitePath; compilation.debug=$debug" -Expected 'False' -Remediation 'Set system.web/compilation debug to False for each affected website/application.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '3.3' -Level 'L2' -AuditType Automated -Title 'Ensure custom error messages are not off' -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/customErrors" -name "mode" | Format-List Name, Value
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/customErrors" -name "mode" -value "RemoteOnly"
'@

    if ($script:Sites.Count -eq 0) {
        Add-CisResult -ControlId '3.3' -Level 'L2' -Title 'Ensure custom error messages are not off' -AuditType Automated -Status NotApplicable -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' -Expected 'For each website/application, customErrors mode should not be Off.' -Remediation 'No action required unless IIS websites/applications exist.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($site in $script:Sites) {
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($site.Name)"
        $mode = Get-CisWebProperty -PSPath $sitePath -Filter 'system.web/customErrors' -Name 'mode'
        $status = if ([string]$mode -ne 'Off') { 'Pass' } else { 'Fail' }
        Add-CisResult -ControlId '3.3' -Level 'L2' -Title 'Ensure custom error messages are not off' -AuditType Automated -Status $status -Scope "Site: $($site.Name)" -Evidence "PSPath=$sitePath; customErrors.mode=$mode" -Expected 'RemoteOnly or On; not Off.' -Remediation 'Set customErrors mode to RemoteOnly or On for each affected website/application.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '3.4' -Level 'L1' -AuditType Automated -Title 'Ensure IIS HTTP detailed errors are hidden from displaying remotely' -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.webServer/httpErrors" -name "errorMode"
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.webServer/httpErrors" -name "errorMode" -value "DetailedLocalOnly"
'@

    if ($script:Sites.Count -eq 0) {
        Add-CisResult -ControlId '3.4' -Level 'L1' -Title 'Ensure IIS HTTP detailed errors are hidden from displaying remotely' -AuditType Automated -Status NotApplicable -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' -Expected 'For each website/application, errorMode should be DetailedLocalOnly or Custom.' -Remediation 'No action required unless IIS websites/applications exist.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($site in $script:Sites) {
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($site.Name)"
        $errorMode = Get-CisWebProperty -PSPath $sitePath -Filter 'system.webServer/httpErrors' -Name 'errorMode'
        $status = if (@('DetailedLocalOnly', 'Custom') -contains [string]$errorMode) { 'Pass' } else { 'Fail' }
        Add-CisResult -ControlId '3.4' -Level 'L1' -Title 'Ensure IIS HTTP detailed errors are hidden from displaying remotely' -AuditType Automated -Status $status -Scope "Site: $($site.Name)" -Evidence "PSPath=$sitePath; httpErrors.errorMode=$errorMode" -Expected 'DetailedLocalOnly or Custom' -Remediation 'Set httpErrors errorMode to DetailedLocalOnly or Custom for each affected website/application.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '3.5' -Level 'L2' -AuditType Automated -Title 'Ensure ASP.NET stack tracing is not enabled' -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/trace" -name "enabled" | Format-List Name,Value
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/trace" -name "enabled" -value "False"
'@

    if ($script:Sites.Count -eq 0) {
        Add-CisResult -ControlId '3.5' -Level 'L2' -Title 'Ensure ASP.NET stack tracing is not enabled' -AuditType Automated -Status NotApplicable -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' -Expected 'For each website/application, trace enabled should be False.' -Remediation 'No action required unless IIS websites/applications exist.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    foreach ($site in $script:Sites) {
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($site.Name)"
        $enabled = Get-CisWebProperty -PSPath $sitePath -Filter 'system.web/trace' -Name 'enabled'
        $status = if ($enabled -eq $false) { 'Pass' } else { 'Fail' }
        Add-CisResult -ControlId '3.5' -Level 'L2' -Title 'Ensure ASP.NET stack tracing is not enabled' -AuditType Automated -Status $status -Scope "Site: $($site.Name)" -Evidence "PSPath=$sitePath; trace.enabled=$enabled" -Expected 'False' -Remediation 'Set ASP.NET trace enabled to False for each affected website/application.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '3.6' -Level 'L2' -AuditType Automated -Title "Ensure 'httpcookie' mode is configured for session state" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/sessionState" -name "mode"
'@

    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter "system.web/sessionState" -name "mode" -value "StateServer"
'@

    $sites = @(Get-Website -ErrorAction SilentlyContinue)

    if ($sites.Count -eq 0) {
        Add-CisResult `
            -ControlId '3.6' `
            -Level 'L2' `
            -Title "Ensure 'httpcookie' mode is configured for session state" `
            -AuditType Automated `
            -Status 'NotApplicable' `
            -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' `
            -Expected 'For each website/application, sessionState cookieless should be UseCookies or False.' `
            -Remediation 'No action required unless IIS websites/applications exist.' `
            -CisAuditCommand $auditCommand `
            -CisRemediationCommand $remediationCommand
        return
    }

    $findings = @()

    foreach ($site in $sites) {
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($site.Name)"

        try {
            $cookieless = Get-WebConfigurationProperty `
                -pspath $sitePath `
                -filter 'system.web/sessionState' `
                -name 'cookieless' `
                -ErrorAction Stop

            $value = [string]$cookieless.Value

            if ($value -notin @('UseCookies', 'False')) {
                $findings += "Site='$($site.Name)', Path='$sitePath', cookieless='$value'"
            }
        }
        catch {
            $findings += "Site='$($site.Name)', Path='$sitePath', Error='$($_.Exception.Message)'"
        }
    }

    $status = if ($findings.Count -eq 0) { 'Pass' } else { 'Fail' }

    $evidence = if ($findings.Count -eq 0) {
        'All IIS websites have sessionState cookieless configured as UseCookies or False.'
    }
    else {
        "Non-compliant sessionState settings found: $($findings -join '; ')"
    }

    Add-CisResult `
        -ControlId '3.6' `
        -Level 'L2' `
        -Title "Ensure 'httpcookie' mode is configured for session state" `
        -AuditType Automated `
        -Status $status `
        -Evidence $evidence `
        -Expected 'sessionState cookieless should be UseCookies or False.' `
        -Remediation 'Configure sessionState cookieless to UseCookies for each affected website/application.' `
        -CisAuditCommand $auditCommand `
        -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '3.7' -Level 'L1' -AuditType Automated -Title "Ensure 'cookies' are set with HttpOnly attribute" -ScriptBlock {
    $auditCommand = 'No PowerShell audit command is provided in CIS IIS 10 Benchmark v1.2.1 for this control. Verify application web.config contains <httpCookies httpOnlyCookies="true" />.'

    $remediationCommand = @'
<configuration>
  <system.web>
    <httpCookies httpOnlyCookies="true" />
  </system.web>
</configuration>
'@

    $sites = @(Get-Website -ErrorAction SilentlyContinue)

    if ($sites.Count -eq 0) {
        Add-CisResult `
            -ControlId '3.7' `
            -Level 'L1' `
            -Title "Ensure 'cookies' are set with HttpOnly attribute" `
            -AuditType Automated `
            -Status 'NotApplicable' `
            -Evidence 'No IIS websites were found. This CIS control is website/application scoped.' `
            -Expected 'Each website/application web.config should configure <httpCookies httpOnlyCookies="true" />.' `
            -Remediation 'No action required unless IIS websites/applications exist.' `
            -CisAuditCommand $auditCommand `
            -CisRemediationCommand $remediationCommand
        return
    }

    $findings = @()

    foreach ($site in $sites) {
        $sitePath = "MACHINE/WEBROOT/APPHOST/$($site.Name)"

        try {
            $httpOnly = Get-WebConfigurationProperty `
                -PSPath $sitePath `
                -Filter 'system.web/httpCookies' `
                -Name 'httpOnlyCookies' `
                -ErrorAction Stop

            $value = [string]$httpOnly.Value

            if ($value -ne 'True') {
                $findings += "Site='$($site.Name)', Path='$sitePath', httpOnlyCookies='$value'"
            }
        }
        catch {
            $findings += "Site='$($site.Name)', Path='$sitePath', Error='$($_.Exception.Message)'"
        }
    }

    $status = if ($findings.Count -eq 0) { 'Pass' } else { 'Fail' }

    $evidence = if ($findings.Count -eq 0) {
        'All IIS websites have httpOnlyCookies configured as True.'
    }
    else {
        "Non-compliant httpCookies settings found: $($findings -join '; ')"
    }

    Add-CisResult `
        -ControlId '3.7' `
        -Level 'L1' `
        -Title "Ensure 'cookies' are set with HttpOnly attribute" `
        -AuditType Automated `
        -Status $status `
        -Evidence $evidence `
        -Expected 'Each website/application web.config should configure <httpCookies httpOnlyCookies="true" />.' `
        -Remediation 'Add <httpCookies httpOnlyCookies="true" /> inside the <system.web> section of the affected application web.config.' `
        -CisAuditCommand $auditCommand `
        -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '3.8' -Level 'L2' -AuditType Automated -Title "Ensure 'MachineKey validation method - .Net 3.5' is configured" -ScriptBlock {
    $auditCommand = @'
No PowerShell audit command is provided in CIS IIS 10 Benchmark v1.2.1 for this control.

CIS Audit Procedure:
Open IIS Manager > navigate to WEBROOT/server level > Machine Key > verify SHA1 is selected in the validation method dropdown.
'@

    $remediationCommand = @'
%systemroot%\system32\inetsrv\appcmd set config /commit:WEBROOT /section:machineKey /validation:SHA1
'@

    try {
        $validation = Get-WebConfigurationProperty `
            -PSPath 'MACHINE/WEBROOT' `
            -Filter 'system.web/machineKey' `
            -Name 'validation' `
            -ErrorAction Stop

        $value = Get-CisConfigValue -InputObject $validation
        $status = if ($value -eq 'SHA1') {
            'Pass'
        }
        else {
            'Fail'
        }

        Add-CisResult `
            -ControlId '3.8' `
            -Level 'L2' `
            -Title "Ensure 'MachineKey validation method - .Net 3.5' is configured" `
            -AuditType Automated `
            -Status $status `
            -Evidence "MACHINE/WEBROOT system.web/machineKey validation='$value'" `
            -Expected 'MachineKey validation method for .NET 3.5 should be SHA1.' `
            -Remediation 'Configure the WEBROOT machineKey validation method to SHA1.' `
            -CisAuditCommand $auditCommand `
            -CisRemediationCommand $remediationCommand
    }
    catch {
        Add-CisResult `
            -ControlId '3.8' `
            -Level 'L2' `
            -Title "Ensure 'MachineKey validation method - .Net 3.5' is configured" `
            -AuditType Automated `
            -Status 'Error' `
            -Evidence $_.Exception.Message `
            -Expected 'MachineKey validation method for .NET 3.5 should be SHA1.' `
            -Remediation 'Configure the WEBROOT machineKey validation method to SHA1.' `
            -CisAuditCommand $auditCommand `
            -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '3.9' -Level 'L1' -AuditType Automated -Title "Ensure 'MachineKey validation method - .Net 4.5' is configured" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/machineKey" -name "validation"
'@

    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/machineKey" -name "validation" -value "HMACSHA256"
'@

    try {
        $validation = Get-WebConfigurationProperty `
            -PSPath 'MACHINE/WEBROOT' `
            -Filter 'system.web/machineKey' `
            -Name 'validation' `
            -ErrorAction Stop

        $value = Get-CisConfigValue -InputObject $validation
        $status = if ($value -eq 'HMACSHA256') { 'Pass' } else { 'Fail' }

        Add-CisResult `
            -ControlId '3.9' `
            -Level 'L1' `
            -Title "Ensure 'MachineKey validation method - .Net 4.5' is configured" `
            -AuditType Automated `
            -Status $status `
            -Evidence "MACHINE/WEBROOT system.web/machineKey validation='$value'" `
            -Expected 'MachineKey validation method for .NET 4.5 should be HMACSHA256.' `
            -Remediation 'Configure MACHINE/WEBROOT system.web/machineKey validation to HMACSHA256.' `
            -CisAuditCommand $auditCommand `
            -CisRemediationCommand $remediationCommand
    }
    catch {
        Add-CisResult `
            -ControlId '3.9' `
            -Level 'L1' `
            -Title "Ensure 'MachineKey validation method - .Net 4.5' is configured" `
            -AuditType Automated `
            -Status 'Error' `
            -Evidence $_.Exception.Message `
            -Expected 'MachineKey validation method for .NET 4.5 should be HMACSHA256.' `
            -Remediation 'Configure MACHINE/WEBROOT system.web/machineKey validation to HMACSHA256.' `
            -CisAuditCommand $auditCommand `
            -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '3.10' -Level 'L1' -AuditType Automated -Title "Ensure global .NET trust level is configured" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/trust" -name "level"
'@

    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/trust" -name "level" -value "Medium"
'@

    try {
        $result = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter 'system.web/trust' -Name 'level' -ErrorAction Stop
        $value = [string]$result.Value
        $status = if ($value -in @('Medium', 'Low', 'Minimal')) { 'Pass' } else { 'Fail' }

        Add-CisResult -ControlId '3.10' -Level 'L1' -Title "Ensure global .NET trust level is configured" -AuditType Automated -Status $status -Evidence "MACHINE/WEBROOT system.web/trust level='$value'" -Expected 'Trust level should be Medium or lower.' -Remediation 'Configure global .NET trust level to Medium or lower.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
    catch {
        Add-CisResult -ControlId '3.10' -Level 'L1' -Title "Ensure global .NET trust level is configured" -AuditType Automated -Status 'Error' -Evidence $_.Exception.Message -Expected 'Trust level should be Medium or lower.' -Remediation 'Configure global .NET trust level to Medium or lower.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '3.11' -Level 'L2' -AuditType Manual -Title 'Ensure X-Powered-By Header is removed' -ScriptBlock {
    $auditCommand = '%systemroot%\system32\inetsrv\appcmd.exe list config -section:system.webServer/httpProtocol'
    $remediationCommand = @'
Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webserver/httpProtocol/customHeaders" -name '.' -AtElement @{name='X-Powered-By'}
'@
    $headers = @(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/httpProtocol/customHeaders/add' -Recurse -ErrorAction Stop | Where-Object { $_.name -eq 'X-Powered-By' })
    $status = if ($headers.Count -eq 0) { 'Pass' } else { 'Fail' }

    Add-CisResult -ControlId '3.11' -Level 'L2' -Title 'Ensure X-Powered-By Header is removed' -AuditType Manual -Status $status -Evidence "X-Powered-By custom header entries=$($headers.Count)" -Expected 'X-Powered-By header absent from IIS customHeaders configuration.' -Remediation 'Remove the X-Powered-By custom header and verify live responses.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '3.12' -Level 'L2' -AuditType Manual -Title "Ensure Server Header is removed" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath machine/webroot/apphost -filter 'system.webserver/security/requestfiltering' -name 'removeServerHeader'
'@

    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/' -filter "system.webServer/security/requestFiltering" -name "removeServerHeader" -value "True"
'@

    try {
        $result = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name 'removeServerHeader' -ErrorAction Stop
        $value = [string]$result.Value
        $status = if ($value -eq 'True') { 'Pass' } else { 'Fail' }

        Add-CisResult -ControlId '3.12' -Level 'L2' -Title "Ensure Server Header is removed" -AuditType Manual -Status $status -Evidence "removeServerHeader='$value'" -Expected 'removeServerHeader should be True.' -Remediation 'Configure requestFiltering removeServerHeader to True.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
    catch {
        Add-CisResult -ControlId '3.12' -Level 'L2' -Title "Ensure Server Header is removed" -AuditType Manual -Status 'Error' -Evidence $_.Exception.Message -Expected 'removeServerHeader should be True.' -Remediation 'Configure requestFiltering removeServerHeader to True.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

# -----------------------------------------------------------------------------
# 4 Request Filtering and Other Restriction Modules
# -----------------------------------------------------------------------------
$RequestLimitChecks = @(
    @{ Id='4.1'; Level='L2'; Type='Manual';    Title="Ensure 'maxAllowedContentLength' is configured"; Property='maxAllowedContentLength'; Expected='Organisation-approved maximum content length, such as 30000000 bytes.'; RemediationValue='30000000' },
    @{ Id='4.2'; Level='L2'; Type='Automated'; Title="Ensure 'maxURL request filter' is configured";              Property='maxUrl';                  Expected='4096 or lower unless documented.'; RemediationValue='4096' },
    @{ Id='4.3'; Level='L2'; Type='Automated'; Title="Ensure 'MaxQueryString request filter' is configured";       Property='maxQueryString';          Expected='2048 or lower unless documented.'; RemediationValue='2048' }
)

foreach ($check in $RequestLimitChecks) {
    Invoke-CisCheck -ControlId $check.Id -Level $check.Level -AuditType $check.Type -Title $check.Title -ScriptBlock {
        $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "$($check.Property)"
'@
        $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/requestLimits" -name "$($check.Property)" -value $($check.RemediationValue)
'@
        $value = Get-CisWebProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering/requestLimits' -Name $check.Property

        if ($check.Id -eq '4.1') {
            $status = if ($null -ne $value -and [int64]$value -gt 0) { 'Pass' } else { 'Fail' }
        }
        elseif ($check.Id -eq '4.2') {
            $status = if ($null -ne $value -and [int]$value -le 4096) { 'Pass' } else { 'Fail' }
        }
        else {
            $status = if ($null -ne $value -and [int]$value -le 2048) { 'Pass' } else { 'Fail' }
        }

        Add-CisResult -ControlId $check.Id -Level $check.Level -Title $check.Title -AuditType $check.Type -Status $status -Evidence "$($check.Property)=$value" -Expected $check.Expected -Remediation 'Set this request limit to the CIS/example value or an organisation-approved documented value.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '4.4' -Level 'L2' -AuditType Automated -Title "Ensure non-ASCII characters in URLs are not allowed" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'allowHighBitCharacters'
'@

    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters" -value "False"
'@

    try {
        $result = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name 'allowHighBitCharacters' -ErrorAction Stop
        $value = [string]$result.Value
        $status = if ($value -eq 'False') { 'Pass' } else { 'Fail' }

        Add-CisResult -ControlId '4.4' -Level 'L2' -Title "Ensure non-ASCII characters in URLs are not allowed" -AuditType Automated -Status $status -Evidence "allowHighBitCharacters='$value'" -Expected 'allowHighBitCharacters should be False.' -Remediation 'Set allowHighBitCharacters to False.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
    catch {
        Add-CisResult -ControlId '4.4' -Level 'L2' -Title "Ensure non-ASCII characters in URLs are not allowed" -AuditType Automated -Status 'Error' -Evidence $_.Exception.Message -Expected 'allowHighBitCharacters should be False.' -Remediation 'Set allowHighBitCharacters to False.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '4.5' -Level 'L1' -AuditType Automated -Title 'Ensure Double-Encoded requests will be rejected' -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping"
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value "False"
'@
    $value = Get-CisWebProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name 'allowDoubleEscaping'
    $status = if ($value -eq $false) { 'Pass' } else { 'Fail' }

    Add-CisResult -ControlId '4.5' -Level 'L1' -Title 'Ensure Double-Encoded requests will be rejected' -AuditType Automated -Status $status -Evidence "allowDoubleEscaping=$value" -Expected 'False' -Remediation 'Set allowDoubleEscaping to False.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '4.6' -Level 'L1' -AuditType Manual -Title "Ensure 'HTTP Trace Method' is disabled" -ScriptBlock {
    $auditCommand = @'
%systemroot%\system32\inetsrv\appcmd listconfig /section:requestfiltering
'@

    $remediationCommand = @'
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/verbs" -name "." -value @{verb='TRACE';allowed='False'}
'@

    try {
        $verbs = @(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering/verbs/add' -ErrorAction SilentlyContinue)
        $traceRule = @($verbs | Where-Object { [string]$_.verb -eq 'TRACE' })
        $deniedTraceRule = @($traceRule | Where-Object { [string]$_.allowed -eq 'False' })

        $status = if ($deniedTraceRule.Count -gt 0) { 'Pass' } else { 'Fail' }
        $evidence = if ($traceRule.Count -eq 0) {
            'No TRACE verb deny rule was found.'
        } else {
            "TRACE rule count=$($traceRule.Count); denied TRACE rule count=$($deniedTraceRule.Count)"
        }

        Add-CisResult -ControlId '4.6' -Level 'L1' -Title "Ensure 'HTTP Trace Method' is disabled" -AuditType Manual -Status $status -Evidence $evidence -Expected "A requestFiltering verb rule should exist with verb='TRACE' and allowed='False'." -Remediation 'Add a requestFiltering deny rule for TRACE.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
    catch {
        Add-CisResult -ControlId '4.6' -Level 'L1' -Title "Ensure 'HTTP Trace Method' is disabled" -AuditType Manual -Status 'Error' -Evidence $_.Exception.Message -Expected "A requestFiltering verb rule should exist with verb='TRACE' and allowed='False'." -Remediation 'Add a requestFiltering deny rule for TRACE.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '4.7' -Level 'L1' -AuditType Automated -Title "Ensure Unlisted File Extensions are not allowed" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted"
'@

    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted" -value "False"
'@

    try {
        $result = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering/fileExtensions' -Name 'allowUnlisted' -ErrorAction Stop
        $value = [string]$result.Value
        $status = if ($value -eq 'False') { 'Pass' } else { 'Fail' }

        Add-CisResult -ControlId '4.7' -Level 'L1' -Title "Ensure Unlisted File Extensions are not allowed" -AuditType Automated -Status $status -Evidence "fileExtensions allowUnlisted='$value'" -Expected 'allowUnlisted should be False.' -Remediation 'Set fileExtensions allowUnlisted to False, then explicitly allow only required extensions.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
    catch {
        Add-CisResult -ControlId '4.7' -Level 'L1' -Title "Ensure Unlisted File Extensions are not allowed" -AuditType Automated -Status 'Error' -Evidence $_.Exception.Message -Expected 'allowUnlisted should be False.' -Remediation 'Set fileExtensions allowUnlisted to False, then explicitly allow only required extensions.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '4.8' -Level 'L1' -AuditType Manual -Title 'Ensure Handler is not granted Write and Script/Execute' -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/handlers" -name "accessPolicy"
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/handlers" -name "accessPolicy" -value "Read,Script"
'@
    $accessPolicy = [string](Get-CisWebProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/handlers' -Name 'accessPolicy')
    $hasWrite = $accessPolicy -match '(^|,\s*)Write(,|$)'
    $hasScriptOrExecute = $accessPolicy -match '(^|,\s*)(Script|Execute)(,|$)'
    $status = if ($hasWrite -and $hasScriptOrExecute) { 'Fail' } else { 'Pass' }

    Add-CisResult -ControlId '4.8' -Level 'L1' -Title 'Ensure Handler is not granted Write and Script/Execute' -AuditType Manual -Status $status -Evidence "handlers.accessPolicy=$accessPolicy" -Expected 'accessPolicy must not contain Write together with Script or Execute.' -Remediation 'Set handlers accessPolicy to Read,Script or another approved value that does not combine Write with Script/Execute.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '4.9' -Level 'L1' -AuditType Automated -Title "Ensure 'notListedIsapisAllowed' is set to false" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/isapiCgiRestriction" -name "notListedIsapisAllowed"
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/isapiCgiRestriction" -name "notListedIsapisAllowed" -value "False"
'@
    $value = Get-CisWebProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/isapiCgiRestriction' -Name 'notListedIsapisAllowed'
    $status = if ($value -eq $false) { 'Pass' } else { 'Fail' }

    Add-CisResult -ControlId '4.9' -Level 'L1' -Title "Ensure 'notListedIsapisAllowed' is set to false" -AuditType Automated -Status $status -Evidence "notListedIsapisAllowed=$value" -Expected 'False' -Remediation 'Set notListedIsapisAllowed to False.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '4.10' -Level 'L1' -AuditType Automated -Title "Ensure 'notListedCgisAllowed' is set to false" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/isapiCgiRestriction" -name "notListedCgisAllowed"
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/isapiCgiRestriction" -name "notListedCgisAllowed" -value "False"
'@
    $value = Get-CisWebProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/isapiCgiRestriction' -Name 'notListedCgisAllowed'
    $status = if ($value -eq $false) { 'Pass' } else { 'Fail' }

    Add-CisResult -ControlId '4.10' -Level 'L1' -Title "Ensure 'notListedCgisAllowed' is set to false" -AuditType Automated -Status $status -Evidence "notListedCgisAllowed=$value" -Expected 'False' -Remediation 'Set notListedCgisAllowed to False.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '4.11' -Level 'L1' -AuditType Manual -Title "Ensure 'Dynamic IP Address Restrictions' is enabled" -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "enabled"
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "maxConcurrentRequests"
'@

    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "enabled" -value "True"
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "maxConcurrentRequests" -value <number of requests>
'@

    try {
        $enabled = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests' -Name 'enabled' -ErrorAction Stop
        $max = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests' -Name 'maxConcurrentRequests' -ErrorAction Stop

        $enabledValue = [string]$enabled.Value
        $maxValue = [int]$max.Value
        $status = if ($enabledValue -eq 'True' -and $maxValue -gt 0) { 'Pass' } else { 'Fail' }

        Add-CisResult -ControlId '4.11' -Level 'L1' -Title "Ensure 'Dynamic IP Address Restrictions' is enabled" -AuditType Manual -Status $status -Evidence "denyByConcurrentRequests enabled='$enabledValue'; maxConcurrentRequests='$maxValue'. Live trigger test not performed." -Expected 'denyByConcurrentRequests enabled should be True and maxConcurrentRequests should be configured.' -Remediation 'Enable Dynamic IP Restrictions and configure maxConcurrentRequests to an organisation-approved threshold.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
    catch {
        Add-CisResult -ControlId '4.11' -Level 'L1' -Title "Ensure 'Dynamic IP Address Restrictions' is enabled" -AuditType Manual -Status 'Error' -Evidence $_.Exception.Message -Expected 'denyByConcurrentRequests enabled should be True and maxConcurrentRequests should be configured.' -Remediation 'Enable Dynamic IP Restrictions and configure maxConcurrentRequests to an organisation-approved threshold.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

# -----------------------------------------------------------------------------
# 5 IIS Logging Recommendations
# -----------------------------------------------------------------------------
Invoke-CisCheck -ControlId '5.1' -Level 'L1' -AuditType Automated -Title 'Ensure Default IIS web log location is moved' -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile" -name "directory"
'@
    $directory = Get-CisWebProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/siteDefaults/logFile' -Name 'directory'
    $expanded = Get-ExpandedPath -Path $directory
    $root = Get-DriveRootSafe -Path $expanded
    $systemRoot = Get-SystemDriveRoot
    $status = if ($root -and $root -ne $systemRoot) { 'Pass' } else { 'Fail' }

    Add-CisResult -ControlId '5.1' -Level 'L1' -Title 'Ensure Default IIS web log location is moved' -AuditType Automated -Status $status -Evidence "siteDefaults.logFile.directory=$directory; resolved=$expanded; root=$root; systemRoot=$systemRoot" -Expected 'Default IIS log location should be moved away from the system drive.' -Remediation 'Move IIS web logs to a dedicated non-system drive.' -CisAuditCommand $auditCommand
}

Invoke-CisCheck -ControlId '5.2' -Level 'L1' -AuditType Automated -Title "Ensure Advanced IIS logging is enabled" -ScriptBlock {
    $auditCommand = @'
No PowerShell audit command is provided in CIS IIS 10 Benchmark v1.2.1 for this control.

CIS Audit Procedure:
Browse to the location of the Advanced Logs and verify .log files are being generated.
'@

    $remediationCommand = @'
No PowerShell remediation command is provided in CIS IIS 10 Benchmark v1.2.1 for this control.

CIS Remediation Procedure:
Open IIS Manager > select server > Logging > Select Fields > configure required fields.
'@

    Add-CisResult -ControlId '5.2' -Level 'L1' -Title "Ensure Advanced IIS logging is enabled" -AuditType Automated -Status 'ManualReview' -Evidence 'CIS does not provide a PowerShell command for this check. Verify generated .log files in the Advanced Logs location and confirm required fields are configured.' -Expected 'Advanced IIS logging should generate .log files with required fields.' -Remediation 'Configure Advanced/Enhanced Logging fields in IIS Manager according to organisational logging requirements.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '5.3' -Level 'L1' -AuditType Manual -Title "Ensure 'ETW Logging' is enabled" -ScriptBlock {
    $auditCommand = @'
No PowerShell audit command is provided in CIS IIS 10 Benchmark v1.2.1 for this control.

CIS Audit Procedure:
Using Message Analyzer, configure the query for Microsoft-Windows-IIS-Logging. Verify live logging data by accessing the website.
'@

    $remediationCommand = @'
No PowerShell remediation command is provided in CIS IIS 10 Benchmark v1.2.1 for this control.

CIS Remediation Procedure:
Open IIS Manager > select server or site > Logging > ensure Log file format is W3C > select Both log file and ETW event > Save.
'@

    Add-CisResult -ControlId '5.3' -Level 'L1' -Title "Ensure 'ETW Logging' is enabled" -AuditType Manual -Status 'ManualReview' -Evidence 'CIS requires live ETW validation using Message Analyzer or equivalent. Script did not perform a live ETW trace.' -Expected 'Live Microsoft-Windows-IIS-Logging ETW events should be visible when accessing the website.' -Remediation 'Enable Both log file and ETW event in IIS Logging and verify live ETW events.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

# -----------------------------------------------------------------------------
# 6 FTP Requests
# -----------------------------------------------------------------------------
Invoke-CisCheck -ControlId '6.1' -Level 'L1' -AuditType Manual -Title 'Ensure FTP requests are encrypted' -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl" -name "controlChannelPolicy"
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl" -name "dataChannelPolicy"
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl" -name "controlChannelPolicy" -value "SslRequire"
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl" -name "dataChannelPolicy" -value "SslRequire"
'@
    $ftpInstalled = Test-WindowsFeatureInstalled -Name 'Web-Ftp-Server'

    if ($ftpInstalled -eq $false) {
        Add-CisResult -ControlId '6.1' -Level 'L1' -Title 'Ensure FTP requests are encrypted' -AuditType Manual -Status NotApplicable -Evidence 'Web-Ftp-Server installed=False' -Expected 'If FTP is installed/used, FTP SSL should be required.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    $controlPolicy = Get-CisWebProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/siteDefaults/ftpServer/security/ssl' -Name 'controlChannelPolicy'
    $dataPolicy = Get-CisWebProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/siteDefaults/ftpServer/security/ssl' -Name 'dataChannelPolicy'
    $status = if ([string]$controlPolicy -eq 'SslRequire' -and [string]$dataPolicy -eq 'SslRequire') { 'Pass' } else { 'Fail' }

    Add-CisResult -ControlId '6.1' -Level 'L1' -Title 'Ensure FTP requests are encrypted' -AuditType Manual -Status $status -Evidence "Web-Ftp-Server installed=$ftpInstalled; controlChannelPolicy=$controlPolicy; dataChannelPolicy=$dataPolicy" -Expected 'controlChannelPolicy=SslRequire and dataChannelPolicy=SslRequire.' -Remediation 'Require SSL for FTP control/data channels or remove FTP if unused.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

Invoke-CisCheck -ControlId '6.2' -Level 'L1' -AuditType Manual -Title 'Ensure FTP Logon attempt restrictions is enabled' -ScriptBlock {
    $auditCommand = @'
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.ftpServer/security/authentication/denyByFailure" -name "enabled"
'@
    $remediationCommand = @'
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.ftpServer/security/authentication/denyByFailure" -name "enabled" -value "True"
'@
    $ftpInstalled = Test-WindowsFeatureInstalled -Name 'Web-Ftp-Server'

    if ($ftpInstalled -eq $false) {
        Add-CisResult -ControlId '6.2' -Level 'L1' -Title 'Ensure FTP Logon attempt restrictions is enabled' -AuditType Manual -Status NotApplicable -Evidence 'Web-Ftp-Server installed=False' -Expected 'If FTP is installed/used, FTP logon attempt restrictions should be enabled.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
        return
    }

    $enabled = Get-CisWebProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.ftpServer/security/authentication/denyByFailure' -Name 'enabled'
    $status = if ($enabled -eq $true) { 'Pass' } else { 'Fail' }

    Add-CisResult -ControlId '6.2' -Level 'L1' -Title 'Ensure FTP Logon attempt restrictions is enabled' -AuditType Manual -Status $status -Evidence "Web-Ftp-Server installed=$ftpInstalled; denyByFailure.enabled=$enabled" -Expected 'denyByFailure.enabled=True.' -Remediation 'Configure FTP logon attempt restrictions or remove FTP if unused.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

# -----------------------------------------------------------------------------
# 7 Transport Encryption
# -----------------------------------------------------------------------------
Invoke-CisCheck -ControlId '7.1' -Level 'L2' -AuditType Manual -Title "Ensure HSTS Header is set" -ScriptBlock {
    $auditCommand = @'
No PowerShell audit command is provided in CIS IIS 10 Benchmark v1.2.1 for this control.

CIS Audit Procedure:
IIS Manager > HTTP Response Headers > verify an entry named Strict-Transport-Security exists and its value contains max-age greater than 0.
'@

    $remediationCommand = @'
%systemroot%\system32\inetsrv\appcmd.exe set config -section:system.webServer/httpProtocol /+"customHeaders.[name='Strict-Transport-Security',value='max-age=480; preload']"
'@

    try {
        $headers = @(Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/httpProtocol/customHeaders/add' -ErrorAction SilentlyContinue)
        $hsts = @($headers | Where-Object { [string]$_.name -eq 'Strict-Transport-Security' })

        if ($hsts.Count -eq 0) {
            $status = 'ManualReview'
            $evidence = 'No server-level Strict-Transport-Security custom header was found. Check site/application-level headers manually as required by CIS.'
        }
        else {
            $values = @($hsts | ForEach-Object { [string]$_.value })
            $hasMaxAge = $false

            foreach ($value in $values) {
                if ($value -match 'max-age\s*=\s*(\d+)' -and [int]$Matches[1] -gt 0) {
                    $hasMaxAge = $true
                }
            }

            $status = if ($hasMaxAge) { 'Pass' } else { 'Fail' }
            $evidence = "Strict-Transport-Security header value(s): $($values -join '; ')"
        }

        Add-CisResult -ControlId '7.1' -Level 'L2' -Title "Ensure HSTS Header is set" -AuditType Manual -Status $status -Evidence $evidence -Expected 'Strict-Transport-Security header should exist with max-age greater than 0.' -Remediation 'Add Strict-Transport-Security header with max-age greater than 0, such as max-age=480; preload.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
    catch {
        Add-CisResult -ControlId '7.1' -Level 'L2' -Title "Ensure HSTS Header is set" -AuditType Manual -Status 'Error' -Evidence $_.Exception.Message -Expected 'Strict-Transport-Security header should exist with max-age greater than 0.' -Remediation 'Add Strict-Transport-Security header with max-age greater than 0, such as max-age=480; preload.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

$ProtocolChecks = @(
    @{ Id='7.2'; Protocol='SSL 2.0'; Expected='Disabled'; Value='0' },
    @{ Id='7.3'; Protocol='SSL 3.0'; Expected='Disabled'; Value='0' },
    @{ Id='7.4'; Protocol='TLS 1.0'; Expected='Disabled'; Value='0' },
    @{ Id='7.5'; Protocol='TLS 1.1'; Expected='Disabled'; Value='0' }
)

foreach ($protocolCheck in $ProtocolChecks) {
    Invoke-CisCheck -ControlId $protocolCheck.Id -Level 'L1' -AuditType Automated -Title "Ensure $($protocolCheck.Protocol) is Disabled" -ScriptBlock {
        $auditCommand = "Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$($protocolCheck.Protocol)\Server' -name 'Enabled'"
        $remediationCommand = "Create Server and Client protocol subkeys for $($protocolCheck.Protocol); set Enabled=0 and DisabledByDefault=1."
        $result = Test-SchannelProtocolDisabled -Protocol $protocolCheck.Protocol
        $status = if ($result.IsCompliant) { 'Pass' } else { 'Fail' }

        Add-CisResult -ControlId $protocolCheck.Id -Level 'L1' -Title "Ensure $($protocolCheck.Protocol) is Disabled" -AuditType Automated -Status $status -Evidence $result.Evidence -Expected 'Server and Client Enabled=0, DisabledByDefault=1.' -Remediation 'Set SCHANNEL protocol registry values as defined by CIS and reboot.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '7.6' -Level 'L1' -AuditType Automated -Title 'Ensure TLS 1.2 is Enabled' -ScriptBlock {
    $auditCommand = "Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled'"
    $remediationCommand = "Create TLS 1.2 Server protocol subkey; set Enabled=1 and DisabledByDefault=0."
    $result = Test-SchannelProtocolEnabled -Protocol 'TLS 1.2'
    $status = if ($result.IsCompliant) { 'Pass' } else { 'Fail' }

    Add-CisResult -ControlId '7.6' -Level 'L1' -Title 'Ensure TLS 1.2 is Enabled' -AuditType Automated -Status $status -Evidence $result.Evidence -Expected 'TLS 1.2 Server Enabled=1 and DisabledByDefault=0.' -Remediation 'Enable TLS 1.2 via SCHANNEL registry values and reboot.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

$CipherChecks = @(
    @{ Id='7.7'; Title='Ensure NULL Cipher Suites is Disabled';        Ciphers=@('NULL');                                          ExpectedValue=0 },
    @{ Id='7.8'; Title='Ensure DES Cipher Suites is Disabled';         Ciphers=@('DES 56/56');                                     ExpectedValue=0 },
    @{ Id='7.9'; Title='Ensure RC4 Cipher Suites is Disabled';         Ciphers=@('RC4 40/128','RC4 56/128','RC4 64/128','RC4 128/128'); ExpectedValue=0 },
    @{ Id='7.10'; Title='Ensure AES 128/128 Cipher Suite is Disabled'; Ciphers=@('AES 128/128');                                   ExpectedValue=0 },
    @{ Id='7.11'; Title='Ensure AES 256/256 Cipher Suite is Enabled';  Ciphers=@('AES 256/256');                                   ExpectedValue=1 }
)

foreach ($cipherCheck in $CipherChecks) {
    Invoke-CisCheck -ControlId $cipherCheck.Id -Level 'L1' -AuditType Automated -Title $cipherCheck.Title -ScriptBlock {
        $firstCipher = $cipherCheck.Ciphers[0]
        $auditCommand = "Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$firstCipher' -name 'Enabled'"
        $remediationCommand = "Create the SCHANNEL Ciphers subkey and set Enabled=$($cipherCheck.ExpectedValue) for: $($cipherCheck.Ciphers -join ', ')"
        $result = Test-CipherRegistryValue -CipherNames $cipherCheck.Ciphers -ExpectedEnabledValue $cipherCheck.ExpectedValue
        $status = if ($result.IsCompliant) { 'Pass' } else { 'Fail' }

        Add-CisResult -ControlId $cipherCheck.Id -Level 'L1' -Title $cipherCheck.Title -AuditType Automated -Status $status -Evidence $result.Evidence -Expected "Enabled registry value should be $($cipherCheck.ExpectedValue)." -Remediation 'Set the SCHANNEL cipher registry value exactly as defined by CIS and reboot.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
    }
}

Invoke-CisCheck -ControlId '7.12' -Level 'L2' -AuditType Automated -Title 'Ensure TLS Cipher Suite ordering is Configured' -ScriptBlock {
    $auditCommand = "Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions'"
    $expectedOrder = 'TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
    $remediationCommand = "New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Force | Out-Null; New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value '$expectedOrder' -PropertyType 'MultiString' -Force | Out-Null"
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
    $functions = $null

    try {
        $functions = (Get-ItemProperty -Path $path -Name 'Functions' -ErrorAction Stop).Functions
    }
    catch {
        $functions = $null
    }

    $actual = if ($functions -is [array]) { $functions -join ',' } else { [string]$functions }
    $status = if ($actual -eq $expectedOrder) { 'Pass' } elseif ([string]::IsNullOrWhiteSpace($actual)) { 'Fail' } else { 'Fail' }

    Add-CisResult -ControlId '7.12' -Level 'L2' -Title 'Ensure TLS Cipher Suite ordering is Configured' -AuditType Automated -Status $status -Evidence "Functions=$actual" -Expected $expectedOrder -Remediation 'Configure the TLS cipher suite order using the CIS registry policy value.' -CisAuditCommand $auditCommand -CisRemediationCommand $remediationCommand
}

$script:Results

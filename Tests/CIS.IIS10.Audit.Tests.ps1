param([string]$ProjectRoot)

function Get-FirstExistingFile {
    param(
        [Parameter(Mandatory)] [string]$Root,
        [Parameter(Mandatory)] [string[]]$Names
    )
    foreach ($name in $Names) {
        $path = Join-Path $Root $name
        if (Test-Path $path) { return $path }
    }
    throw "Could not find any of these files under '$Root': $($Names -join ', ')"
}

Describe 'CIS IIS 10 audit script - contract tests' {
    BeforeAll {
        $script:AuditScript = Get-FirstExistingFile -Root $ProjectRoot -Names @(
            'Invoke-CIS-IIS10.ps1',
            'Invoke-CIS-IIS10-v8.ps1',
            'Invoke-CIS-IIS10-v8(1).ps1'
        )

        $script:AuditText = Get-Content -Path $script:AuditScript -Raw
        $script:ParseErrors = $null
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:AuditScript,
            [ref]$null,
            [ref]$script:ParseErrors
        )

        $script:ExpectedControls = @(
            '1.1','1.2','1.3','1.4','1.5','1.6','1.7',
            '2.1','2.2','2.3','2.4','2.5','2.6','2.7','2.8',
            '3.1','3.2','3.3','3.4','3.5','3.6','3.7','3.8','3.9','3.10','3.11','3.12',
            '4.1','4.2','4.3','4.4','4.5','4.6','4.7','4.8','4.9','4.10','4.11',
            '5.1','5.2','5.3',
            '6.1','6.2',
            '7.1','7.2','7.3','7.4','7.5','7.6','7.7','7.8','7.9','7.10','7.11','7.12'
        )

        $script:RequiredProperties = @(
            'Server','ControlId','Level','AuditType','Status','Scope','Title','Evidence','Expected','Remediation','CisAuditCommand','CisRemediationCommand'
        )

        $script:ValidStatuses = @('Pass','Fail','ManualReview','NotApplicable','Error')
    }

    It 'has no PowerShell parser errors' {
        $script:ParseErrors | Should -BeNullOrEmpty
    }

    It 'contains required helper functions' {
        $script:AuditText | Should -Match 'function\s+Add-CisResult'
        $script:AuditText | Should -Match 'function\s+Invoke-CisCheck'
        $script:AuditText | Should -Match 'function\s+Get-CisConfigValue'
    }

    It 'contains one Invoke-CisCheck block for every CIS IIS 10 v1.2.1 control' {
        foreach ($control in $script:ExpectedControls) {
            $pattern = "Invoke-CisCheck\s+-ControlId\s+'$([regex]::Escape($control))'"
            $script:AuditText | Should -Match $pattern -Because "Control $control should be audited or explicitly reported as ManualReview/NotApplicable"
        }
    }

    It 'does not use Write-Host for audit results' {
        $script:AuditText | Should -Not -Match 'Write-Host' -Because 'The audit script should return structured objects, not console-only text.'
    }

    It 'uses only allowed status values in source literals' {
        $statusLiterals = [regex]::Matches($script:AuditText, "Status\s+['\"](?<status>[^'\"]+)['\"]") |
            ForEach-Object { $_.Groups['status'].Value } |
            Select-Object -Unique

        foreach ($status in $statusLiterals) {
            $status | Should -BeIn $script:ValidStatuses
        }
    }

    It 'emits all required report properties through Add-CisResult' {
        foreach ($property in $script:RequiredProperties) {
            $script:AuditText | Should -Match ([regex]::Escape($property))
        }
    }

    It 'keeps known CIS Manual controls as AuditType Manual' {
        $manualControls = @('1.1','2.1','2.2','3.1','3.11','3.12','4.1','4.6','4.8','4.11','5.3','6.1','6.2','7.1')

        foreach ($control in $manualControls) {
            $pattern = "Invoke-CisCheck\s+-ControlId\s+'$([regex]::Escape($control))'\s+-Level\s+'[^']+'\s+-AuditType\s+Manual"
            $script:AuditText | Should -Match $pattern -Because "CIS marks control $control as Manual."
        }
    }
}

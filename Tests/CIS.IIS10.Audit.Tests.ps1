BeforeAll {
    function Get-FirstExistingFile {
        param(
            [Parameter(Mandatory)]
            [string[]]$CandidatePaths
        )

        foreach ($candidatePath in $CandidatePaths) {
            if (Test-Path -LiteralPath $candidatePath) {
                return (Resolve-Path -LiteralPath $candidatePath).Path
            }
        }

        throw "None of the expected files were found: $($CandidatePaths -join ', ')"
    }

    function Get-CisControlIdsFromAuditText {
        param(
            [Parameter(Mandatory)]
            [string]$Text
        )

        $ids = New-Object System.Collections.Generic.HashSet[string]

        # Literal direct calls:
        # Invoke-CisCheck -ControlId '1.1'
        foreach ($match in [regex]::Matches($Text, "ControlId\s+['""](?<id>[^'""]+)['""]")) {
            [void]$ids.Add($match.Groups['id'].Value)
        }

        # Parameterized table-driven checks:
        # @{ Id='4.1'; ... } then Invoke-CisCheck -ControlId $check.Id
        foreach ($match in [regex]::Matches($Text, "Id\s*=\s*['""](?<id>[^'""]+)['""]")) {
            [void]$ids.Add($match.Groups['id'].Value)
        }

        return @($ids)
    }

    $script:ProjectRoot = if ($env:CIS_IIS10_PROJECT_ROOT) {
        $env:CIS_IIS10_PROJECT_ROOT
    }
    elseif ($PSCommandPath) {
        Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    }
    else {
        (Get-Location).Path
    }

    $script:AuditScriptPath = Get-FirstExistingFile -CandidatePaths @(
        (Join-Path $script:ProjectRoot 'Invoke-CIS-IIS10.ps1'),
        (Join-Path $script:ProjectRoot 'Invoke-CIS-IIS10-v8.ps1'),
        (Join-Path $script:ProjectRoot 'Invoke-CIS-IIS10.2.ps1')
    )

    $script:AuditText = Get-Content -LiteralPath $script:AuditScriptPath -Raw
    $script:ActualControlIds = Get-CisControlIdsFromAuditText -Text $script:AuditText
}

Describe 'CIS IIS 10 audit script - static contract tests' {
    It 'has valid PowerShell syntax' {
        $tokens = $null
        $errors = $null

        [System.Management.Automation.Language.Parser]::ParseFile(
            $script:AuditScriptPath,
            [ref]$tokens,
            [ref]$errors
        ) | Out-Null

        $errors | Should -BeNullOrEmpty
    }

    It 'defines Invoke-CisCheck calls' {
        $script:AuditText | Should -Match 'Invoke-CisCheck'
    }

    It 'uses the expected structured status values only' {
        $allowedStatuses = @(
            'Pass',
            'Fail',
            'ManualReview',
            'NotApplicable',
            'Error'
        )

        $pattern = 'Status\s+''(?<status>[^'']+)'''
        $statusMatches = [regex]::Matches($script:AuditText, $pattern)

        foreach ($match in $statusMatches) {
            $match.Groups['status'].Value | Should -BeIn $allowedStatuses
        }
    }

    It 'contains Add-CisResult calls' {
        $script:AuditText | Should -Match 'Add-CisResult'
    }

    It 'includes the core output fields' {
        $requiredFields = @(
            'ControlId',
            'Level',
            'Title',
            'AuditType',
            'Status',
            'Evidence',
            'Expected',
            'Remediation',
            'CisAuditCommand',
            'CisRemediationCommand'
        )

        foreach ($field in $requiredFields) {
            $script:AuditText | Should -Match $field
        }
    }

    It 'contains all CIS IIS 10 Benchmark v1.2.1 control IDs' {
        $expectedControls = @(
            '1.1','1.2','1.3','1.4','1.5','1.6','1.7',
            '2.1','2.2','2.3','2.4','2.5','2.6','2.7','2.8',
            '3.1','3.2','3.3','3.4','3.5','3.6','3.7','3.8','3.9','3.10','3.11','3.12',
            '4.1','4.2','4.3','4.4','4.5','4.6','4.7','4.8','4.9','4.10','4.11',
            '5.1','5.2','5.3',
            '6.1','6.2',
            '7.1','7.2','7.3','7.4','7.5','7.6','7.7','7.8','7.9','7.10','7.11','7.12'
        )

        $missingControls = @($expectedControls | Where-Object { $_ -notin $script:ActualControlIds })

        $missingControls | Should -BeNullOrEmpty
    }
}

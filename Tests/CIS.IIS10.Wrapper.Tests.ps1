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

    $script:ProjectRoot = if ($env:CIS_IIS10_PROJECT_ROOT) {
        $env:CIS_IIS10_PROJECT_ROOT
    }
    elseif ($PSCommandPath) {
        Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    }
    else {
        (Get-Location).Path
    }

    $script:WrapperScriptPath = Get-FirstExistingFile -CandidatePaths @(
        (Join-Path $script:ProjectRoot 'CIS-IIS10-wrapper.ps1'),
        (Join-Path $script:ProjectRoot 'iisauditwrapper-v8-tabbed-filtered-grouped.ps1'),
        (Join-Path $script:ProjectRoot 'iisauditwrapper-v8-tabbed-filtered.ps1'),
        (Join-Path $script:ProjectRoot 'iisauditwrapper-v8-tabbed.ps1'),
        (Join-Path $script:ProjectRoot 'iisauditwrapper-v8.ps1'),
        (Join-Path $script:ProjectRoot 'iisauditwrapper.ps1')
    )

    $script:WrapperText = Get-Content -LiteralPath $script:WrapperScriptPath -Raw
}

Describe 'CIS IIS 10 wrapper script - static report tests' {
    It 'has valid PowerShell syntax' {
        $tokens = $null
        $errors = $null

        [System.Management.Automation.Language.Parser]::ParseFile(
            $script:WrapperScriptPath,
            [ref]$tokens,
            [ref]$errors
        ) | Out-Null

        $errors | Should -BeNullOrEmpty
    }

    It 'defines New-IisAuditHtmlReport' {
        $script:WrapperText | Should -Match 'function\s+New-IisAuditHtmlReport'
    }

    It 'contains the Detailed Results tab' {
        $script:WrapperText | Should -Match 'Detailed Results'
    }

    It 'contains the Consolidated Report tab' {
        $script:WrapperText | Should -Match 'Consolidated Report'
    }

    It 'contains consolidated status filters' {
        $script:WrapperText | Should -Match 'Fail'
        $script:WrapperText | Should -Match 'Error'
        $script:WrapperText | Should -Match 'ManualReview|Manual Review'
    }

    It 'contains sticky table header CSS' {
        $script:WrapperText | Should -Match 'position\s*:\s*sticky'
        $script:WrapperText | Should -Match 'thead\s*th'
    }

    It 'groups or combines servers in the consolidated report' {
        $script:WrapperText | Should -Match 'Servers'
        $script:WrapperText | Should -Match 'Group-Object|grouped|Consolidated'
    }
}

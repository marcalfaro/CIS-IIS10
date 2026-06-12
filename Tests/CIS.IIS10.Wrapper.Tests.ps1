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

Describe 'CIS IIS 10 wrapper script - report generation contract tests' {
    BeforeAll {
        $script:WrapperScript = Get-FirstExistingFile -Root $ProjectRoot -Names @(
            'iisauditwrapper-v8-tabbed-filtered-grouped.ps1',
            'iisauditwrapper-v8-tabbed-filtered.ps1',
            'iisauditwrapper-v8-tabbed.ps1',
            'iisauditwrapper-v8.ps1'
        )

        $script:WrapperText = Get-Content -Path $script:WrapperScript -Raw
        $script:ParseErrors = $null
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:WrapperScript,
            [ref]$null,
            [ref]$script:ParseErrors
        )
    }

    It 'has no PowerShell parser errors' {
        $script:ParseErrors | Should -BeNullOrEmpty
    }

    It 'contains the HTML report generator function' {
        $script:WrapperText | Should -Match 'function\s+New-IisAuditHtmlReport'
    }

    It 'generates a single self-contained HTML file without external CSS or JavaScript' {
        $script:WrapperText | Should -Match '<style>'
        $script:WrapperText | Should -Not -Match '<link\s+[^>]*stylesheet'
        $script:WrapperText | Should -Not -Match '<script\s+[^>]*src='
        $script:WrapperText | Should -Not -Match 'https?://'
    }

    It 'contains two report tabs' {
        $script:WrapperText | Should -Match 'Detailed Results'
        $script:WrapperText | Should -Match 'Consolidated Report'
    }

    It 'contains consolidated report filters for Fail, Error, and ManualReview' {
        $script:WrapperText | Should -Match 'Fail'
        $script:WrapperText | Should -Match 'Error'
        $script:WrapperText | Should -Match 'ManualReview|Manual Review'
    }

    It 'groups consolidated rows by status, control, level, and title' {
        $script:WrapperText | Should -Match 'Group-Object'
        $script:WrapperText | Should -Match 'Status'
        $script:WrapperText | Should -Match 'ControlId|Control'
        $script:WrapperText | Should -Match 'Level'
        $script:WrapperText | Should -Match 'Title'
    }

    It 'keeps table headers sticky/frozen' {
        $script:WrapperText | Should -Match 'position\s*:\s*sticky'
        $script:WrapperText | Should -Match 'thead\s+th|thead\s*th'
    }
}

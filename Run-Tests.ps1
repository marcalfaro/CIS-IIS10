param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Import-Module Pester -MinimumVersion 5.0 -Force

$config = New-PesterConfiguration
$config.Run.Path = Join-Path $PSScriptRoot 'Tests'
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'
$config.TestResult.Enabled = $true
$config.TestResult.OutputPath = Join-Path $PSScriptRoot 'TestResults.xml'
$config.TestResult.OutputFormat = 'NUnitXml'
$config.CodeCoverage.Enabled = $false
$config.Run.Container = New-PesterContainer -Path (Join-Path $PSScriptRoot 'Tests') -Data @{ ProjectRoot = $ProjectRoot }

Invoke-Pester -Configuration $config

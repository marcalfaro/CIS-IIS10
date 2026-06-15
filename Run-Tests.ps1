[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ProjectRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path)
)

$ErrorActionPreference = 'Stop'
$env:CIS_IIS10_PROJECT_ROOT = $ProjectRoot

Import-Module Pester -MinimumVersion 5.0 -Force

$testPath = Join-Path $ProjectRoot 'Tests'

$config = New-PesterConfiguration
$config.Run.Path = $testPath
$config.Output.Verbosity = 'Detailed'

Invoke-Pester -Configuration $config

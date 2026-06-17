This is a PowerShell Script designed for auditing the IIS 10 as per the CIS Microsoft IIS 10 Benchmark v1.2.1. 


# CIS IIS 10 Pester Tests

These are starter Pester v5 tests for the CIS IIS 10 audit/wrapper scripts.

## Folder layout

CIS-IIS10/
  Invoke-CIS-IIS10.ps1
  CIS-IIS10-wrapper.ps1
  Run-Tests.ps1
  Tests/
    CIS.IIS10.Audit.Tests.ps1
    CIS.IIS10.Wrapper.Tests.ps1
```

## Run

```powershell
Import-Module Pester -MinimumVersion 5.0 -Force
.\Run-Tests.ps1 -ProjectRoot 'C:\VSCodeProfiles\Marc\Github\CIS-IIS10'
```

Or, if you put `Run-Tests.ps1` directly inside the project folder:

```powershell
.\Run-Tests.ps1
```

## What these tests cover

- Audit script has no parser errors.
- Audit script contains an `Invoke-CisCheck` block for every CIS IIS 10 Benchmark v1.2.1 control.
- Audit script uses structured results rather than `Write-Host` output.
- Audit script uses only allowed statuses: `Pass`, `Fail`, `ManualReview`, `NotApplicable`, `Error`.
- Known CIS Manual controls are marked as `AuditType Manual`.
- Wrapper generates self-contained HTML.
- Wrapper includes the Detailed Results and Consolidated Report tabs.
- Wrapper includes Fail/Error/ManualReview filters.
- Wrapper groups the consolidated report.
- Wrapper keeps table headers sticky/frozen.

## Note

These are mostly contract/static tests. They intentionally do not connect to remote servers or require IIS to be installed on the test machine. Later, the scripts can be refactored into a `.psm1` module so individual checks and HTML generation can be tested with full Pester mocks.

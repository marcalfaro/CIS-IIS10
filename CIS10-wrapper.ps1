<#
.SYNOPSIS
  Remote wrapper for structured CIS IIS 10 Benchmark v1.2.1 evidence collection.
.DESCRIPTION
  Preserves the server list in this wrapper, runs Invoke-CIS-IIS10-v8.ps1
  against each server, and writes one combined HTML report at the end.
#>
[CmdletBinding()]
param(
    [string]$AuditScriptName = 'Invoke-CIS-IIS10.ps1',
    [string]$ReportPrefix = 'CIS_IIS10_Audit_Report'
)

$localFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$localScript = Join-Path $localFolder $AuditScriptName
$logFile = Join-Path $localFolder ("IIS_Audit_Log_{0}.txt" -f (Get-Date -Format 'yyyyMMdd'))
$localReport = Join-Path $localFolder ("{0}_{1}.html" -f $ReportPrefix,(Get-Date -Format 'yyyyMMdd_HHmmss'))

if(-not (Test-Path $localScript)){ throw "Audit script not found: $localScript" }

try { $global:creds = Get-Credential -UserName 'digitaldev\malfaroa' -Message 'Enter credentials for ALL remote sessions (this will be applied to all servers):' }
catch { Write-Host '[!] Credential prompt canceled. Exiting script.' -ForegroundColor Red; exit }
if(-not $global:creds){ Write-Host '[!] No credentials supplied. Exiting script.' -ForegroundColor Red; exit }

# Define remote servers (hostnames)
$remoteServers = @(
    "",
    "",
    ""
)

function Write-Log { param([string]$Message='') Add-Content -Path $logFile -Value ("{0}`t{1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message) }
function Resolve-Server { param([string]$server)
    try { $dns=Resolve-DnsName -Name $server -Type A -ErrorAction Stop; $ipv4=$dns|? {$_.IPAddress -match '^\d{1,3}(\.\d{1,3}){3}$'}|Select-Object -First 1; if($ipv4){return $ipv4.IPAddress} } catch {}
    try { if(Test-Connection -ComputerName $server -Count 1 -Quiet){ $ping=Test-Connection -ComputerName $server -Count 1; return $ping.IPV4Address.IPAddressToString } } catch {}
    return $null
}
function New-ErrorRow { param($Server,$Status,$Evidence)
    [pscustomobject]@{ Server=$Server; ControlId='Wrapper'; Level=''; AuditType='Automated'; Status=$Status; Scope='Remote execution'; Title='Remote audit execution'; Evidence=[string]$Evidence; Expected='Remote audit should execute successfully.'; Remediation='Check DNS, WinRM, credentials, firewall, permissions, and IIS/WebAdministration availability.' }
}
function HtmlEncode([object]$Value){ [System.Net.WebUtility]::HtmlEncode([string]$Value) }
function New-IisAuditHtmlReport {
    param(
        [object[]]$Rows,
        [string]$Path
    )

    $safeRows = @(
        $Rows | ForEach-Object {
            [pscustomobject]@{
                Server                = [string]$_.Server
                ControlId             = [string]$_.ControlId
                Level                 = [string]$_.Level
                AuditType             = [string]$_.AuditType
                Status                = [string]$_.Status
                Scope                 = [string]$_.Scope
                Title                 = [string]$_.Title
                Evidence              = [string]$_.Evidence
                Expected              = [string]$_.Expected
                Remediation           = [string]$_.Remediation
                CisAuditCommand       = [string]$_.CisAuditCommand
                CisRemediationCommand = [string]$_.CisRemediationCommand
            }
        }
    )

    $total  = $safeRows.Count
    $pass   = (@($safeRows | Where-Object Status -eq 'Pass')).Count
    $fail   = (@($safeRows | Where-Object Status -eq 'Fail')).Count
    $manual = (@($safeRows | Where-Object Status -eq 'ManualReview')).Count
    $na     = (@($safeRows | Where-Object Status -eq 'NotApplicable')).Count
    $err    = (@($safeRows | Where-Object Status -eq 'Error')).Count

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $detailRowHtml = foreach ($r in $safeRows) {
        $cls = switch ($r.Status) {
            'Pass'          { 'pass' }
            'Fail'          { 'fail' }
            'ManualReview'  { 'manual' }
            'NotApplicable' { 'na' }
            'Error'         { 'error' }
            default         { 'other' }
        }

        "<tr class='$cls'><td>$(HtmlEncode $r.Server)</td><td>$(HtmlEncode $r.ControlId)</td><td>$(HtmlEncode $r.Level)</td><td>$(HtmlEncode $r.AuditType)</td><td>$(HtmlEncode $r.Status)</td><td>$(HtmlEncode $r.Scope)</td><td>$(HtmlEncode $r.Title)</td><td>$(HtmlEncode $r.Evidence)</td><td>$(HtmlEncode $r.Expected)</td><td>$(HtmlEncode $r.Remediation)</td><td>$(HtmlEncode $r.CisAuditCommand)</td><td>$(HtmlEncode $r.CisRemediationCommand)</td></tr>"
    }

    $consolidatedRows = @(
        $safeRows |
            Where-Object { $_.Status -in @('Fail', 'Error', 'ManualReview') } |
            Group-Object -Property Status, ControlId, Level, Title |
            ForEach-Object {
                $groupRows = @($_.Group)
                $first = $groupRows[0]
                $servers = @(
                    $groupRows |
                        ForEach-Object { [string]$_.Server } |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                        Sort-Object -Unique
                )

                [pscustomobject]@{
                    Status      = [string]$first.Status
                    ControlId   = [string]$first.ControlId
                    Level       = [string]$first.Level
                    Title       = [string]$first.Title
                    ServerCount = $servers.Count
                    Servers     = ($servers -join ', ')
                }
            } |
            Sort-Object @{ Expression = {
                    switch ($_.Status) {
                        'Fail'         { 1 }
                        'Error'        { 2 }
                        'ManualReview' { 3 }
                        default        { 9 }
                    }
                }
            }, ControlId, Title
    )

    $consolidatedRowHtml = foreach ($r in $consolidatedRows) {
        $cls = switch ($r.Status) {
            'Fail'         { 'fail' }
            'ManualReview' { 'manual' }
            'Error'        { 'error' }
            default        { 'other' }
        }

        "<tr class='$cls consolidated-row' data-status='$(HtmlEncode $r.Status)'><td>$(HtmlEncode $r.Status)</td><td>$(HtmlEncode $r.ControlId)</td><td>$(HtmlEncode $r.Level)</td><td>$(HtmlEncode $r.Title)</td><td><b>$(HtmlEncode $r.ServerCount) server(s):</b> $(HtmlEncode $r.Servers)</td></tr>"
    }

    if ($consolidatedRowHtml.Count -eq 0) {
        $consolidatedRowHtml = @("<tr class='consolidated-empty-row'><td colspan='5'>No Fail, Error, or ManualReview rows found.</td></tr>")
    }

    $html = @"
<!doctype html>
<html>
<head>
<meta charset='utf-8'>
<title>CIS IIS 10 Audit Report</title>
<style>
*{box-sizing:border-box}
html,body{height:100%}
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f8fafc;color:#111827;overflow:hidden}
.report-shell{height:100vh;display:flex;flex-direction:column;padding:18px 24px;gap:12px}
h1{margin:0 0 2px 0;font-size:24px}.meta{color:#4b5563}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:0}.card{background:white;border:1px solid #e5e7eb;border-radius:8px;padding:10px 16px;box-shadow:0 1px 2px #ddd}.num{font-size:22px;font-weight:700}.note{background:#fff7ed;border:1px solid #fed7aa;padding:10px 12px;border-radius:8px;margin:0}
.tabs{display:flex;gap:0;border-bottom:1px solid #d1d5db;background:#e5e7eb;border-radius:8px 8px 0 0;overflow:hidden}.tab-button{border:0;background:#e5e7eb;padding:11px 16px;cursor:pointer;font-size:14px;color:#111827}.tab-button.active{background:#ffffff;border-bottom:3px solid #1f4e79;font-weight:700}.tab-content{display:none;flex:1;min-height:0}.tab-content.active{display:flex;flex-direction:column;gap:8px}.tab-heading{margin:0;font-size:16px}.tab-help{margin:0;color:#4b5563;font-size:13px}
.filter-bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:2px 0 4px 0}.filter-label{font-size:13px;color:#4b5563;margin-right:4px}.filter-button{border:1px solid #d1d5db;background:white;border-radius:999px;padding:7px 12px;cursor:pointer;font-size:13px}.filter-button.active{font-weight:700;border-color:#1f4e79;box-shadow:0 0 0 2px rgba(31,78,121,.15)}.filter-button[data-status='Fail'].active{background:#fee2e2}.filter-button[data-status='Error'].active{background:#fecaca}.filter-button[data-status='ManualReview'].active{background:#fef3c7}.hidden-row{display:none}.no-filter-results td{font-weight:700;color:#4b5563;background:#f9fafb}
.table-wrap{flex:1;min-height:0;width:100%;overflow:auto;background:white;border:1px solid #e5e7eb;border-radius:0 0 8px 8px;position:relative}
table{border-collapse:separate;border-spacing:0;width:100%;table-layout:fixed;background:white;font-size:12px}
.details-table{min-width:1900px}.consolidated-table{min-width:900px}
thead th{position:sticky;top:0;z-index:50;background:#111827;color:white;border-top:0;box-shadow:0 2px 4px rgba(0,0,0,.25)}
th,td{border-right:1px solid #e5e7eb;border-bottom:1px solid #e5e7eb;padding:7px;vertical-align:top;white-space:normal;overflow-wrap:anywhere;word-break:break-word;text-align:left}
th:first-child,td:first-child{border-left:0}.pass td:nth-child(5),.pass-status{background:#dcfce7;font-weight:700}.fail td:nth-child(5),.fail-status{background:#fee2e2;font-weight:700}.manual td:nth-child(5),.manual-status{background:#fef3c7;font-weight:700}.na td:nth-child(5){background:#e0f2fe;font-weight:700}.error td:nth-child(5),.error-status{background:#fecaca;font-weight:700}
@media(max-width:900px){.report-shell{padding:10px}.cards{gap:8px}.card{padding:8px 12px}table{font-size:11px}.details-table{min-width:1500px}.consolidated-table{min-width:760px}}
</style>
<script>
function openTab(tabId, button) {
    document.querySelectorAll('.tab-content').forEach(function (x) { x.classList.remove('active'); });
    document.querySelectorAll('.tab-button').forEach(function (x) { x.classList.remove('active'); });
    document.getElementById(tabId).classList.add('active');
    button.classList.add('active');
}

function toggleConsolidatedStatus(status, button) {
    button.classList.toggle('active');
    applyConsolidatedFilters();
}

function applyConsolidatedFilters() {
    var activeStatuses = Array.from(document.querySelectorAll('.filter-button.active')).map(function (button) {
        return button.getAttribute('data-status');
    });

    var rows = Array.from(document.querySelectorAll('#consolidated .consolidated-row'));
    var visibleCount = 0;

    rows.forEach(function (row) {
        var rowStatus = row.getAttribute('data-status');
        var isVisible = activeStatuses.indexOf(rowStatus) >= 0;
        row.classList.toggle('hidden-row', !isVisible);
        if (isVisible) {
            visibleCount++;
        }
    });

    var noResultsRow = document.getElementById('noFilterResultsRow');
    if (noResultsRow) {
        noResultsRow.classList.toggle('hidden-row', visibleCount > 0);
    }
}

window.addEventListener('load', applyConsolidatedFilters);
</script>
</head>
<body>
<div class='report-shell'>
<h1>CIS Microsoft IIS 10 Benchmark v1.2.1 Audit Evidence Report</h1>
<div class='meta'>Generated: $generated &nbsp; | &nbsp; Servers: $((@($remoteServers)).Count)</div>
<div class='note'><b>Important:</b> This report is a PowerShell evidence collector. Controls marked ManualReview require human validation and should not be counted as automated compliance.</div>
<div class='cards'><div class='card'><div>Total</div><div class='num'>$total</div></div><div class='card'><div>Pass</div><div class='num'>$pass</div></div><div class='card'><div>Fail</div><div class='num'>$fail</div></div><div class='card'><div>ManualReview</div><div class='num'>$manual</div></div><div class='card'><div>NotApplicable</div><div class='num'>$na</div></div><div class='card'><div>Error</div><div class='num'>$err</div></div></div>

<div class='tabs'>
    <button class='tab-button active' onclick="openTab('details', this)">Detailed Results</button>
    <button class='tab-button' onclick="openTab('consolidated', this)">Consolidated Report</button>
</div>

<div id='details' class='tab-content active'>
    <h2 class='tab-heading'>Detailed Results</h2>
    <p class='tab-help'>Full evidence table for every control and every server.</p>
    <div class='table-wrap'>
        <table class='details-table'>
            <colgroup><col style='width:10%'><col style='width:7%'><col style='width:5%'><col style='width:8%'><col style='width:8%'><col style='width:12%'><col style='width:16%'><col style='width:16%'><col style='width:10%'><col style='width:10%'><col style='width:14%'><col style='width:16%'></colgroup>
            <thead><tr><th>Server</th><th>Control</th><th>Level</th><th>Audit Type</th><th>Status</th><th>Scope</th><th>Title</th><th>Evidence</th><th>Expected</th><th>Remediation</th><th>CIS Audit Command</th><th>CIS Remediation Command</th></tr></thead>
            <tbody>
$($detailRowHtml -join "`n")
            </tbody>
        </table>
    </div>
</div>

<div id='consolidated' class='tab-content'>
    <h2 class='tab-heading'>Consolidated Report</h2>
    <p class='tab-help'>Grouped rows requiring attention only. Servers with the same Status, Control, Level, and Title are combined into one row.</p>
    <div class='filter-bar'>
        <span class='filter-label'>Show:</span>
        <button type='button' class='filter-button active' data-status='Fail' onclick="toggleConsolidatedStatus('Fail', this)">Fail</button>
        <button type='button' class='filter-button active' data-status='Error' onclick="toggleConsolidatedStatus('Error', this)">Error</button>
        <button type='button' class='filter-button active' data-status='ManualReview' onclick="toggleConsolidatedStatus('ManualReview', this)">Manual Review</button>
    </div>
    <div class='table-wrap'>
        <table class='consolidated-table'>
            <colgroup><col style='width:10%'><col style='width:10%'><col style='width:8%'><col style='width:47%'><col style='width:25%'></colgroup>
            <thead><tr><th>Status</th><th>Control</th><th>Level</th><th>Title</th><th>Servers</th></tr></thead>
            <tbody>
$($consolidatedRowHtml -join "`n")
                <tr id='noFilterResultsRow' class='no-filter-results hidden-row'><td colspan='5'>No rows match the selected filter.</td></tr>
            </tbody>
        </table>
    </div>
</div>
</div>
</body>
</html>
"@

    $html | Out-File -FilePath $Path -Encoding UTF8
}

$allRows = New-Object System.Collections.Generic.List[object]
foreach($server in $remoteServers){
    Write-Host "`n[~] Starting audit for: $server ..." -ForegroundColor Cyan; Write-Log "[~] Starting audit for $server"
    $ip=Resolve-Server $server
    if(-not $ip){ Write-Host "[!] Unreachable: $server" -ForegroundColor Red; Write-Log "[!] FAILED: $server unreachable"; $allRows.Add((New-ErrorRow $server 'Error' 'DNS and ping failed.'))|Out-Null; continue }
    Write-Host "[+] Resolved $server -> $ip" -ForegroundColor Yellow; Write-Log "[+] Resolved $server to $ip"
    $session=$null; $success=$false
    $maxAttempts = 1    #Set to 1 because server will lockout after 3 failed attempts, so we don't want to retry if it fails.
    for($attempt=1; $attempt -le $maxAttempts -and -not $success; $attempt++){
        try{
            Write-Host "[~] Attempt $attempt of $maxAttempts for $server ..." -ForegroundColor DarkCyan; Write-Log "[~] Attempt $attempt for $server"
            $session=New-PSSession -ComputerName $ip -Authentication Default -Credential $global:creds -ErrorAction Stop
            $rows=@(Invoke-Command -Session $session -FilePath $localScript -ErrorAction Stop)
            if($rows.Count -eq 0){ $allRows.Add((New-ErrorRow $server 'Error' 'Remote script returned zero rows.'))|Out-Null } else { foreach($row in $rows){ $allRows.Add($row)|Out-Null } }
            $success=$true; Write-Host "[+] SUCCESS: $server returned $($rows.Count) rows" -ForegroundColor Green; Write-Log "[+] SUCCESS: $server returned $($rows.Count) rows"
        } catch { Write-Host "[!] ERROR on attempt ${attempt}: $($_.Exception.Message)" -ForegroundColor Red; Write-Log "[!] ERROR attempt $attempt for ${server}: $($_.Exception.Message)"; if($attempt -lt $maxAttempts){ Start-Sleep -Seconds ([math]::Pow(2,$attempt)) } }
        finally { if($session){ Remove-PSSession $session -ErrorAction SilentlyContinue; $session=$null } }
    }
    if(-not $success){ $allRows.Add((New-ErrorRow $server 'Error' "Remote audit failed after $maxAttempts attempts. See log file for details."))|Out-Null }
}
New-IisAuditHtmlReport -Rows $allRows -Path $localReport
Write-Host "`n[+] Combined HTML report saved -> $localReport" -ForegroundColor Green
Write-Log "[+] Combined HTML report saved to $localReport"

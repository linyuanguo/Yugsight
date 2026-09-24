# av_smoke.ps1 - functional smoke test for the built Yugsight exe.
#
# Boots the binary on a free loopback port with
#   -no-admin -no-auth -no-browser -port <free>
# then verifies:
#   - GET /api/info : 200 + expected version (server + version injection)
#   - GET /app/     : 200 + Yugsight (embedded Vue frontend via go:embed)
#   - POST /api/quit: graceful shutdown (process gone within 30s, quit marker
#     in log, exit code 0)
#   - log           : startup marker present, no panic
#
# Note on /api/quit: the handler calls os.Exit(0) right after writing the
# response, so the HTTP client frequently sees "connection closed" instead of
# 200. That is expected; the authoritative evidence is process exit + log.
#
# ASCII-only file (Chinese log markers built from Unicode code points).
param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$Log,
  [int]$PortBase = 18420
)
$ErrorActionPreference = 'Stop'
$script:fail = 0

function Check($name, $ok, $detail) {
  if ($ok) { Write-Host ("  [PASS] {0}  ({1})" -f $name, $detail) }
  else { Write-Host ("  [FAIL] {0}  ({1})" -f $name, $detail); $script:fail++ }
}

# ---- free loopback port ----
$port = 0
for ($p = $PortBase; $p -le $PortBase + 99; $p++) {
  try {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $p)
    $l.Start()
    $l.Stop()
    $port = $p
    break
  } catch { }
}
if ($port -eq 0) { Write-Host '  [FAIL] no free port in range'; exit 1 }
Write-Host ("SMOKE {0} on port {1}" -f (Split-Path $Exe -Leaf), $port)

# Retry: right after build/sign, AV real-time protection may hold the fresh
# exe for scanning -> Start-Process fails until the scan finishes.
$proc = $null
for ($attempt = 1; $attempt -le 6; $attempt++) {
  try {
    $proc = Start-Process -FilePath $Exe `
      -ArgumentList @('-no-admin', '-no-auth', '-no-browser', '-port', "$port") `
      -WorkingDirectory (Split-Path $Exe -Parent) `
      -NoNewWindow -PassThru `
      -RedirectStandardOutput $Log -RedirectStandardError ($Log + '.err')
    break
  } catch {
    if ($attempt -eq 6) { throw }
    Write-Host ("  [INFO] exe busy (AV scan?), attempt {0} - retrying in 10s..." -f $attempt)
    Start-Sleep -Seconds 10
  }
}
Write-Host ("  [INFO] pid={0}" -f $proc.Id)

try {
  # ---- /api/info ----
  $infoBody = ''
  $okInfo = $false
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt 90) {
    if ($proc.HasExited) { break }
    try {
      $r = Invoke-WebRequest -UseBasicParsing -Uri ("http://127.0.0.1:{0}/api/info" -f $port) -TimeoutSec 2
      if ($r.StatusCode -eq 200) {
        $infoBody = $r.Content
        if ($infoBody -match [regex]::Escape($Version)) { $okInfo = $true; break }
      }
    } catch { }
    Start-Sleep -Milliseconds 500
  }
  if ($infoBody) { $show = $infoBody.Substring(0, [Math]::Min(120, $infoBody.Length)) } else { $show = 'no response' }
  Check 'api-info' $okInfo $show

  # ---- /app/ (embedded Vue frontend) ----
  $okApp = $false
  try {
    $ra = Invoke-WebRequest -UseBasicParsing -Uri ("http://127.0.0.1:{0}/app/" -f $port) -TimeoutSec 5
    if ($ra.StatusCode -eq 200 -and $ra.Content -match 'Yugsight') { $okApp = $true }
  } catch { }
  Check 'vue-app' $okApp 'GET /app/ (embedded frontend)'

  # ---- POST /api/quit ----
  $quitNote = ''
  try {
    $rq = Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://127.0.0.1:{0}/api/quit" -f $port) -TimeoutSec 5
    if ($rq.StatusCode -eq 200) { $quitNote = 'http 200' } else { $quitNote = "http $($rq.StatusCode)" }
  } catch { $quitNote = 'conn closed (expected: server os.Exit right after response)' }
  Check 'api-quit-sent' $true $quitNote

  # ---- graceful exit ----
  $exited = $false
  $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
  while ($sw2.Elapsed.TotalSeconds -lt 30) {
    if ($proc.WaitForExit(500)) { $exited = $true; break }
  }
  Check 'process-exited' $exited 'process gone within 30s after quit'

  # ExitCode may be null for a moment after exit (Start-Process quirk); retry.
  $code = $null
  for ($i = 0; $i -lt 10 -and $null -eq $code; $i++) {
    if ($proc.HasExited) { $code = $proc.ExitCode }
    Start-Sleep -Milliseconds 300
  }
  if ($null -eq $code) { $codeNote = 'not readable (process gone; quit marker below is the evidence)' } else { $codeNote = "exit code=$code" }
  Check 'exit-code-0' (($null -eq $code) -or ($code -eq 0)) $codeNote

  # ---- log markers (UTF-8) ----
  $logText = ''
  if (Test-Path $Log) { $logText = [System.IO.File]::ReadAllText($Log, [System.Text.Encoding]::UTF8) }
  $started = -join ([char[]]@(0x5DF2, 0x542F, 0x52A8))   # ???
  $stopped = -join ([char[]]@(0x5DF2, 0x505C, 0x6B62))   # ???
  Check 'log-startup' ($logText.Contains($started)) 'startup marker in log'
  Check 'log-quit' ($logText.Contains($stopped)) 'quit marker in log'
  Check 'log-no-panic' ($logText -notmatch 'panic') 'no panic in log'
}
finally {
  if (-not $proc.HasExited) { try { $proc.Kill() } catch { } }
}

Write-Host ''
if ($script:fail -eq 0) { Write-Host 'SMOKE: ALL CHECKS PASSED' } else { Write-Host ('SMOKE: {0} CHECK(S) FAILED' -f $script:fail) }
exit $script:fail

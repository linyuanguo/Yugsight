# av_sign.ps1 - offline self-signing of the built Yugsight exe.
#
# Fully offline:
#   1. creates (once) a local code-signing certificate in Cert:\CurrentUser\My
#      (New-SelfSignedCertificate, no CA, no network)
#   2. exports it as a PFX next to the build output (build_tmp\sign\)
#   3. signs the exe with signtool (Windows SDK, local)
#   4. verifies with Get-AuthenticodeSignature (locale-independent: a valid
#      self-signed signature reports status "Valid")
#
# Effect: the exe gains an Authenticode signature block, which changes the
# binary structure and defuses "unsigned program" heuristics. The certificate
# is self-signed (not trusted by any CA) - for dev builds that is sufficient;
# the goal is structure, not trust.
param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [Parameter(Mandatory = $true)][string]$PfxDir,
  [string]$Subject = 'CN=Yugsight Local Build Publisher',
  [string]$PfxPass = 'yugsight-local'
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $PfxDir)) { New-Item -ItemType Directory -Force -Path $PfxDir | Out-Null }

# ---- certificate (create once, reuse afterwards) ----
$store = 'Cert:\CurrentUser\My'
$cert = Get-ChildItem $store -ErrorAction SilentlyContinue |
  Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date).AddDays(7) } |
  Sort-Object NotAfter -Descending | Select-Object -First 1

if ($null -eq $cert) {
  Write-Host '[SIGN] creating local self-signed code signing certificate (valid 5 years)'
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject `
    -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(5) -FriendlyName 'YugsightLocalSign' -CertStoreLocation $store
}
$pfx = Join-Path $PfxDir 'yugsight.pfx'
$sec = ConvertTo-SecureString -String $PfxPass -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $sec | Out-Null
Write-Host ("[SIGN] certificate: {0} (expires {1:yyyy-MM-dd})" -f $cert.Subject, $cert.NotAfter)

# Trust the self-signed root in the current user's Root store (one-time,
# offline). Without this, WinVerifyTrust / Get-AuthenticodeSignature report
# "terminated in a root certificate which is not trusted" even though the
# signature itself is intact. Dev-machine only; the published artifact does
# not depend on this.
$thumb = $cert.Thumbprint
$trusted = Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
  Where-Object { $_.Thumbprint -eq $thumb }
if ($null -eq $trusted) {
  $cer = Join-Path $PfxDir 'yugsight.cer'
  Export-Certificate -Cert $cert -FilePath $cer | Out-Null
  Import-Certificate -FilePath $cer -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
  Write-Host '[SIGN] added self-signed root to Cert:\CurrentUser\Root (user store, local only)'
}

# ---- locate signtool (Windows SDK) ----
$sigtool = $null
$kit = 'C:\Program Files (x86)\Windows Kits\10\bin'
if (Test-Path $kit) {
  $sigtool = Get-ChildItem $kit -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1 -ExpandProperty FullName
}
if ($null -eq $sigtool) {
  $cmd = Get-Command signtool -ErrorAction SilentlyContinue
  if ($cmd) { $sigtool = $cmd.Source }
}
if ($null -eq $sigtool) { Write-Host '[SIGN] signtool not found - cannot sign'; exit 2 }
Write-Host ("[SIGN] using {0}" -f $sigtool)

# ---- sign (no timestamp server: offline) ----
# Retry: right after a big build, AV real-time protection (e.g. Huorong)
# often holds the fresh exe for scanning -> "file is being used by another
# process". Wait it out instead of failing the whole pipeline.
$signOk = $false
for ($attempt = 1; $attempt -le 6; $attempt++) {
  & $sigtool sign /fd SHA256 /f $pfx /p $PfxPass $Exe
  if ($LASTEXITCODE -eq 0) { $signOk = $true; break }
  if ($attempt -lt 6) {
    Write-Host ("[SIGN] attempt {0} failed - file may be held by AV scan, retrying in 10s..." -f $attempt)
    Start-Sleep -Seconds 10
  }
}
if (-not $signOk) { Write-Host '[SIGN] signtool sign FAILED'; exit 1 }

# ---- verify (locale-independent) ----
$asig = Get-AuthenticodeSignature $Exe
if ($asig.Status -eq 'Valid' -or $asig.Status -eq 'Trusted') {
  Write-Host ("[SIGN] OK: signed and verified (status={0}, signer={1})" -f $asig.Status, $asig.SignerCertificate.Subject)
  exit 0
}
Write-Host ("[SIGN] verify FAILED (status={0})" -f $asig.Status)
exit 1

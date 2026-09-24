# av_verify.ps1 - post-build verification for the Yugsight AV-resistance build.
#
# Checks performed on the built exe:
#   - basic: exists, size, sha256
#   - PE structure: console subsystem, non-PIE (DYNAMIC_BASE off), x64
#   - static: import table contains only Windows system DLLs (no third-party
#     runtime) - proves the pure-static single-binary property
#   - cli: "-version" prints the expected version (ldflags -X worked)
#   - resources: UTF-16LE FileDescription / ProductName / version / company
#     strings are embedded in the PE (windres rsrc.syso applied)
#   - signature (when -RequireSign): Authenticode signature status and signer
#
# The file is pure ASCII on purpose: Chinese literals are built from Unicode
# code points, so it is safe under any code page / BOM situation (PS 5.1).
param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$RequireSign = '1'   # string on purpose: this PS 5.1 build fails to
)                             # bind -File string args onto [bool] (tested)
$ErrorActionPreference = 'Stop'
$script:fail = 0

function Check($name, $ok, $detail) {
  if ($ok) { Write-Host ("  [PASS] {0}  ({1})" -f $name, $detail) }
  else { Write-Host ("  [FAIL] {0}  ({1})" -f $name, $detail); $script:fail++ }
}
function Find-Bytes([byte[]]$hay, [byte[]]$needle) {
  if ($needle.Length -eq 0 -or $hay.Length -lt $needle.Length) { return -1 }
  for ($i = 0; $i -le $hay.Length - $needle.Length; $i++) {
    $m = $true
    for ($j = 0; $j -lt $needle.Length; $j++) {
      if ($hay[$i + $j] -ne $needle[$j]) { $m = $false; break }
    }
    if ($m) { return $i }
  }
  return -1
}
function Cps([int[]]$codes) { -join ([char[]]$codes) }
# cast to [int] before shifting: PS keeps the left operand's type in shift
# ops, so [byte]0x86 -shl 8 silently overflows to 0 (byte wraparound).
function U16([byte[]]$d, [int]$o) { [int]$d[$o] -bor ([int]$d[$o + 1] -shl 8) }
function U32([byte[]]$d, [int]$o) { [int]$d[$o] -bor ([int]$d[$o + 1] -shl 8) -bor ([int]$d[$o + 2] -shl 16) -bor ([int]$d[$o + 3] -shl 24) }

Write-Host ("VERIFY {0} (expected version: {1})" -f (Split-Path $Exe -Leaf), $Version)
if (-not (Test-Path $Exe)) { Write-Host '  [FAIL] exe not found'; exit 1 }

# Retry: right after build/sign, AV real-time protection may hold the fresh
# exe for scanning; wait it out instead of failing.
$b = $null
$sha = ''
for ($attempt = 1; $attempt -le 6; $attempt++) {
  try {
    $b = [System.IO.File]::ReadAllBytes($Exe)
    $sha = (Get-FileHash $Exe -Algorithm SHA256).Hash
    break
  } catch {
    if ($attempt -eq 6) { Write-Host '  [FAIL] cannot read exe (held by another process)'; exit 1 }
    Write-Host ("  [INFO] file busy (AV scan?), attempt {0} - retrying in 10s..." -f $attempt)
    Start-Sleep -Seconds 10
  }
}
Check 'file' $true ("size={0:N2} MB sha256={1}..." -f ($b.Length / 1MB), $sha.Substring(0, 24))

# ---------- PE structure ----------
if ($b[0] -ne 0x4D -or $b[1] -ne 0x5A) { Write-Host '  [FAIL] not a PE (no MZ)'; exit 1 }
$pe = U32 $b 0x3C
if ($b[$pe] -ne 0x50 -or $b[$pe + 1] -ne 0x45) { Write-Host '  [FAIL] no PE signature'; exit 1 }
$machine = U16 $b ($pe + 4)
$numSec = U16 $b ($pe + 6)
# SizeOfOptionalHeader is at pe+20 (pe+16 is NumberOfSymbols - reading it
# yields 0 and misaligns the whole section table).
$optSize = U16 $b ($pe + 20)
$opt = $pe + 24
$magic = U16 $b $opt
$is64 = ($magic -eq 0x20B)
# Subsystem / DLLCharacteristics: PE32+ at opt+0x44/opt+0x46,
# PE32 at opt+0x40/opt+0x42 (ImageBase is 8 vs 4 bytes).
$subOff = if ($is64) { $opt + 0x44 } else { $opt + 0x40 }
$dlOff = if ($is64) { $opt + 0x46 } else { $opt + 0x42 }
$sub = U16 $b $subOff
$dlc = U16 $b $dlOff
# 3 = IMAGE_SUBSYSTEM_WINDOWS_CUI (console window is the service UI); 2 = GUI.
Check 'subsystem-console' ($sub -eq 3) ("value={0}; 3=console(CUI), 2=GUI" -f $sub)
# DYNAMIC_BASE (ASLR/PIE) is bit 0x0040; Go 1.15+ defaults to PIE on
# windows/amd64, so the build must pass -buildmode=exe explicitly.
$dynamicBase = [bool]($dlc -band 0x0040)
Check 'non-pie' (-not $dynamicBase) ("DYNAMIC_BASE={0} (dllchars=0x{1:X4}); plan: -buildmode=exe, no PIE" -f $dynamicBase, $dlc)
Check 'x64' ($machine -eq 0x8664) ("machine=0x{0:X4}" -f $machine)

# ---------- static: imports must be system DLLs only ----------
$sysDlls = 'kernel32.dll', 'ntdll.dll', 'advapi32.dll', 'ws2_32.dll', 'iphlpapi.dll',
  'wpcap.dll', 'pdh.dll', 'dnsapi.dll', 'crypt32.dll', 'ncrypt.dll', 'bcrypt.dll',
  'setupapi.dll', 'user32.dll', 'gdi32.dll', 'shell32.dll', 'shlwapi.dll', 'ole32.dll',
  'oleaut32.dll', 'netapi32.dll', 'version.dll', 'winmm.dll', 'userenv.dll',
  'ntmarta.dll', 'secur32.dll', 'mswsock.dll', 'wldap32.dll', 'wininet.dll',
  'winhttp.dll', 'winspool.drv'
$imports = @()
$dd = if ($is64) { $opt + 112 } else { $opt + 96 }
$impRva = U32 $b ($dd + 8)
function Rva2Off([int]$rva) {
  $secStart = $opt + $optSize
  for ($s = 0; $s -lt $numSec; $s++) {
    $so = $secStart + $s * 40
    $vsize = U32 $b ($so + 8)
    $vaddr = U32 $b ($so + 12)
    $rawSize = U32 $b ($so + 16)
    $rawPtr = U32 $b ($so + 20)   # PointerToRawData (NOT SizeOfRawData)
    $len = [Math]::Max($vsize, $rawSize)
    if ($rva -ge $vaddr -and $rva -lt ($vaddr + $len)) { return ($rawPtr + ($rva - $vaddr)) }
  }
  return -1
}
if ($impRva -gt 0) {
  $o = Rva2Off $impRva
  if ($o -ge 0) {
    while ($true) {
      $nameRva = U32 $b ($o + 12)
      if ($nameRva -eq 0) { break }
      $no = Rva2Off $nameRva
      if ($no -lt 0) { break }
      $e = $no
      while ($e -lt $b.Length -and $b[$e] -ne 0) { $e++ }
      $imports += ([System.Text.Encoding]::ASCII.GetString($b, $no, $e - $no)).ToLower()
      $o += 20
      if ($o -ge $b.Length - 20) { break }
    }
  }
}
$foreign = @($imports | Where-Object { $sysDlls -notcontains $_ })
Check 'static-imports' ($imports.Count -gt 0 -and $foreign.Count -eq 0) ("{0} imports: {1}" -f $imports.Count, ($imports -join ','))

# ---------- -version flag (ldflags -X) ----------
$verOut = ''
try { $verOut = (& $Exe -version 2>&1 | Out-String).Trim() } catch { $verOut = 'ERR ' + $_.Exception.Message }
Check 'cli-version' ($verOut -match [regex]::Escape($Version)) $verOut

# ---------- embedded version resource (UTF-16LE) ----------
# FileDescription = ????????? ; ProductName = Yugsight ??
$desc = Cps @(0x5B89, 0x5168, 0x8FD0, 0x7EF4, 0x4E00, 0x4F53, 0x5316, 0x5E73, 0x53F0)
$prod = 'Yugsight ' + (Cps @(0x5FA1, 0x89C6))
Check 'resource-filedesc' ((Find-Bytes $b ([System.Text.Encoding]::Unicode.GetBytes($desc))) -ge 0) 'FileDescription'
Check 'resource-product' ((Find-Bytes $b ([System.Text.Encoding]::Unicode.GetBytes($prod))) -ge 0) 'ProductName'
Check 'resource-version' ((Find-Bytes $b ([System.Text.Encoding]::Unicode.GetBytes($Version))) -ge 0) ("version string $Version")
Check 'resource-company' ((Find-Bytes $b ([System.Text.Encoding]::Unicode.GetBytes('Yugsight Project'))) -ge 0) 'CompanyName'

# ---------- signature ----------
if ($RequireSign -eq '1') {
  $asig = Get-AuthenticodeSignature $Exe
  $okSig = ($asig.Status -eq 'Valid') -or ($asig.Status -eq 'Trusted')
  Check 'signature-valid' $okSig ("Authenticode status={0}" -f $asig.Status)
  $signer = ''
  if ($asig.SignerCertificate) { $signer = $asig.SignerCertificate.Subject }
  Check 'signer-local-cert' ($signer -like '*Yugsight*') ("signer={0}" -f $signer)
}

Write-Host ''
if ($script:fail -eq 0) { Write-Host 'VERIFY: ALL CHECKS PASSED' } else { Write-Host ('VERIFY: {0} CHECK(S) FAILED' -f $script:fail) }
exit $script:fail

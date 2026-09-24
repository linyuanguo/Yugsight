@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Yugsight AV-resistance build
rem ==========================================================================
rem  Yugsight AV-resistance build (Windows batch)
rem
rem  What it does, in order:
rem   1. build sandbox : GOTMPDIR + GOCACHE under .\build_tmp - every
rem                      intermediate (.a/.o/tmp exes) stays in-project,
rem                      nothing lands in the high-watch %LOCALAPPDATA%\Temp
rem   2. compile flags : CGO_ENABLED=0 (pure static), default (non-PIE) exe
rem                      mode, no -trimpath (keep build path in binary),
rem                      -s -w by default (/keepsym disables),
rem                      -X main.appVersion from VERSION
rem   3. resources     : icon + full VERSIONINFO (product name, file
rem                      description, versions, company) embedded via
rem                      windres rsrc.syso
rem   4. obfuscation   : garble fingerprint obfuscation (optional: /noobf;
rem                      /nolit = without string literal obfuscation, much
rem                      smaller binary)
rem   5. signing       : offline self-signed code cert + signtool
rem                      (/nosign to disable)
rem   6. verify        : PE structure / imports / version / resources /
rem                      signature (scripts\av_verify.ps1)
rem   7. smoke test    : boot on a free loopback port, /api/info, /app/,
rem                      POST /api/quit, graceful exit (scripts\av_smoke.ps1)
rem
rem  Usage:
rem    scripts\build_av.bat                 full pipeline (default)
rem    scripts\build_av.bat /noobf          native go build, no garble
rem    scripts\build_av.bat /nolit          garble without literal obfuscation
rem    scripts\build_av.bat /keepsym        keep symbols and debug info
rem    scripts\build_av.bat /nosign         skip self-signing
rem    scripts\build_av.bat /notest         skip functional smoke test
rem    scripts\build_av.bat /clean          wipe build_tmp (Go cache) first
rem    scripts\build_av.bat /out D:\x       custom output dir (default .\bin)
rem
rem  Rollback: every step is a switch above; the regular release build
rem  (scripts\build.ps1) is untouched.
rem
rem  NOTE: add .\build_tmp and .\bin to your antivirus trust zone before the
rem  first run, otherwise real-time protection may quarantine intermediates.
rem ==========================================================================

set "ROOT=%~dp0.."
pushd "%ROOT%" >nul
if errorlevel 1 (
  echo [ERR] cannot locate repo root
  exit /b 1
)

set "DO_OBF=1"
set "OBF_LIT=1"
set "DO_SIGN=1"
set "DO_TEST=1"
set "STRIP_SYM=1"
set "DO_CLEAN=0"
set "OUTDIR=%ROOT%\bin"
set "MODE="
set "SIGNED=no"
set "GARBLE_OK=0"

:parse
if "%~1"=="" goto parsed
if /i "%~1"=="help" goto usage
if /i "%~1"=="/?" goto usage
set "sw=%~1"
if "%sw:~0,1%" neq "/" goto unknown
set "sw=%sw:~1%"
if /i "%sw%"=="noobf"   set "DO_OBF=0"    & shift & goto parse
if /i "%sw%"=="nolit"   set "OBF_LIT=0"   & shift & goto parse
if /i "%sw%"=="nosign"  set "DO_SIGN=0"   & shift & goto parse
if /i "%sw%"=="keepsym" set "STRIP_SYM=0" & shift & goto parse
if /i "%sw%"=="notest"  set "DO_TEST=0"   & shift & goto parse
if /i "%sw%"=="clean"   set "DO_CLEAN=1"  & shift & goto parse
if /i "%sw%"=="out" (
  shift
  if "%~1"=="" (
    echo /out requires a directory
    goto unknown
  )
  set "OUTDIR=%~1"
  shift
  goto parse
)
:unknown
echo Unknown switch: %~1
goto usage
:parsed

echo.
echo =============== Yugsight AV-resistance build ===============
echo  root : %ROOT%
echo  out  : %OUTDIR%\yugsight.exe
echo  obf  : %DO_OBF% (literals=%OBF_LIT%)   sign : %DO_SIGN%   test : %DO_TEST%
echo  symbols stripped : %STRIP_SYM%   clean cache : %DO_CLEAN%
echo.

rem ---------- preflight ----------
where go >nul 2>&1 || goto err_go
where windres >nul 2>&1 || goto err_windres
if not exist "build\icon_full.rc" (
  echo [ERR] build\icon_full.rc missing
  exit /b 1
)
if not exist "frontend\dist\index.html" (
  echo [ERR] frontend\dist missing - run "cd frontend" then "npm run build" first
  exit /b 1
)
if not exist "VERSION" (
  echo [ERR] VERSION missing
  exit /b 1
)
set /p VER=<VERSION
if "%VER%"=="" (
  echo [ERR] VERSION is empty
  exit /b 1
)
echo version: v%VER%

rem ---------- step 1: build sandbox (all intermediates in-project) ----------
if "%DO_CLEAN%"=="1" if exist "build_tmp" rmdir /s /q "build_tmp"
if not exist "build_tmp\tmp"   mkdir "build_tmp\tmp"
if not exist "build_tmp\cache" mkdir "build_tmp\cache"
if not exist "build_tmp\sign"  mkdir "build_tmp\sign"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
set "GOTMPDIR=%ROOT%\build_tmp\tmp"
set "GOCACHE=%ROOT%\build_tmp\cache"
set "CGO_ENABLED=0"
set "GOOS=windows"
set "GOARCH=amd64"
echo [1/7] build sandbox: GOTMPDIR=%GOTMPDIR%
echo               GOCACHE=%GOCACHE%  CGO_ENABLED=0 (pure static)

rem ---------- step 2: version resource (rsrc.syso) ----------
rem windres (TDM-GCC binutils) reads .rc in the system ANSI code page (GBK);
rem the UTF-8 BOM template is re-encoded to GBK before compiling.
powershell -NoProfile -Command "$t = Get-Content -Raw -Encoding UTF8 'build\icon_full.rc'; $v = '%VER%'; $t = $t.Replace('__VERNUM__', (($v -split '\.') -join ',')).Replace('__VER__', $v); [IO.File]::WriteAllText('build_tmp\icon_gen.rc', $t, [Text.Encoding]::GetEncoding('GBK'))"
if errorlevel 1 (
  echo [ERR] resource .rc generation failed
  exit /b 1
)
windres --target=pe-x86-64 -I "%ROOT%" -i "build_tmp\icon_gen.rc" -O coff -o "build_tmp\rsrc.syso"
if errorlevel 1 (
  echo [ERR] windres failed
  exit /b 1
)
rem Go links .syso from the package dir; it must not stay in the repo
rem (a stray rsrc.syso in the root breaks linux/darwin cross builds).
copy /y "build_tmp\rsrc.syso" "rsrc.syso" >nul
echo [2/7] resource: rsrc.syso generated (icon + VERSIONINFO, UTF-16LE Chinese)

rem ---------- step 3: garble availability ----------
call :garble_check
echo [3/7] obfuscation mode: %MODE%

rem ---------- step 4: compile ----------
set "LDFLAGS="
if "%STRIP_SYM%"=="1" set "LDFLAGS=-s -w"
set "LDFLAGS=%LDFLAGS% -X main.appVersion=%VER%"
set "OUTEXE=%OUTDIR%\yugsight.exe"
if exist "%OUTEXE%" del /q "%OUTEXE%"
set "BUILDLOG=%ROOT%\build_tmp\build.log"

if "%GARBLE_OK%"=="1" (
  set "GFLAGS="
  if "%OBF_LIT%"=="1" set "GFLAGS=-literals"
  rem -buildmode=exe: Go 1.15+ defaults to PIE on windows/amd64; the plan
  rem requires non-PIE (DYNAMIC_BASE off) to lower heuristic weight.
  echo [4/7] building with garble !GFLAGS! ...
  "!GARBLE!" !GFLAGS! build -buildmode=exe -ldflags "%LDFLAGS%" -o "%OUTEXE%" . >"%BUILDLOG%" 2>&1
  if errorlevel 1 goto err_build
) else (
  echo [4/7] building with native go build ...
  go build -buildmode=exe -ldflags "%LDFLAGS%" -o "%OUTEXE%" . >"%BUILDLOG%" 2>&1
  if errorlevel 1 goto err_build
)
if not exist "%OUTEXE%" goto err_build
if exist "rsrc.syso" del /q "rsrc.syso"
for %%s in ("%OUTEXE%") do set "EXESIZE=%%~zs"
echo [4/7] built %OUTEXE%  (%EXESIZE% bytes)

rem ---------- step 5: sign (before verify: verify checks the signature) ----------
if "%DO_SIGN%"=="1" (
  echo [5/7] signing with local self-signed certificate ...
  powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\av_sign.ps1" -Exe "%OUTEXE%" -PfxDir "%ROOT%\build_tmp\sign"
  if errorlevel 1 goto err_sign
  set "SIGNED=yes"
)

rem ---------- step 6: verify ----------
echo [6/7] verifying binary ...
if "%DO_SIGN%"=="1" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\av_verify.ps1" -Exe "%OUTEXE%" -Version "%VER%" -RequireSign 1
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\av_verify.ps1" -Exe "%OUTEXE%" -Version "%VER%" -RequireSign 0
)
if errorlevel 1 goto err_verify

rem ---------- step 7: smoke test ----------
if "%DO_TEST%"=="1" (
  echo [7/7] functional smoke test ...
  set "HAD_DATA=0"
  if exist "%OUTDIR%\data" set "HAD_DATA=1"
  set "HAD_LOG=0"
  if exist "%OUTDIR%\logs" set "HAD_LOG=1"
  set "HAD_LOGF=0"
  if exist "%OUTDIR%\yugsight.log" set "HAD_LOGF=1"
  set "HAD_VULN=0"
  if exist "%OUTDIR%\vuln" set "HAD_VULN=1"
  powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\av_smoke.ps1" -Exe "%OUTEXE%" -Version "%VER%" -Log "%ROOT%\build_tmp\smoke.log"
  if errorlevel 1 goto err_smoke
  rem clean smoke-test runtime residue (only what this run created);
  rem retry once: AV real-time protection may hold fresh dirs/files.
  call :smoke_cleanup
  call :smoke_cleanup
)

rem ---------- summary ----------
echo.
echo ========================= SUMMARY =========================
echo  artifact : %OUTEXE%
echo  size     : %EXESIZE% bytes
echo  version  : v%VER%
echo  mode     : %MODE%
echo  signed   : %SIGNED%
echo.
echo  Manual AV scan (Huorong has no command-line scanner):
echo   1. Trust .\build_tmp and .\bin in Huorong (right-click folder - Trust)
echo   2. Right-click yugsight.exe - Huorong - Scan selected / Full scan
echo   3. Expect no HackTool/VcenterKiller alert and no auto delete
echo   4. If still flagged: retry with /keepsym, then /noobf + /keepsym
echo.
exit /b 0

rem ================= subroutines / error paths =================

:smoke_cleanup
if "%HAD_DATA%"=="0" if exist "%OUTDIR%\data" rmdir /s /q "%OUTDIR%\data"
if "%HAD_LOG%"=="0" if exist "%OUTDIR%\logs" rmdir /s /q "%OUTDIR%\logs"
if "%HAD_VULN%"=="0" if exist "%OUTDIR%\vuln" rmdir /s /q "%OUTDIR%\vuln"
if "%HAD_LOGF%"=="0" if exist "%OUTDIR%\yugsight.log" del /q "%OUTDIR%\yugsight.log"
exit /b 0

:garble_check
set "MODE=native"
if "%DO_OBF%"=="0" goto garble_done
set "GARBLE="
for /f "delims=" %%g in ('go env GOPATH 2^>nul') do set "GOPATHD=%%g"
if defined GOPATHD if exist "!GOPATHD!\bin\garble.exe" set "GARBLE=!GOPATHD!\bin\garble.exe"
if not defined GARBLE for /f "delims=" %%g in ('where garble 2^>nul') do if not defined GARBLE set "GARBLE=%%g"
if not defined GARBLE (
  echo [WARN] garble not found - install once: go install mvdan.cc/garble@latest
  echo [WARN] falling back to native go build
  goto garble_done
)
rem garble v0.18 needs go 1.27+ with a GOROOT outside the module cache
rem (garble overlays linker sources in GOROOT; module-cache copies rejected).
set "SYS_GO_OK=0"
for /f "tokens=3" %%g in ('go version 2^>nul') do set "GOVER=%%g"
set "GM=0"
set "GN=0"
for /f "tokens=1,2 delims=." %%a in ("!GOVER!") do (
  set "GM=%%a"
  set "GN=%%b"
)
set "GM=!GM:go=!"
if !GM! GEQ 2 set "SYS_GO_OK=1"
if !GM! EQU 1 if !GN! GEQ 27 set "SYS_GO_OK=1"
set "GOROOTD="
for /f "delims=" %%g in ('go env GOROOT 2^>nul') do set "GOROOTD=%%g"
if defined GOROOTD (
  set "GOROOT_CLEAN=!GOROOTD:pkg\mod=!"
  if "!GOROOT_CLEAN!" neq "!GOROOTD!" set "SYS_GO_OK=0"
)
if !SYS_GO_OK! EQU 1 (
  set "MODE=garble"
  if "%OBF_LIT%"=="1" set "MODE=garble-literals"
  set "GARBLE_OK=1"
  goto garble_done
)
rem standalone go1.27.1: copy from the module cache if present (no download)
set "TC=%GOPATHD%\go1.27.1"
if not exist "!TC!\bin\go.exe" (
  echo [INFO] preparing standalone go1.27.1 at !TC!
  if not exist "!TC!" mkdir "!TC!"
  for /f "delims=" %%d in ('dir /b /ad "!GOPATHD!\pkg\mod\golang.org\toolchain@*go1.27.1.windows-amd64" 2^>nul') do (
    if exist "!GOPATHD!\pkg\mod\golang.org\%%d\bin\go.exe" xcopy /e /i /q /y /h "!GOPATHD!\pkg\mod\golang.org\%%d" "!TC!" >nul
  )
)
if exist "!TC!\bin\go.exe" (
  set "PATH=!TC!\bin;!PATH!"
  set "MODE=garble"
  if "%OBF_LIT%"=="1" set "MODE=garble-literals"
  set "GARBLE_OK=1"
  goto garble_done
)
echo [WARN] garble needs go 1.27+ outside the module cache - expected: !TC!
echo [WARN] falling back to native go build
goto garble_done
:garble_done
exit /b 0

:err_build
echo [ERR] build failed - tail of %BUILDLOG%:
powershell -NoProfile -Command "Get-Content -Tail 25 '%BUILDLOG%' -ErrorAction SilentlyContinue"
if exist "rsrc.syso" del /q "rsrc.syso"
exit /b 1
:err_sign
echo [ERR] self-signing failed - use /nosign to skip signing, or check signtool/PFX
exit /b 1
:err_verify
echo [ERR] binary verification failed
exit /b 1
:err_smoke
echo [ERR] smoke test failed - see build_tmp\smoke.log and smoke.log.err
exit /b 1
:err_go
echo [ERR] go not found in PATH
exit /b 1
:err_windres
echo [ERR] windres not found in PATH (TDM-GCC / MinGW required)
exit /b 1
:usage
echo Usage: scripts\build_av.bat [switches]
echo   /noobf    native go build (no garble)
echo   /nolit    garble without string literal obfuscation (smaller)
echo   /keepsym  keep symbol tables and debug info (no -s -w)
echo   /nosign   skip self-signing
echo   /notest   skip functional smoke test
echo   /clean    wipe build_tmp (Go build cache) first
echo   /out DIR  custom output directory (default .\bin)
exit /b 0

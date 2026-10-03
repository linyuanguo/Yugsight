# build-agents.ps1 交叉编译各平台探针(yugsight-agent)并放入 dist/data/agents 目录。
#
# 用途: 中心端 Web 的"探针管理 -> 下载探针"从 exe 同目录 data/agents/ 读取安装包
# (见 probe_agent_download.go)。本脚本一次性产出全部平台包, 免去逐个设置
# GOOS/GOARCH 手敲命令时极易写错的平台名与文件名。
#
# 命名约定(必须一致, 否则中心端识别不到):
#   data/agents/yugsight-agent_{os}_{arch}[.exe]
#
# 【2026-09-29 用户要求】探针构建产物直接输出到 dist/data/agents(运行目录) ——
# 先是不再放仓库根 agents/(仓库根只留源码), 后又随 data/ 归拢: 探针包与 cert/
# 一并收进 data 目录, dist 根目录只留可执行与资源。
#
# 用法:
#   pwsh -File scripts/build-agents.ps1              # 默认 amd64 双平台(windows+linux)
#   pwsh -File scripts/build-agents.ps1 -IncludeArm64    # 额外产出 arm64 包
#   pwsh -File scripts/build-agents.ps1 -Version 1.0.0 -OutDir dist\data\agents

param(
    # 输出目录(默认 dist/data/agents, 与中心端运行目录一致)
    [string]$OutDir = (Join-Path $PSScriptRoot '..\dist\data\agents'),
    # 版本号仅用于日志提示, 不参与文件名(文件名带版本会让中心端匹配逻辑复杂化;
    # 探针版本由 agent 自身 -version 与注册时上报的 NodeInfo.Version 体现)
    [string]$Version = '1.0.0',
    # 额外产出 arm64 探针包(默认不产: 实际几乎用不到, 白占磁盘)
    [switch]$IncludeArm64
)

$ErrorActionPreference = 'Stop'

# 平台矩阵只能取 probe_agent_download.go 的 agentPlatforms 的子集:
# 多出白名单之外的平台 -> 中心端不认(会落到"未识别"只列不下载)。
#
# 默认只编 amd64: 实际部署里 arm64 机器很少(Windows ARM 终端基本见不到, x86 服务器
# 占绝对多数), 每次全量交叉编译要白产 3 个包占 20MB 磁盘。
# **注意这是"默认构建范围"而非"支持范围"** —— 白名单仍是 6 个平台, 需要 arm64 探针时
# 用 -IncludeArm64 产出即可, 中心端拿到就能分发; 若把白名单一起删掉, 以后想给 ARM 机器
# 装探针会被中心端 400 直接拒绝(而且白名单同时兼作目录穿越防护, 不能随手砍)。
# 【2026-09-29 用户明确要求】探针只保留 linux + windows 两种, 默认不再产 darwin(macOS)。
$Targets = @(
    @{ OS = 'windows'; Arch = 'amd64'; Ext = '.exe' },
    @{ OS = 'linux';   Arch = 'amd64'; Ext = '' }
)
if ($IncludeArm64) {
    $Targets += @(
        @{ OS = 'windows'; Arch = 'arm64'; Ext = '.exe' },
        @{ OS = 'linux';   Arch = 'arm64'; Ext = '' }
    )
}

# 仓库根目录(本脚本在 scripts/ 下, 上一级即根)
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
# 用绝对路径拼目录: 相对路径在 PowerShell 里基于进程 cwd 而非脚本所在目录,
# 从别处调用会创建到意外的位置(项目历史踩过的坑)。
$OutAbs = $OutDir
if (-not [System.IO.Path]::IsPathRooted($OutAbs)) {
    $OutAbs = Join-Path $Root $OutDir
}
if (-not (Test-Path $OutAbs)) {
    New-Item -ItemType Directory -Force -Path $OutAbs | Out-Null
}

# ===== 版本号注入 =====
# 探针版本必须与中心端同源(仓库根 VERSION): 中心端拿 appVersion 与探针注册时
# 上报的版本比对, 相等才判"无需更新"。此前 agent 恒报硬编码 1.0.0, 中心端每次
# 注册都下发更新指令, 探针重启后还是 1.0.0 —— 死循环。
#
# 这里**只读不自增**(自增是中心端构建 build.ps1 的职责): 显式 -Version 优先;
# 未显式指定时读 VERSION 当前值; 读失败退回 1.0.0(与 main.go 兜底值一致)。
$VersionArg = $Version
if (-not $PSBoundParameters.ContainsKey('Version')) {
    try {
        $verScript = Join-Path $PSScriptRoot 'version.ps1'
        $v = (& $verScript) -join ''
        $v = $v.Trim()
        if ($v -ne '') { $VersionArg = $v }
    } catch {
        Write-Host "警告: 读取 VERSION 失败($_), 本次构建使用兜底版本 1.0.0" -ForegroundColor Yellow
    }
}

Write-Host "Yugsight 探针构建 v$VersionArg" -ForegroundColor Cyan
Write-Host "输出目录: $OutAbs"
Write-Host ''

# CGO_ENABLED=0: 纯静态链接。探针会部署到各种发行版的精简镜像里,
# 依赖 glibc 动态链接的产物很容易出现 "not found" 类加载失败。
$env:CGO_ENABLED = '0'
$failed = 0

foreach ($t in $Targets) {
    $env:GOOS = $t.OS
    $env:GOARCH = $t.Arch
    $name = "yugsight-agent_$($t.OS)_$($t.Arch)$($t.Ext)"
    $out = Join-Path $OutAbs $name

    # -trimpath 去掉构建机绝对路径; -s -w 去符号表与调试信息(体积可省 25% 左右)
    # -X main.agentVersion=: 与中心端同源注入(见上方版本号注入说明)。agent 入口也是
    # package main, 链接器对 main 包固定用 "main" 作 import path(与主程序同一口径)。
    # 注意: -X 静默失败不报错, 构建后对当前平台产物跑 -version 校验(见循环后)。
    $ldflags = '-s -w -X main.agentVersion=' + $VersionArg
    & go build -trimpath -ldflags $ldflags -o $out ./cmd/agent 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkYellow }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL  $($t.OS)/$($t.Arch)" -ForegroundColor Red
        $failed++
        continue
    }
    $size = [math]::Round((Get-Item $out).Length / 1MB, 2)
    Write-Host ("OK    {0,-8} {1,-6} {2,7} MB  {3}" -f $t.OS, $t.Arch, $size, $name) -ForegroundColor Green
}

# 版本注入校验(同 build.ps1 的教训: -X 链接变量失败时 Go 不报错, 变量保持源码兜底
# 值, 表现为"构建成功但探针版本一直是 1.0.0" —— 中心端据此永远下发更新指令)。
# 交叉编译的产物无法在本机执行, 只校验当前平台(Windows)那一份。
if ($env:OS -eq 'Windows_NT' -and (Test-Path (Join-Path $OutAbs 'yugsight-agent_windows_amd64.exe'))) {
    try {
        $actual = (& (Join-Path $OutAbs 'yugsight-agent_windows_amd64.exe') -version 2>&1 | Out-String).Trim()
        if ($actual -match [regex]::Escape($VersionArg)) {
            Write-Host "版本校验: 探针产物报告 v$VersionArg (与 VERSION 一致)" -ForegroundColor Green
        } else {
            Write-Host "警告: 探针版本号校验未通过 — 期望含 '$VersionArg', 实际输出: $actual" -ForegroundColor Yellow
            Write-Host "      请检查 cmd/agent/main.go 里 agentVersion 是否为 var(链接器无法改写 const)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "警告: 版本校验未执行($_)" -ForegroundColor Yellow
    }
}

# 恢复环境变量, 避免影响调用者后续的 go build(否则会意外产出别平台的主程序)
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host ''
if ($failed -gt 0) {
    Write-Host "完成: $($Targets.Count - $failed)/$($Targets.Count) 成功, $failed 个失败" -ForegroundColor Red
    exit 1
}
Write-Host "完成: $($Targets.Count)/$($Targets.Count) 全部成功" -ForegroundColor Green
Write-Host '启动中心端后, 在 Web 的「探针管理 -> 下载探针」即可获取这些安装包。'

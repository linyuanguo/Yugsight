# build-agents.ps1 交叉编译各平台探针(yugsight-agent)并放入 agents/ 目录。
#
# 用途: 中心端 Web 的"探针管理 -> 下载探针"从 exe 同目录 agents/ 读取安装包
# (见 probe_agent_download.go)。本脚本一次性产出全部平台包, 免去逐个设置
# GOOS/GOARCH 手敲命令时极易写错的平台名与文件名。
#
# 命名约定(必须一致, 否则中心端识别不到):
#   agents/yugsight-agent_{os}_{arch}[.exe]
#
# 用法:
#   pwsh -File scripts/build-agents.ps1              # 默认 amd64 三平台
#   pwsh -File scripts/build-agents.ps1 -IncludeArm64    # 额外产出 arm64 包
#   pwsh -File scripts/build-agents.ps1 -Version 1.0.0 -OutDir agents

param(
    # 输出目录(默认仓库根目录下的 agents/)
    [string]$OutDir = (Join-Path $PSScriptRoot '..\agents'),
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
$Targets = @(
    @{ OS = 'windows'; Arch = 'amd64'; Ext = '.exe' },
    @{ OS = 'linux';   Arch = 'amd64'; Ext = '' },
    @{ OS = 'darwin';  Arch = 'amd64'; Ext = '' }
)
if ($IncludeArm64) {
    $Targets += @(
        @{ OS = 'windows'; Arch = 'arm64'; Ext = '.exe' },
        @{ OS = 'linux';   Arch = 'arm64'; Ext = '' },
        @{ OS = 'darwin';  Arch = 'arm64'; Ext = '' }
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

Write-Host "Yugsight 探针构建 v$Version" -ForegroundColor Cyan
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
    & go build -trimpath -ldflags '-s -w' -o $out ./cmd/agent 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkYellow }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL  $($t.OS)/$($t.Arch)" -ForegroundColor Red
        $failed++
        continue
    }
    $size = [math]::Round((Get-Item $out).Length / 1MB, 2)
    Write-Host ("OK    {0,-8} {1,-6} {2,7} MB  {3}" -f $t.OS, $t.Arch, $size, $name) -ForegroundColor Green
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

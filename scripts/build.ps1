# build.ps1 构建 Yugsight 中心端主程序(默认当前平台; -All 一次产出四平台)并可选一并产出探针包。
#
# ===== 为什么需要这个脚本 =====
#
# 【核心坑: -H windowsgui 会让控制台消失】
# Windows 下 Go 有两个子系统:
#   - console(默认)         : 进程带控制台窗口, 日志实时打印到窗口
#   - windowsgui(-H windowsgui): **完全不分配控制台**, 没有黑框
#
# 本项目当前设计是"控制台窗口即服务界面"(见 console_windows.go 与 main.go):
# 日志打到 stdout, 关窗/Ctrl+C 即停止服务。所以**必须用默认 console 子系统构建**。
#
# 一旦误加 -H windowsgui:
#   进程照常运行、Web 页面照常打开、功能全对 —— 唯独任务栏看不到任何窗口,
#   用户以为"服务没在跑"或"程序有问题", 日志也看不到。这个现象极具误导性,
#   因为程序实际上是一切正常的。项目早期用过 -H windowsgui + 自绘任务栏窗口,
#   自绘窗口因原生崩溃(0xC0000005)被移除后才改回控制台方案, 构建参数必须跟着改。
#   (回归护栏: console_subsystem_test.go 直接读 PE 头断言子系统必须是 console)
#
# 【Linux 服务端】中心端可以跑在 Linux 上(常见部署形态), 用 -All 一次产出
# windows/linux/darwin 三平台 amd64 主程序到 -OutDir; 只想要 Linux 时用
#   powershell -File scripts/build.ps1 -Targets linux/amd64
# 产物名统一带平台后缀(yugsight_windows_amd64.exe), **只产这一个, 不再另存短名
# yugsight.exe** —— 两个不同进程名的二进制并存会导致旧实例占住端口提供旧路由表
# (详见循环内注释), 用户已明确要求保持单一产物名。
#
# 【arm64 默认不产】arm64 机器在实际部署里很少, 全量编译会白产 3 个 12MB 主程序。
# 需要时用 -IncludeArm64, 或 -Targets linux/arm64 单独指定。
#
# 用法:
#   powershell -File scripts/build.ps1                        # 只构建当前平台主程序
#   powershell -File scripts/build.ps1 -All                   # 构建 amd64 三平台主程序
#   powershell -File scripts/build.ps1 -All -IncludeArm64     # 额外含 arm64
#   powershell -File scripts/build.ps1 -Targets linux/amd64   # 只构建指定平台
#   powershell -File scripts/build.ps1 -Agents                # 顺带产出探针包
#   powershell -File scripts/build.ps1 -OutDir dist           # 指定输出目录

param(
    # 输出目录(默认仓库根目录; 产物名 yugsight[_os_arch].exe 与配置文件名约定一致)
    [string]$OutDir = '',
    # 是否一并交叉编译探针包(调用 scripts/build-agents.ps1)
    [switch]$Agents,
    # 构建全部平台的主程序(等价于 -Targets 全矩阵)
    [switch]$All,
    # 指定平台列表, 形如 "linux/amd64,linux/arm64"; 与 -All 二选一
    [string[]]$Targets = @(),
    # 探针包输出目录(仅 -Agents 生效)
    [string]$AgentsOutDir = '',
    # -All 时额外包含 arm64(默认不含: 实际几乎用不到, 白占磁盘)
    [switch]$IncludeArm64,
    # 不自动递增版本号(默认每次构建都会把 VERSION 末位 +1 并注入二进制)
    [switch]$NoBumpVersion,
    # 不把注入的版本号写回 VERSION 文件(只影响本次构建产物; 便于试构建不留痕)
    [switch]$VersionDryRun
)

$ErrorActionPreference = 'Stop'

# 仓库根目录: 本脚本在 scripts/ 下, 上一级即根。
# 用绝对路径 —— 相对路径在 PowerShell 里基于进程 cwd 而非脚本目录, 从别处调用会错位。
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
# 默认输出到 dist/: 源码仓库与"运行时目录"必须分开。
# 程序全程以 os.Executable() 的目录作配置根(engine.json / probe.json / bin/ / data/ /
# 日志 ...), 所以 exe 放哪, 运行期文件就落在哪 —— 把 exe 固定放 dist/ 就天然实现了
# 分离, 不必改一行 Go 代码。以前默认输出到仓库根, 结果 .go 源码和 exe/log/json 混在
# 一起, 分不清哪些是"要提交的源码"哪些是"跑出来的东西"。
$OutAbs = if ([string]::IsNullOrWhiteSpace($OutDir)) { Join-Path $Root 'dist' } else {
    if ([System.IO.Path]::IsPathRooted($OutDir)) { $OutDir } else { Join-Path $Root $OutDir }
}
if (-not (Test-Path $OutAbs)) {
    New-Item -ItemType Directory -Force -Path $OutAbs | Out-Null
}

# ===== 卫生清理: 输出目录里的 *~ 旧备份 =====
# 历史构建/手工备份会把旧二进制改名成 *.exe~ 留在输出目录(如
# yugsight_windows_amd64.exe~)。这类文件无任何进程引用, 留着只会让交付目录
# 出现"到底双击哪个"的歧义, 每次构建前统一清掉。
# 用 Where-Object 而非 -Filter '*~': 实测 -Filter 通配在部分环境抛
# Win32Exception(找不到文件), Where-Object 更稳。
Get-ChildItem -Path $OutAbs -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like '*~' } |
    Remove-Item -Force -ErrorAction SilentlyContinue

# ===== 目标平台矩阵 =====
# 与探针包矩阵(scripts/build-agents.ps1)保持同一口径: 两者默认都只编 amd64, 都用
# 各自的 -IncludeArm64 扩展。中心端跑在哪个平台, 就要能在那个平台分发探针, 两套
# 列表不一致会让"我明明构建了中心端却拿不到某平台探针"。
# 默认只含 amd64: arm64 服务器/终端在实际部署中很少, 全量编译白产 3 个 12MB 主程序。
# 需要 arm64 时用 -Targets windows/arm64,linux/arm64 显式指定(也可 -IncludeArm64)。
$AllTargets = @(
    @{ OS = 'windows'; Arch = 'amd64'; Ext = '.exe' },
    @{ OS = 'linux';   Arch = 'amd64'; Ext = '' },
    @{ OS = 'darwin';  Arch = 'amd64'; Ext = '' }
)
if ($IncludeArm64) {
    $AllTargets += @(
        @{ OS = 'windows'; Arch = 'arm64'; Ext = '.exe' },
        @{ OS = 'linux';   Arch = 'arm64'; Ext = '' },
        @{ OS = 'darwin';  Arch = 'arm64'; Ext = '' }
    )
}

function Resolve-Targets {
    param([switch]$All, [string[]]$Targets)
    if ($All -and $Targets.Count -gt 0) {
        Write-Host '-All 与 -Targets 不能同时使用' -ForegroundColor Red
        exit 1
    }
    if ($All) { return $AllTargets }
    if ($Targets.Count -eq 0) {
        # 未指定 = 只构建当前平台(沿用历史行为, 避免无意间跑 6 次完整构建)
        $goos = if ($env:GOOS) { $env:GOOS } else { 'windows' }
        $goarch = if ($env:GOARCH) { $env:GOARCH } else {
            if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { '386' }
        }
        $ext = if ($goos -eq 'windows') { '.exe' } else { '' }
        return @(@{ OS = $goos; Arch = $goarch; Ext = $ext })
    }
    $out = @()
    foreach ($t in $Targets) {
        $parts = $t.Split('/')
        if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
            Write-Host "平台格式错误: '$t'(应为 os/arch, 如 linux/amd64)" -ForegroundColor Red
            exit 1
        }
        $ext = if ($parts[0] -eq 'windows') { '.exe' } else { '' }
        $out += @{ OS = $parts[0].Trim(); Arch = $parts[1].Trim(); Ext = $ext }
    }
    return $out
}

$Matrix = Resolve-Targets -All:$All -Targets $Targets

# ===== 版本号 =====
# 【为什么构建时自增】用户要求"每次更新版本号 +1"(规则: 末位 +1, 到 9 则进位
# 1.0.9 -> 1.0.10)。版本号放在仓库根 VERSION 纯文本文件里, 由 scripts/version.ps1
# 维护 —— 不拿"上次构建产物"推断版本, 因为产物会被删/被拷走/被手工替换,
# 那样会出现版本号回退或卡住不动。
#
# 注入方式: -ldflags "-X main.appVersion=<ver>"。因此 main.go 里 appVersion 必须是
# **var 而非 const**(链接器只能改写变量)。
#
# -NoBumpVersion 用于"只想重新编译一次、不想动版本号"的场景(如反复调试构建参数);
# -VersionDryRun 则用于"试构建但不留痕"。两者都不写回 VERSION 文件。
$VersionArg = $null
try {
    $verScript = Join-Path $PSScriptRoot 'version.ps1'
    if ($NoBumpVersion) {
        $VersionArg = (& $verScript) -join ''
        $VersionArg = $VersionArg.Trim()
    } elseif ($VersionDryRun) {
        $VersionArg = (& $verScript -Bump -DryRun) -join ''
        $VersionArg = $VersionArg.Trim()
    } else {
        $VersionArg = (& $verScript -Bump) -join ''
        $VersionArg = $VersionArg.Trim()
    }
} catch {
    # 版本号获取失败不该让整个构建挂掉: 退回 main.go 里的兜底值, 但明确告警
    Write-Host "警告: 版本号获取失败($_), 本次构建使用 main.go 内的兜底版本" -ForegroundColor Yellow
    $VersionArg = ''
}

Write-Host 'Yugsight 中心端构建' -ForegroundColor Cyan
Write-Host "输出目录: $OutAbs"
if ($VersionArg -ne '') {
    Write-Host "版本号:   v$VersionArg$(if ($NoBumpVersion) { ' (未自增)' } elseif ($VersionDryRun) { ' (试构建, 未写回 VERSION)' } else { " (VERSION 已更新)" })" -ForegroundColor Cyan
}
Write-Host ''

# 图标资源(rsrc.syso)必须放在 build/ 子目录, 构建时临时拷到包目录:
# Go 会把包目录下的 .syso 链接进**所有** GOOS 构建, 若常驻根目录会破坏 linux/darwin 编译。
$syso = Join-Path $Root 'build\rsrc.syso'
$tmpSyso = Join-Path $Root 'rsrc.syso'
$copiedSyso = $false

# 原环境(构建结束必须还原, 否则调用者后续的 go 命令会意外产出别平台产物)
$envBackup = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; CGO_ENABLED = $env:CGO_ENABLED }

$failed = 0
try {
    foreach ($t in $Matrix) {
        # CGO_ENABLED=0: 纯静态单二进制, 与项目"零第三方依赖、单文件跨平台"约束一致
        $env:CGO_ENABLED = '0'
        $env:GOOS = $t.OS
        $env:GOARCH = $t.Arch

        # 图标资源只在 windows/amd64 下链接:
        #   - 非 Windows 目标: Go 会把包目录下的 .syso 当成目标平台的 COFF 对象去链接,
        #     直接报格式错误, 必须移走(build/ 子目录就是为此存在的);
        #   - windows/arm64: 现有 build/rsrc.syso 是 windres 按 x64 产出的, arm64 链接器
        #     报 "unknown ARM64 relocation type 3"(实测)。图标纯属外观, 不该让 arm64
        #     产物构建不出来, 所以 arm64 不带图标; 需要时在 arm64 机器上重新生成 syso
        #     (windres --target=pe-aarch64 或 rsrc)后放入 build/。
        if ($t.OS -eq 'windows' -and $t.Arch -eq 'amd64' -and (Test-Path $syso)) {
            Copy-Item $syso $tmpSyso -Force
            $copiedSyso = $true
            $iconNote = ''
        } else {
            if ($copiedSyso) {
                Remove-Item $tmpSyso -Force -ErrorAction SilentlyContinue
                $copiedSyso = $false
            }
            $iconNote = if ($t.OS -eq 'windows') { "  (无图标: 现有 rsrc.syso 仅适用 amd64)" } else { '' }
        }

        # 平台后缀名 + (当前平台时)短名: 短名便于直接双击/直接执行, 平台名便于分发
        $named = "yugsight_$($t.OS)_$($t.Arch)$($t.Ext)"
        $outExe = Join-Path $OutAbs $named

        # 【关键】ldflags 里绝不能出现 -H windowsgui, 否则控制台窗口消失(见文件头说明)。
        # -s -w 去符号表与调试信息(体积约省 25%), -trimpath 去构建机绝对路径。
        #
        # 【为什么把 stderr 也重定向进 -RedirectStandardError 而不是用管道】
        # PowerShell 5.1 里把原生命令的 stderr 用 2>&1 管道接入管道链时, stderr 的每一行
        # 都会被包装成 ErrorRecord 并从管道**之外**冒出来 —— 命令其实成功(exit 0), 但控制台
        # 会打出 "NativeCommandError" 红字, 配合 $ErrorActionPreference='Stop' 还会把脚本
        # 直接打断(实测: 构建 windows/arm64 时中断在 arm64 那一步)。Go 工具链会往 stderr 写
        # 进度(# yugsight 这类), 所以这个坑必然触发, 不是偶发。
        # 改用 Start-Process 落临时文件: 退出码与输出都拿得到, 且不污染管道。
        $errFile = Join-Path ([System.IO.Path]::GetTempPath()) ("yugsight-build-" + [guid]::NewGuid().ToString('N') + ".err")
        $logFile = Join-Path ([System.IO.Path]::GetTempPath()) ("yugsight-build-" + [guid]::NewGuid().ToString('N') + ".out")
        Write-Host ("构建 {0,-8} {1,-6} -> {2}" -f $t.OS, $t.Arch, $named) -ForegroundColor DarkGray
        # 【参数引号】Start-Process 的 -ArgumentList 是数组, 但它最终会把各元素用空格拼成
        # 一条命令行字符串, 元素内部的空格**不会自动加引号** —— 直接写 '-s -w' 会被拆成
        # 两个参数, go 报 "flag provided but not defined: -w"(实测)。所以这里显式带上
        # 转义引号, 让 go 收到单个 -ldflags 值。
        # 【ldflags 里的变量名必须是 main.appVersion】appVersion 定义在 main 包
        # (main.go), 链接器要求完整包路径。写成其它名字会静默不生效 —— 表现为
        # "构建成功但 UI 里版本号还是旧值", 很难排查, 所以版本号注入后会在下面校验。
        $ldflags = '"-s -w'
        if ($VersionArg -ne '') { $ldflags += ' -X main.appVersion=' + $VersionArg }
        $ldflags += '"'

        $proc = Start-Process -FilePath 'go' `
            -ArgumentList @('build', '-trimpath', '-ldflags', $ldflags, '-o', $outExe, '.') `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $logFile -RedirectStandardError $errFile
        $buildLog = @()
        foreach ($f in @($logFile, $errFile)) {
            if (Test-Path $f) {
                $c = Get-Content $f -ErrorAction SilentlyContinue
                Remove-Item $f -Force -ErrorAction SilentlyContinue
                if ($c) { $buildLog += $c }
            }
        }
        foreach ($line in $buildLog) { Write-Host "  $line" -ForegroundColor DarkYellow }
        if ($proc.ExitCode -ne 0) {
            Write-Host "FAIL  $($t.OS)/$($t.Arch)" -ForegroundColor Red
            $failed++
            continue
        }
        $size = [math]::Round((Get-Item $outExe).Length / 1MB, 2)
        $verNote = if ($VersionArg -ne '') { "  v$VersionArg" } else { '' }
        Write-Host ("OK    {0,-8} {1,-6} {2,7} MB  {3}{4}{5}" -f $t.OS, $t.Arch, $size, $named, $verNote, $iconNote) -ForegroundColor Green

        # 【不再产出短名 yugsight.exe —— 刻意的设计决定, 勿"优化"回去】
        #
        # 曾经这里是"当前平台额外拷一份短名 yugsight.exe 便于双击"。但两个二进制
        # **进程名不同**(yugsight.exe vs yugsight_windows_amd64.exe)带来一连串事故:
        #
        #   1) 只要有一次绕过本脚本用裸 go build 生成单个文件, 两者版本就不一致;
        #   2) 旧实例与新实例进程名不同 → `Get-Process yugsight` 杀不掉平台名那个
        #      → 旧进程占住 8420 端口继续提供**旧二进制的路由表**, 新实例静默顺延到
        #      8421 → 现象是"新加的路由一直 404"; 排查时极易误判为路由冲突/构建未
        #      生效/构建约束问题(实测为此耗掉大量时间);
        #   3) 交付目录里两个同名不同内容的 exe 也让"到底该双击哪个"变得含糊。
        #
        # 现在**只产平台名版本**, 交付/分发/双击都用它。用户已明确要求保持这一点。
        #
        # 下面这段仍按"当前平台"判定, 因为随主程序就位的运行时资源(npcap 安装器 /
        # agents/)只该拷到本机平台那份产物旁边 —— 交叉编译 Linux/
        # Darwin 产物时不需要, 它们不同机运行。
        # 【注意】必须在循环内取 $env:GOOS —— 上面刚把它设成了目标平台值, 若循环外
        # 取一次, 多目标模式下会把"最后一个平台"误判成当前平台。PowerShell 5.1 没有
        # $IsWindows(那是 PS Core 的变量), 故用"目标 == 循环外备份的初始值"判定。
        $hostOS = if ($envBackup.GOOS) { $envBackup.GOOS } else { 'windows' }
        $hostArch = if ($envBackup.GOARCH) { $envBackup.GOARCH } else { $t.Arch }
        if ($t.OS -eq $hostOS -and $t.Arch -eq $hostArch) {
            # ===== 随主程序一起就位的运行时资源 =====
            # 这些文件程序运行时要按"exe 同目录"找, 不放过来就会出现功能性缺失:
            #   - npcap 安装器: 抓包页的"安装网络驱动"按钮靠扫描同目录 npcap-*.exe 拉起,
            #     缺失时按钮点了只报"未找到安装器"。
            #   - test_mode.txt 免登录开关**不自动拷贝**(正式产物不应带免鉴权开关),
            #     开发调试需要时手动放到 exe 同目录即可。
            # 配置文件(engine.json/probe.json 等)刻意**不自动拷**: 它们是用户按需写的,
            # 自动拷一份会导致"改了仓库根那份却不生效"的经典困惑。
            $runtimeRes = @(
                @{ Src = (Join-Path $Root 'npcap-1.86.exe'); Desc = 'Npcap 安装器(抓包驱动一键安装用)' }
            )
            foreach ($res in $runtimeRes) {
                if (Test-Path $res.Src) {
                    Copy-Item $res.Src (Join-Path $OutAbs (Split-Path $res.Src -Leaf)) -Force
                    Write-Host ("      附带: {0}" -f $res.Desc) -ForegroundColor DarkGray
                }
            }
            # agents/ 是探针分发包目录, 中心端 Web 下载页据此提供下载。
            # 用镜像而非移动: 仓库根的 agents/ 仍可被脚本直接更新, dist/ 这份供运行期读取。
            $agentsSrc = Join-Path $Root 'agents'
            if (Test-Path $agentsSrc) {
                $agentsDst = Join-Path $OutAbs 'agents'
                if (-not (Test-Path $agentsDst)) { New-Item -ItemType Directory -Force -Path $agentsDst | Out-Null }
                Copy-Item (Join-Path $agentsSrc '*') $agentsDst -Force -Recurse
                $n = (Get-ChildItem $agentsDst -File -ErrorAction SilentlyContinue | Measure-Object).Count
                Write-Host ("      附带: agents/ 探针包 {0} 个" -f $n) -ForegroundColor DarkGray
            }
            # build/geoip(IP 地理段表, 任务 10c)与 build/globe(three.js/globe.gl/贴图, 任务 10d)
            # 是运行期按需读取的数据/前端资源(不嵌入二进制, 见 geoip/ 与 dashboard_api.go 头注释):
            # 运行时分别按 "exe 同目录 geoip/" 与 "exe 同目录 globe/" 查找, 缺失时降级
            # (地理查询全 unknown / 地球白屏占位), 不报错 —— 故缺失也照样构建, 只提示。
            foreach ($resDir in @('geoip', 'globe')) {
                $src = Join-Path $Root ('build\' + $resDir)
                if (Test-Path $src) {
                    $dst = Join-Path $OutAbs $resDir
                    if (-not (Test-Path $dst)) { New-Item -ItemType Directory -Force -Path $dst | Out-Null }
                    Copy-Item (Join-Path $src '*') $dst -Force -Recurse
                    $n = (Get-ChildItem $dst -File -ErrorAction SilentlyContinue | Measure-Object).Count
                    Write-Host ("      附带: {0}/ {1} 个文件" -f $resDir, $n) -ForegroundColor DarkGray
                } else {
                    Write-Host ("      跳过: build\{0} 不存在(地理映射/3D 地球将降级, 可跑 scripts\geoip_sync.go 生成)" -f $resDir) -ForegroundColor DarkYellow
                }
            }
            # build/report_templates(报告模板包, 二期报告中心)。
            # 与 geoip/globe 的关键差别: 这是**用户可写目录**(模板管理会往里写自定义
            # 模板), 因此只补缺失文件, 绝不覆盖已存在的 —— 升级时冲掉用户自己做的
            # 模板是不可逆丢失, 而"少一个示例模板"毫无损失。
            $rtSrc = Join-Path $Root 'build\report_templates'
            if (Test-Path $rtSrc) {
                $rtDst = Join-Path $OutAbs 'report_templates'
                if (-not (Test-Path $rtDst)) { New-Item -ItemType Directory -Force -Path $rtDst | Out-Null }
                $added = 0
                Get-ChildItem $rtSrc -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $rel = $_.FullName.Substring($rtSrc.Length).TrimStart('\', '/')
                    $target = Join-Path $rtDst $rel
                    if (-not (Test-Path $target)) {
                        $d = Split-Path $target -Parent
                        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
                        Copy-Item $_.FullName $target -Force
                        $added++
                    }
                }
                Write-Host ("      附带: report_templates/ 新增 {0} 个文件(已存在的不覆盖)" -f $added) -ForegroundColor DarkGray
            }
        }
    }
}
finally {
    if ($copiedSyso) { Remove-Item $tmpSyso -Force -ErrorAction SilentlyContinue }
    # 还原环境变量: 不还原会让调用者后续 go build 意外产出别平台产物
    if ($null -ne $envBackup.GOOS) { $env:GOOS = $envBackup.GOOS } else { Remove-Item Env:\GOOS -ErrorAction SilentlyContinue }
    if ($null -ne $envBackup.GOARCH) { $env:GOARCH = $envBackup.GOARCH } else { Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue }
    if ($null -ne $envBackup.CGO_ENABLED) { $env:CGO_ENABLED = $envBackup.CGO_ENABLED } else { Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue }
}

Write-Host ''
if ($failed -gt 0) {
    Write-Host "完成: $($Matrix.Count - $failed)/$($Matrix.Count) 成功, $failed 个失败" -ForegroundColor Red
    exit 1
}
Write-Host "完成: $($Matrix.Count)/$($Matrix.Count) 全部成功" -ForegroundColor Green

# 版本号注入校验: 对**当前平台**产物执行 `-version` 打印, 与期望值比对。
#
# 【为什么值得单独校验一次】-X 链接变量失败时 Go **不会报错**, 只是变量保持源码里
# 的兜底值 —— 现象是"构建成功但 UI 版本号一直是 1.0.0", 且每次构建都这样, 极难定位
# (会怀疑是前端缓存/后端没读到)。这里跑一次真实二进制就能立刻暴露。
# 交叉编译的产物无法在本机执行, 故只校验当前平台那一份。
if ($VersionArg -ne '') {
    $hostOS = if ($envBackup.GOOS) { $envBackup.GOOS } else { 'windows' }
    $hostArch = if ($envBackup.GOARCH) { $envBackup.GOARCH } else {
        if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { '386' }
    }
    $hostExt = if ($hostOS -eq 'windows') { '.exe' } else { '' }
    $hostExe = Join-Path $OutAbs "yugsight_$($hostOS)_$($hostArch)$hostExt"
    if ((Test-Path $hostExe) -and $hostOS -eq 'windows') {
        try {
            $actual = (& $hostExe -version 2>&1 | Out-String).Trim()
            if ($actual -match [regex]::Escape($VersionArg)) {
                Write-Host "版本校验: 产物报告 v$VersionArg (与 VERSION 一致)" -ForegroundColor Green
            } else {
                Write-Host "警告: 产物版本号校验未通过 — 期望含 '$VersionArg', 实际输出: $actual" -ForegroundColor Yellow
                Write-Host "      请检查 main.go 里 appVersion 是否为 var(链接器无法改写 const)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "警告: 版本校验未执行($_)" -ForegroundColor Yellow
        }
    }
}

if ($Agents) {
    Write-Host ''
    $agentArgs = @()
    if (-not [string]::IsNullOrWhiteSpace($AgentsOutDir)) { $agentArgs += @('-OutDir', $AgentsOutDir) }
    & (Join-Path $PSScriptRoot 'build-agents.ps1') @agentArgs
}

Write-Host ''
Write-Host '启动: 双击 dist\yugsight_windows_amd64.exe(会弹出控制台窗口显示实时日志, 关窗不停服务, 停止服务用网页"停止服务"按钮)' -ForegroundColor Cyan
Write-Host '      首次运行会弹 UAC 提权(ICMP 探测需要), 提权后 PID 会变一次, 属正常现象' -ForegroundColor DarkGray
Write-Host 'Linux 服务端: 上传 yugsight_linux_amd64(或 arm64), chmod +x 后执行; 配置与 Windows 同为 exe 同目录 settings.json' -ForegroundColor DarkGray
Write-Host '提示: 功能开关在页面上(首页仪表盘「功能开关」, 默认开启), settings.json 只用于保存参数; 缺失的节走默认值; 仓库根只留源码'

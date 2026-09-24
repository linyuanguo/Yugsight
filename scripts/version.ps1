# version.ps1 版本号自增(供 build.ps1 调用, 也可单独命令行使用)。
#
# ===== 自增规则(用户明确要求) =====
#
#   末位 +1;  末位到 9 再加 1 则"前面加 1 位"(实际是进位);
#
#   1.0.0   -> 1.0.1
#   1.0.9   -> 1.0.10
#   1.0.19  -> 1.0.20
#   1.0.99  -> 1.0.100
#   1.1.9   -> 1.1.10
#
# 注意"到 9 就进位"与"到 10 才进位"的区别: 十进制里 9 是最末位的最大值,
# 但本项目**不截断位数** —— 1.0.9 的下一位是 1.0.10 而不是 1.1.0。
# 理由: 版本段用十进制整数表达, 1.0.10 > 1.0.9 在语义版本比较里天然成立,
# 没有必要为了"段内不超一位"而进位(那会让每次修 bug 都跳大版本, 反而看不清迭代密度)。
#
# ===== 版本号存放位置 =====
#
# VERSION 文件(仓库根, 纯文本一行)。**不用"读上次构建产物"来推断**:
# 产物可能被删除/被换机拷贝/被手工改过, 拿它当真相源会出现"版本号回退"或"卡住不动"
# (实测过的两个不同二进制版本不一致, 就是这类问题)。
# VERSION 文件是纯文本, 便于人工查看/回滚/git diff。
#
# 用法:
#   powershell -File scripts/version.ps1              # 只读取当前版本(不修改)
#   powershell -File scripts/version.ps1 -Bump        # 自增并落盘, 输出新版本
#   powershell -File scripts/version.ps1 -Bump -DryRun # 只算自增结果, 不落盘

param(
    # 自增并写回 VERSION 文件
    [switch]$Bump,
    # 只计算不落盘(用于预览)
    [switch]$DryRun,
    # 版本文件路径(默认仓库根 VERSION; 测试时改指临时文件)
    [string]$File = '',
    # 初始版本(文件不存在时使用)
    [string]$Initial = '1.0.0'
)

$ErrorActionPreference = 'Stop'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
# 注意: 不用 $File 作变量名 —— 它是 PowerShell 内建变量, 赋值会与 .NET 类型名冲突
# (实测在其他脚本里踩过)。这里参数已改名, 但内部仍用一个明确的名字避免歧义。
$VerFile = if ([string]::IsNullOrWhiteSpace($File)) { Join-Path $Root 'VERSION' } else { $File }

# ConvertTo-NextVersion 版本串自增(纯函数, 便于单测)。
#
# 规则: 末位 +1。**不做"到 9 进位"的段内截断** —— 见文件头说明。
# 只接受 "数字.数字[.数字...]" 形态; 非法输入抛错而不是猜(猜错会污染版本号)。
function ConvertTo-NextVersion {
    param([string]$Version)
    $v = ($Version -replace '\s', '')
    if ([string]::IsNullOrWhiteSpace($v)) { throw "版本号为空, 无法自增" }
    # 允许多段(1.0 / 1.0.0 / 1.0.0.1), 但每段必须是非负整数
    if ($v -notmatch '^\d+(\.\d+)+$') {
        throw "版本号格式非法: '$Version'(应为 1.0.0 这样的数字点分形态)"
    }
    $segs = $v.Split('.')
    $last = [int]$segs[$segs.Length - 1]
    $segs[$segs.Length - 1] = [string]($last + 1)
    return ($segs -join '.')
}

function Read-CurrentVersion {
    param([string]$Path, [string]$Fallback)
    if (Test-Path $Path) {
        $raw = (Get-Content $Path -Raw -ErrorAction Stop)
        if ($null -ne $raw) {
            # 关键: 剥掉 UTF-8 BOM。Windows 记事本/PowerShell 5.1 的
            # `Set-Content -Encoding UTF8` 都会带 BOM(EF BB BF), 不剥会导致
            # 版本串变成 "\ufeff1.0.0", 拼进 ldflags 就是乱码版本号(项目内已多次踩过)。
            $raw = $raw.TrimStart([char]0xFEFF).Trim()
            if ($raw -ne '') { return $raw }
        }
    }
    return $Fallback
}

# ===== 主流程 =====
$current = Read-CurrentVersion -Path $VerFile -Fallback $Initial

if (-not $Bump) {
    # 只读模式: 输出当前版本, 便于脚本/人工查询
    Write-Output $current
    return
}

$next = ConvertTo-NextVersion -Version $current

if ($DryRun) {
    Write-Output $next
    return
}

# 写回时**不带 BOM**: 用 [System.IO.File]::WriteAllText 配合 UTF8Encoding($false)。
# `Set-Content -Encoding UTF8` 在 PowerShell 5.1 下会写 BOM, 下次读回来就多一个字符。
$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($VerFile, $next, $enc)
Write-Output $next

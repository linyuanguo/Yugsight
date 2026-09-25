# 四平台交叉编译验证(只做编译可行性检查, 不产出可分发产物)。
#
# ===== 杀软误报必读 =====
# 本脚本产出的二进制常被火绒/Defender 判为 HackTool 类(如 HackTool/VcenterKiller.a):
# 触发的是"go.exe 生成的未签名 PE + 网络/认证交互能力"这一启发式画像, 与代码内容无关,
# 改文件名/去 .exe 后缀均无效(2026-09-24 实测两种都照样报)。
#
# 处置: 把下面的输出目录加入杀软信任区(加目录, 不要逐个加文件 —— 每次编译都是新文件)。
#   默认输出目录: <仓库根>\tmp-cross
# 根本解法是代码签名或向厂商提交误报申诉。
#
# 用法: powershell -ExecutionPolicy Bypass -File scripts\cross-build.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'tmp-cross'
if (Test-Path $out) { [System.IO.Directory]::Delete($out, $true) }
New-Item -ItemType Directory -Path $out -Force | Out-Null

$targets = @(
  @{ GOOS = 'windows'; GOARCH = 'amd64' },
  @{ GOOS = 'windows'; GOARCH = 'arm64' },
  @{ GOOS = 'linux';   GOARCH = 'amd64' },
  @{ GOOS = 'darwin';  GOARCH = 'arm64' }
)

$fail = 0
foreach ($t in $targets) {
  $env:CGO_ENABLED = '0'
  $env:GOOS = $t.GOOS
  $env:GOARCH = $t.GOARCH
  # 产物不带 .exe: 减少被当作"可分发安装程序"的概率(对内容类误报无效, 仅避免二次传播)
  $name = "yugsight_$($t.GOOS)_$($t.GOARCH)"
  # 主程序包在 app/(2026-09-24 目录整理: 从仓库根移入, go:embed 源 frontend/dist 与 web/ 随之同移)
  go build -trimpath -o (Join-Path $out $name) ./app
  $code = $LASTEXITCODE
  if ($code -eq 0) {
    # 先记录哈希再可能被杀软隔离: 误报申诉必须提供样本哈希, 文件被删就取不到了
    $sha = (Get-FileHash (Join-Path $out $name) -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    $len = (Get-Item (Join-Path $out $name) -ErrorAction SilentlyContinue).Length
    Write-Host "OK    $($t.GOOS)/$($t.GOARCH)  sha256=$sha  size=$len"
  } else {
    Write-Host "FAIL  $($t.GOOS)/$($t.GOARCH)"
    $fail++
  }
  Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
}

Write-Host ''
if ($fail -eq 0) { Write-Host "交叉编译全部通过, 产物目录: $out (用完可删, 需已加入杀软信任区)" } else { Write-Host "失败 $fail 个目标" }

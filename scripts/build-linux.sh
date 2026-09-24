#!/usr/bin/env sh
# build-linux.sh 在 Linux 本机(或任意 Unix)构建 Yugsight 中心端 + 全部平台探针包。
#
# ===== 为什么需要这个脚本 =====
#
# 仓库原有的构建脚本是 PowerShell(build.ps1 / build-agents.ps1), Linux 服务器上
# 没有 PowerShell, 于是"中心端部署在 Linux"这件事就变成要手敲一长串 GOOS/GOARCH
# 命令 —— 手敲最常见的两个错误是漏掉 CGO_ENABLED=0(产物依赖 glibc, 丢进精简镜像
# 直接 not found)和文件名与中心端识别约定不一致(探针包放了却不被识别)。
#
# 本脚本把两件事一次做对:
#   1. 构建当前 Linux 平台的中心端, 并做基本自检;
#   2. 交叉编译 6 平台探针包到 ./agents/(与 build-agents.ps1 产物命名完全一致),
#      中心端启动后即可在 Web "探针管理 -> 下载探针" 分发。
#
# 用法:
#   sh scripts/build-linux.sh              # 中心端 + 探针包
#   sh scripts/build-linux.sh --center     # 只构建中心端
#   sh scripts/build-linux.sh --agents     # 只构建探针包
#   OUT_DIR=dist sh scripts/build-linux.sh # 指定中心端输出目录
#
# 注意: 交叉编译探针包不需要目标平台的 Go, 只要是同版本 Go 工具链即可(纯静态, CGO 关闭)。
set -eu

# 仓库根目录(脚本在 scripts/ 下, 上一级即根)。用脚本自身位置推导而不是相对路径 ——
# 相对路径基于调用者 cwd, 从别处调用会把产物落到意外位置(项目历史踩过的坑)。
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
OUT_DIR=${OUT_DIR:-$ROOT}
AGENTS_DIR=${AGENTS_DIR:-$ROOT/agents}

DO_CENTER=1
DO_AGENTS=1
case "${1:-}" in
  --center) DO_AGENTS=0 ;;
  --agents) DO_CENTER=0 ;;
  --help|-h)
    sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  "") ;;
  *) echo "未知参数: $1 (用 --help 查看用法)" >&2; exit 1 ;;
esac

# go 工具链检测: 优先 PATH, 再回落到 GOROOT/bin/go(只装 Go 没配 PATH 的部署很常见)
GO_BIN=$(command -v go 2>/dev/null || true)
if [ -z "$GO_BIN" ] && [ -n "${GOROOT:-}" ] && [ -x "$GOROOT/bin/go" ]; then
  GO_BIN="$GOROOT/bin/go"
fi
if [ -z "$GO_BIN" ]; then
  echo "错误: 未找到 Go 工具链(需 Go 1.25+)。请安装 Go 或把 go 加入 PATH。" >&2
  exit 1
fi
echo "Go: $("$GO_BIN" version)"

# 必须在仓库根目录执行: go build 以 cwd 的模块为上下文
cd "$ROOT"

mkdir -p "$OUT_DIR"

# ===== 1) 中心端(当前 Linux 平台) =====
if [ "$DO_CENTER" = "1" ]; then
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) GOARCH=amd64 ;;
    aarch64|arm64) GOARCH=arm64 ;;
    *) GOARCH=$ARCH ;;
  esac
  NAME="yugsight_linux_${GOARCH}"
  echo "构建中心端 -> $OUT_DIR/$NAME"
  # CGO_ENABLED=0: 纯静态单二进制(与项目"零第三方依赖、单文件跨平台"约束一致)
  # -trimpath 去构建机路径, -s -w 省体积
  CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" \
    "$GO_BIN" build -trimpath -ldflags '-s -w' -o "$OUT_DIR/$NAME" .
  # 便于直接 ./yugsight 启动; 用复制而不是软链, 避免打包时丢链接
  if [ "$OUT_DIR/yugsight" != "$OUT_DIR/$NAME" ]; then
    cp -f "$OUT_DIR/$NAME" "$OUT_DIR/yugsight"
  fi
  # 自检: 产物必须非空且不能在 ldflags 里混入 -H windowsgui(该项只对 Windows 有意义,
  # 这里只做体积检查; Windows 侧由 console_subsystem_test.go 读 PE 头把关)
  if [ ! -s "$OUT_DIR/$NAME" ]; then
    echo "错误: 构建产物为空" >&2
    exit 1
  fi
  SIZE=$(du -h "$OUT_DIR/$NAME" | cut -f1)
  echo "OK    $NAME  $SIZE"
fi

# ===== 2) 探针包(6 平台; 命名必须与 probe_agent_download.go 的 agentPlatforms 一致) =====
if [ "$DO_AGENTS" = "1" ]; then
  mkdir -p "$AGENTS_DIR"
  FAILED=0
  TOTAL=0
  build_agent() {
    os=$1; arch=$2; ext=$3
    TOTAL=$((TOTAL + 1))
    name="yugsight-agent_${os}_${arch}${ext}"
    if CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
      "$GO_BIN" build -trimpath -ldflags '-s -w' -o "$AGENTS_DIR/$name" ./cmd/agent; then
      size=$(du -h "$AGENTS_DIR/$name" | cut -f1)
      printf 'OK    %-8s %-6s %6s  %s\n' "$os" "$arch" "$size" "$name"
    else
      printf 'FAIL  %-8s %-6s\n' "$os" "$arch" >&2
      FAILED=$((FAILED + 1))
    fi
  }
  echo "构建探针包 -> $AGENTS_DIR"
  build_agent windows amd64 .exe
  build_agent windows arm64 .exe
  build_agent linux   amd64 ''
  build_agent linux   arm64 ''
  build_agent darwin  amd64 ''
  build_agent darwin  arm64 ''
  if [ "$FAILED" -gt 0 ]; then
    echo "完成: $((TOTAL - FAILED))/$TOTAL 成功, $FAILED 个失败" >&2
    exit 1
  fi
  echo "完成: $TOTAL/$TOTAL 全部成功"
fi

echo ''
echo "下一步:"
echo "  1) 运行中心端:   ./$OUT_DIR/yugsight            (默认 http://<本机IP>:8420, 可用 -port 改)"
echo "  2) 探针包分发:   Web -> 探针管理 -> 下载探针    (从 $AGENTS_DIR 读取)"
echo "  3) 配置文件(可选, 与中心端同目录): probe.json / engine.json / updater.json / test_mode.txt"

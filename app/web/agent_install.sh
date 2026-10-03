#!/bin/bash
# Yugsight 探针一键安装脚本(Linux + systemd)。
#
# 本脚本由中心端动态生成: WEB/CENTER 地址与节点密钥在渲染时由服务端注入,
# 因此文件内容含密钥 —— 请勿外传本文件(内网部署口径, 与安装落地页一致)。
#
# 用法(在目标机器上执行, 需 root; 普通账号把结尾 bash 换成 sudo bash):
#   curl -fsSLk https://<中心端IP>:<Web端口>/api/v2/probe/agent/install.sh | bash
set -euo pipefail

# ========== 可配置参数(支持环境变量覆盖) ==========
# 默认值为中心端渲染时注入; 需要改值时先设对应环境变量, 例如:
#   WEB_HOST=10.0.0.5 bash -c "$(curl -fsSLk https://<中心端IP>:<Web端口>/api/v2/probe/agent/install.sh)"
WEB_HOST="${WEB_HOST:-{{WEB_HOST}}}"      # 中心端 Web 主机(脚本/探针下载走此端口)
WEB_PORT="${WEB_PORT:-{{WEB_PORT}}}"      # 中心端 Web 端口
CENTER_HOST="${CENTER_HOST:-{{CENTER_HOST}}}"  # 探针通信主机(-center 参数)
CENTER_PORT="${CENTER_PORT:-{{CENTER_PORT}}}"  # 探针通信端口
# 节点密钥: 优先环境变量, 未提供时用中心端注入值。
# 注入值做单引号包裹(单引号内只有单引号本身特殊, 以 '\'' 转义) ——
# 密钥来自配置文件, 可能含 $() 等任意字符, 不包裹会被 shell 当命令执行。
PROBE_TOKEN="${PROBE_TOKEN:-}"
[ -n "${PROBE_TOKEN}" ] || PROBE_TOKEN={{TOKEN}}
INSTALL_PATH="/usr/local/bin/yugsight-agent"
SERVICE_FILE="/etc/systemd/system/yugsight-agent.service"

# ========== 前置检查 ==========
if [ "$(id -u)" -ne 0 ]; then
    echo "[错误] 需要 root 权限(脚本要写 /usr/local/bin 与 /etc/systemd)。请用:"
    echo "        curl -fsSLk https://${WEB_HOST}:${WEB_PORT}/api/v2/probe/agent/install.sh | sudo bash"
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "[错误] 未检测到 curl。先安装(yum install -y curl / apt-get install -y curl)后重跑"
    exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
    echo "[错误] 未检测到 systemd。本脚本仅支持带 systemd 的 Linux 服务器, 其它环境请用安装落地页的手动方式"
    exit 1
fi

# ========== 自动识别 CPU 架构 ==========
ARCH=$(uname -m)
case "$ARCH" in
    aarch64|arm64) ARCH="arm64" ;;
    x86_64|amd64)  ARCH="amd64" ;;
    *) echo "[错误] 不支持的架构: $ARCH"; exit 1 ;;
esac

echo "[1/4] 正在下载 Yugsight 探针 ($ARCH)..."
curl -fsSLk "https://${WEB_HOST}:${WEB_PORT}/api/v2/probe/agent/download?os=linux&arch=${ARCH}" \
     -o "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

echo "[2/4] 正在注册系统服务..."
# 未加引号的 heredoc: 内容做变量展开, 但展开结果不会被 shell 二次解析,
# 密钥中的 $()/反引号 只会原样写入 unit 文件, 不会被执行。
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Yugsight 安全扫描探针
After=network-online.target

[Service]
Type=simple
# 中心端地址变化(换网/VPN 导致 IP 变化)时: 修改上面 ExecStart 的 -center, 然后执行
#   systemctl daemon-reload && systemctl restart yugsight-agent
ExecStart=$INSTALL_PATH -center ${CENTER_HOST}:${CENTER_PORT} -token ${PROBE_TOKEN}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "[3/4] 启动服务并设置开机自启..."
systemctl daemon-reload
systemctl enable --now yugsight-agent

echo "[4/4] 部署完成, 服务状态:"
systemctl status yugsight-agent --no-pager -l

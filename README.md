# Yugsight（御视）· 网络扫描探测工具

**简体中文** | [English](README.en.md)

单文件 exe 的内网安全运维平台，离线开箱即用：内置 Web UI（启动后浏览器自动打开），纯标准库（唯一例外是 YAML 解析 `gopkg.in/yaml.v3`，Nuclei 模板用），不依赖任何外部服务。

- **中心端**：单文件 exe，内含 Web UI 与全部扫描 / 监控能力；外部引擎（nmap / trivy / ZAP）已安装时优先调用，缺失或失败自动降级内置引擎 —— 不装任何外部引擎也能完整工作。
- **探针端**：独立小程序（`yugsight-agent.exe`），装在被扫描机器上，只向中心端发起一条出站连接，零入站端口；不部署探针时中心端单机即可用，部署探针后采集延伸到跨网段与机器系统层（中间件、数据库、进程 / 服务）。

## 功能 Features

| 模块 | 说明 |
|---|---|
| IP 存活扫描 | CIDR / 范围 / 单 IP，ICMP + TCP 双探测，strict / loose / 不判存活 |
| 端口扫描 | 自定义端口（`80,443,500-600`），服务名 / 横幅 / 延迟 |
| Web 漏洞扫描 | 安全响应头、TLS、35+ 敏感路径、SQLi / XSS / 路径穿越 + 8,746 条漏洞规则（可按规则勾选） |
| 主机扫描 | OS 指纹、服务版本 → CVE 匹配（CPE 库 33 产品 / 4,043 CVE，NVD 一键同步） |
| 外部引擎（可选） | nmap / trivy / ZAP / nuclei 一键下载安装，优先外部、失败自动降级内置 |
| 弱口令 / 空口令（默认关） | 10 种协议真实试探，内置 + 自定义字典，白名单 + 限速 + 审计 |
| 实时抓包 | Npcap 一键安装，全量采集 + 页面过滤，报文列表 / 详情 / 十六进制，PCAP 导出，环路检测 |
| Nuclei 模板扫描 | 内置 + 官方模板，tag 过滤，热更新，在线更新 / 回滚 |
| 漏洞管理 | 白名单（ip / cidr / port / cve / tag）+ 人工误报标记 + 置信度打分 |
| 分布式扫描 | 探针 agent：节点上报、任务下发、探针本地扫描 / 抓包 / 枚举 / SYN / ARP 异常检测，包下载与自动更新 |
| 节点监控（默认关） | 主机侧（agent + 无代理 WinRM / SSH / SNMP）+ 网络侧（SNMP / ICMP / NetFlow / NETCONF / RESTCONF），调度 / 限速 / 时序 / 异常事件 |
| 告警推送（默认关） | 节点告警（离线 / 恢复 / 阈值越限）自动 Webhook 推送到企业微信 / 钉钉 / 飞书，按规则（级别 / 时段 / 免打扰）匹配，失败重推、确认 / 忽略，推送日志可追溯 |
| 网络拓扑 | 2D 画布，多套独立视图（服务端持久化、跨浏览器同步），设备库拖拽绑定真实设备，手动连线 + 端口绑定（真实速率标签），连线连通性实测（三态 + 自动重试 / 定期复验），子网折叠 / 钻取，自由框，流量光效 |
| 安全大屏 | 独立全屏页，自由画布 + 卡片布局，拖拽摆位 / 框选，一键浏览器全屏投屏 |
| 任务调度 | 排队、优先级 / 并发 / 网段限速、策略模板、探针路由；扫描历史（重扫 / 取消 / 批量删除） |
| 漏扫报告 | 一键导出 HTML / PDF / Word，可视化排版模板编辑器，风险评分 / 修复建议 / 历史对比 |
| 报告中心 | 原始结果自动存档（抓包 / 扫描 / 弱口令 / 监控），多选合并、多维筛选、AI 研判挂载 |
| 首页仪表盘 | 概览仪表盘（5s 刷新）+ 内嵌安全大屏（15s 刷新） |
| AI 全链路分析（可选，默认关） | Prompt 模板 / RAG 文档库 / 结构化记忆库，Ollama / OpenAI 兼容，强制脱敏 |
| AI 助手「小 Y」（可选） | 页面上下文感知问答，SSE 流式回答 |
| 渗透工作台（仅管理员） | 只对已知漏洞做验证渗透（扫描只发现、渗透只验证），EXP 模板库 + 弱口令验证，渗透审计独立留痕 |
| 角色与权限 | admin / operator / auditor 三角色；登录 = 账号 + 密码 + 6 位动态码（90 秒一换，登录页大字内联） |
| 一键恢复出厂 | 清空全部数据与缓存、重建 admin 账号，全程审计留痕 |
| 中英双语界面 | 全站一键切换（登录页 / 顶栏 / 探针安装落地页，落地页右上角同样可切且与 UI 互相同步），偏好按浏览器记忆（落地页与 UI 共用），默认中文 |

UI 为 Vue3（默认主页 `/app/`），经典单文件页在 `/classic/`。

## 界面截图 Screenshots

> 均为全新安装的初始态（深色主题，1920×1080；网络拓扑为 10.10.10.x 示例设备）。

| 登录 Login | 首页仪表盘 Dashboard | 安全大屏 Big Screen |
|---|---|---|
| ![登录：账号 + 密码 + 内联 6 位动态码（90 秒一换）](docs/images/login.png) | ![资产 / 风险 / 任务 / 引擎 + 中心端运行状态](docs/images/dashboard.png) | ![自由画布 + 卡片布局的运维大屏](docs/images/bigscreen.png) |
| 网络拓扑 Topology | 扫描控制台 Scan Console | 漏洞管理 Vulnerabilities |
| ![2D 画布 · 多套视图 · 设备绑定与实时速率](docs/images/topology.png) | ![任务参数 + 事件流 + 实时结果](docs/images/console.png) | ![全部漏洞记录 + 白名单 / 误报管控](docs/images/vulns.png) |
| 报告中心 Report Center | 节点监控 Node Monitoring | 实时抓包 Live Capture |
| ![可视化模板 + 一键生成 + 原始报告存档](docs/images/reports.png) | ![探针管理 + 执行状态 + 探针任务](docs/images/nodemonitor.png) | ![Npcap 全量采集 + 报文列表 + 页面过滤](docs/images/capture.png) |

## 快速开始 Quick Start

1. 双击 `yugsight_windows_amd64.exe`（首次弹 UAC 提权）
2. 浏览器自动打开 `http://<本机IP>:8420`，用 `admin / admin123` + 6 位动态码登录（码值大字内联在登录页，90 秒一换）
3. 选模块、填参数、开始扫描，结果实时流式显示；完成后到「报告中心」生成报告

- 程序以控制台窗口常驻（自动最小化），关窗不停服务。**停止服务**：登录页底部链接，或「授权与模型 → 服务管理」（免登录）
- 默认绑定 `0.0.0.0`（机器 IP 变化不失联）；只想绑局域网 IP 用 `-bind-local`
- 默认 HTTP；需要 HTTPS 时在 `settings.json` 的 `tls` 节设 `enabled: true` 并重启（自动签发自签证书，按登录页"安装根证书"引导操作）
- 实时抓包需 Npcap（UI 内一键安装）；外部引擎缺省时内置引擎照常工作

## 构建 Build

前置：Go 1.25+（改前端另需 Node 20+，且先在 `app/frontend` 执行 `npm run build`）。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -OutDir dist     # 中心端（自动递增版本号 + 注入图标）
powershell -ExecutionPolicy Bypass -File scripts/build-agents.ps1           # 探针端（6 平台包）
```

- 版本号在 `VERSION`，脚本每次自动 +1；产物只保留平台后缀名（`yugsight_windows_amd64.exe`），勿另留短名 `yugsight.exe`（进程名不同，旧实例会占住 8420 端口）。
- 报告 / 模板 / 漏洞库 / 配置放 exe 同目录，无需重编。

## 许可证 License

社区版遵循 **MIT 协议**；全程本地离线运行、数据不出本机，代码开源可审计，请仅在拥有合法授权的目标上使用。

企业级商用授权 / 定制服务，请通过 GitHub Issues 咨询。

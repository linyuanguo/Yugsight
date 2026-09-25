# Yugsight（御视）· 网络扫描探测工具

**简体中文** | [English](README.en.md)

基于 Go 单文件 exe 的网络扫描探测工具，内置 Web UI（启动后浏览器自动打开），开箱即用、离线可跑：除 YAML 解析（`gopkg.in/yaml.v3`，用于 Nuclei 模板）外全部标准库实现，不依赖任何外部服务与前端资源。

- **中心端**：单文件 exe，内含 Web UI 与全部扫描能力。外部引擎（nmap / trivy / ZAP 等）已安装时优先调用，缺失或失败自动降级到内置引擎 —— 不装任何外部引擎也能完整工作。
- **探针端**：独立小程序（`yugsight-agent.exe`），装在被扫描机器上，只向中心端发起一条出站连接，零入站端口。
- **单机即可用**：不部署探针时，中心端就能独立完成网络扫描、漏洞扫描与监控（覆盖它能直接到达的目标）。部署探针后，采集范围延伸到装探针的那台机器 —— 中心端跨网段 / 跨三层够不到的本地网络信息，以及该机器系统层面的中间件、数据库、进程 / 服务 / 已安装软件等信息，只有部署了探针才能采集。

## 功能模块

| 模块 | 说明 |
|---|---|
| IP 存活扫描 | CIDR / IP 范围 / 单 IP，ICMP + TCP 双探测，strict/loose/不判存活三模式 |
| 端口扫描 | 自定义端口，支持 `80,443,500-600` 列表+范围混合，服务名/横幅/延迟 |
| Web 漏洞扫描 | 安全响应头、TLS 证书、35+ 敏感路径、SQLi/XSS/路径穿越探测 + 漏洞库规则（可按规则勾选、降噪：缺失响应头合并为单条加固建议） |
| Web 深度扫描（可选） | 同源爬取 → 表单/参数注入点 → SQLi 三类 + XSS 三位置（默认关闭） |
| 主机扫描 | 系统指纹（TTL/端口组合推断 OS）、TLS 证书、服务横幅版本、按服务常见风险检测（Redis 未授权等）、CPE 字典匹配具体 CVE+CVSS，只列开放端口 |
| 外部引擎（可选） | nmap / trivy / ZAP / nuclei 一键下载安装到 `bin/`，扫描编排优先外部引擎、失败自动降级内置引擎 |
| 弱口令 / 空口令（可选） | 10 种协议（redis/mysql/postgresql/ftp/telnet/ssh/smb/vnc/rdp/oracle）真实试探，top100 内置字典 + 自定义字典，CIDR 白名单 + 限速 + 审计，默认关闭 |
| 实时抓包 | Npcap（UI 内一键安装）、全量采集 + 页面过滤、报文列表/详情/十六进制、环路检测（默认关） |
| Nuclei 模板扫描 | 内置 5 个模板（打包进 exe）+ 外部模板，tag 黑白名单过滤，热更新，官方仓库在线更新 |
| 漏扫管控 | 白名单（ip/cidr/port/cve/tag）+ 人工误报标记（后续扫描自动标记）+ 置信度打分 |
| 分布式扫描 | 中心端 + 独立探针 agent：节点信息上报、任务下发、探针本地扫描/抓包/枚举/SYN、探针包下载与自动更新 |
| 节点监控 | 阶段 1 采集底座：主机侧（agent 探针 + 无代理 WinRM/SSH/主机 SNMP）+ 网络侧（SNMP + ICMP/NetFlow/NETCONF/RESTCONF），任务调度/限速/白名单/时序/异常事件（默认关闭） |
| 任务调度 | 排队执行、优先级/并发/网段限速、策略模板、探针路由（默认启用；普通即时扫描不受影响） |
| 漏扫报告 | 一键导出 HTML 报告、自定义模板；报告引擎（可选）：风险评分/修复建议/资产拓扑/历史两扫对比、扫描结束自动触发 |
| 报告中心（原始报告） | 抓包 / 扫描 / 弱口令 / 节点监控执行完成后，原始结构化结果自动存档；单份查看、多选合并为汇总报告、标签 / 来源 / 时间 / 资产筛选；业务页 AI 分析的研判结果挂载在对应报告下，原始数据 + AI 研判可同时查看，合并时 AI 内容随源报告保留 |
| 首页仪表盘 | 双 Tab 页面：概览仪表盘（资产/风险/任务/引擎 + **中心端运行状态**：中心主机 CPU/内存/磁盘、服务运行时长、任务队列实时进度、探针连接/数据库/消息队列链路状态，5 秒轮询）+ 安全大屏（原独立大屏页全量迁入） |
| 安全运维大屏 | 大屏：资产/风险/趋势/探针负载/高危 TOP/3D 地球流向/SNMP 监控/热力图，可选 Prometheus 指标端点（阶段 4 起为首页仪表盘内置 Tab2，旧 `/bigscreen` 地址自动重定向） |
| AI 全链路分析（可选） | AI 配置页统一管理：接口参数 / 三套 Prompt 模板 / RAG 文档库（上传分片向量化）/ 结构化记忆库（平台历史数据检索）；分析触发按钮在各业务页面，结果存报告中心；Ollama/OpenAI 兼容，强制脱敏，默认关闭 |
| 渗透工作台（仅管理员） | 阶段 5：只对漏扫管控已登记的**已知漏洞**做验证渗透（扫描只发现、渗透只验证）。内置 EXP 模板库（可导入自定义）+ 弱口令凭据验证，SSE 实时回显，输出 可利用 / 部分利用 / 不可利用 三态结论；可修正风险定级并**一键回传**漏洞管理，报告中心自动产出「扫描 + 渗透验证」整合报告。默认启用，每次执行需逐次授权确认，`penta.*` 渗透审计独立留痕（仅管理员可清空，清空动作本身留痕） |

UI 为 Vue3 前端（默认主页，`/app/`），经典单文件页在 `/classic/` 子路径仍可访问。

## 快速开始

1. 双击 `yugsight_windows_amd64.exe`（首次会弹 UAC 提权，提权后 PID 会变一次，属正常）
2. 浏览器自动打开 `http://<本机IP>:8420`（默认主页为 Vue3 前端，经典页在 `/classic/`）
3. 用初始账号 `admin / admin123` 登录（全新安装自动创建，可在 `settings.json` 的 `auth` 节修改）
4. 选择模块、填参数、点"开始扫描"，结果实时流式显示
5. 扫描完成后点"生成报告"导出 HTML 报告

- 程序以**控制台窗口**形式常驻（显示实时日志，已自动最小化）：关窗不停服务。**停止服务**只有两个入口 —— 登录页底部的"停止服务"链接、授权管理页的"服务管理 → 停止服务"按钮（`/api/quit`，免登录），或恢复控制台窗口后 Ctrl+C。
- 服务默认绑定 `0.0.0.0`（全部网卡，含回环），因此 `http://127.0.0.1:8420`、`http://<本机IP>:8420` 都能访问；机器 IP 变化（DHCP 换租 / 插拔 VPN）也不会失联。只想绑本机局域网 IP 时用 `-bind-local` 启动。
- 实时抓包模块需要 Npcap：UI 内点"一键安装"即可（使用 exe 同目录的 `npcap-1.86.exe` 官方安装器）。
- 外部引擎（nmap/trivy/ZAP 等）缺省时内置引擎照常工作；需要时在「引擎与规则」页的**引擎**页签一键下载安装。

## 硬件要求（中心端）

中心端是 I/O 密集（网络探测 / 抓包），不是 CPU 密集；资源大头两块：① db 的 JSONL 全表内存缓存（资产 / 漏洞越多越吃内存）② 可选外部引擎（ZAP=Java、trivy=容器分析，这两个才重）。

| 档位 | CPU | 内存 | 磁盘 | 网络 |
|---|---|---|---|---|
| **低配（够用）** | 2 核 | 4 GB | 20 GB 空闲（SSD 优先） | 千兆网卡 |
| **推荐** | 4 核 | 8 GB | 50 GB SSD | 千兆 |
| **装 ZAP / trivy 时** | 4 核起 | 8–16 GB | 100 GB | 千兆 |

一句话：纯内置引擎跑内网，2 核 / 4G / 20G 就够；要上 ZAP 或 trivy 按 4 核 / 8G+ 配。以上为架构推算值，非实测基准 —— 压测看「首页仪表盘 → 中心端运行状态」面板的实时 CPU / 内存值。

## 硬件要求（探针端）

探针是约 7MB 的单文件 exe（不含 Web UI / 规则库），零入站端口、只对中心端一条出站连接，装在被扫描机器上，目标是"不干扰机器自身业务"：

| 项 | 最低要求 | 说明 |
|---|---|---|
| CPU | 1 核 | 空闲（心跳 / 监控采集）接近零负载；跑端口 / 全量漏洞扫描时有 CPU 峰值，以 I/O 为主 |
| 内存 | 1 GB | 程序自身空闲仅几十 MB；跑全量漏洞扫描 / Nuclei 模板时有峰值 |
| 磁盘 | 500 MB | 程序 + 卸载副本 + 更新备份约 25MB；日志自动轮转，最多约 160MB（8MB/份 × 20 份） |

- Windows 双击安装落到 `C:\YugsightAgent`（免 UAC 提权），保证 C 盘有上述余量即可。
- 探针机若另调外部引擎（Nmap / Trivy / Nuclei），引擎自身占用另计，内存建议提到 2GB+。
- 以上为架构推算值，非实测基准。

## 角色与权限

登录用户分三种角色（在授权管理页分配）。权限边界由后端中间件兜底，前端只是隐藏入口：

| 能力 | admin 管理员 | operator 操作员 | auditor 只读 |
|---|---|---|---|
| 浏览全部页面（仪表盘 / 大屏 / 资产 / 漏洞 / 报告 / 监控） | ✓ | ✓ | ✓ |
| 发起扫描、抓包、SNMP 监控、弱口令检测 | ✓ | ✓ | ✗ 403 |
| 资产 / 漏洞 / 白名单 / 误报 / 任务 / 探针 / 引擎 / 报告 的写操作 | ✓ | ✓ | ✗ 403 |
| 渗透工作台（已知漏洞的验证渗透 / EXP 模板 / 结果回传） | ✓ | ✗ 菜单隐藏，接口 403 | ✗ 菜单隐藏，接口 403 |
| 授权管理页（用户账号、会话吊销、审计配置与清理） | ✓ | ✗ 菜单隐藏，手输地址回落首页 | ✗ |

- 只读角色看得见所有数据，但任何写接口都返回 403；操作员能干活但碰不到账号体系（否则可自建 admin 自我提权，刻意的红线）。

## 功能使用

左侧菜单分六组：运维总览 / 扫描作业 / **渗透测试** / 资产与风险 / 诊断与观测 / 系统配置。下面按组速览（括号内是路由），细节配置见对应专节。

**典型流程**：立即扫描填网段先摸清存活主机与开放端口 → 对关注主机跑**深度主机**（指纹 + 服务版本 + CVE）/ **Web 漏洞** → 结果自动落库，到**资产 / 漏洞管理**复核、标误报 → 可疑漏洞**发送到渗透工作台**做验证渗透，结论回写漏洞条目 → **报告中心**导出报告交付；日常值守看**首页仪表盘 → 安全大屏**。

### 运维总览
- **首页仪表盘（/）**：两个 Tab —— **概览仪表盘**（资产/漏洞/任务/引擎/Npcap 五卡 + **中心端运行状态**面板 5 秒轮询：中心 CPU/内存/磁盘/运行时长、任务队列实时进度、探针连接/数据库/消息队列链路健康）+ **安全大屏**（15 秒自动刷新：漏洞趋势/风险占比/高危 TOP/IP 流向 3D 地球/SNMP/热力图，可全屏）。
- **报告中心（/reports）**：两类产出 —— **原始报告**（四大业务模块原始结构化结果自动存档，筛选 / 合并 / AI 研判挂载，见「报告中心」节）与**渲染报告**（HTML / PDF / Word 导出、历史对比、模板管理）。PDF 走浏览器打印通道（浏览器另存为 PDF），Word 由服务端直接产出。

### 扫描作业
- **扫描作业（/console）**：两个页签 —— **立即扫描**（快速发现 / 深度主机 / Web 漏洞 三类型，**立即执行**走 SSE 实时出结果、**排队执行**由调度器派发，可选执行节点 / 策略模板 / 优先级）与**任务队列**（暂停 / 恢复 / 取消 / 重试 + 策略模板 + 限速统计）。通用参数是超时（毫秒）与并发。
- **弱口令检测（/weakpass）**：**默认关闭**，需 `settings.json` 的 `authcheck` 节启用（目标 CIDR 白名单 + 限速）；目标一行一个 `host:port[:service[:user]]`，单次最多 200 行；"结论"分 弱口令 / 空口令免认证 / 协议不支持 / 未命中 四种，每次尝试落审计（口令只在命中时出现）。

### 渗透测试（仅管理员）
- **渗透工作台（/penta）**：三页签（任务管理 / 执行控制台 / 结果管理），仅 **admin** 可用（operator / auditor 无菜单入口、接口 403）。只对漏扫管控已登记的**已知漏洞**做**验证渗透**、不做广谱扫描（扫描只发现、渗透只验证，菜单/接口/权限物理隔离）。内置 **EXP 模板库**（可导入自定义 YAML / JSON，步骤仅限 `http / tcp / weakpass / external`，不接受任意命令执行）；**逐次授权**（未勾选 400）+ 全程 `penta.*` 留痕（独立成表，仅管理员可清空且清空动作留 `penta.audit.clear` 痕迹）。验证结论（可利用 / 部分利用 / 不可利用）与风险定级可**一键回传**漏洞管理，报告自动带「渗透验证」章节。

### 资产与风险
- **资产管理（/assets）**：扫描结果自动落库的资产台账（IP / 存活 / 主机名 / OS / 主服务 / 开放端口 / 探针节点 / 标签），可手工补录 / 编辑、管理标签，"存活"列区分是否探测到响应。
- **漏洞管理（/vulns）**：五维筛选（等级 / 状态 = 开放或已修复 / CVE / 资产 IP / 标题）+ 改状态 / 标误报（同资产同 CVE 自动标记）/ 删除；"清空全部漏洞"是破坏性操作（**只清漏洞表、资产台账不动**），需弹窗输入确认并写审计。
- **漏扫管控（/whitelist）**：三页签 —— 白名单（ip / cidr / port / cve / tag，命中即过滤）+ 误报标记（后续扫描自动标记）+ 置信度评分（四级打分，只读说明）。

### 诊断与观测
- **实时抓包分析（/capture）**：Windows 需先装 Npcap（页面一键安装）；**全量采集**（内核只做 `arp or ip` 粗筛，细过滤放页面、换视角不必重抓，过滤词支持 `ip: / port: / proto: / mac: / src: / dst:` 前缀）+ 报文表 / 字段详情 / 十六进制 dump + 环路检测（开关走 `capture` 节）。
- **节点监控（/nodemonitor）**：两个 Tab —— **探针节点管理**（agent 节点表 / 任务下发 / 下载探针 + 无代理 WinRM / SSH / 主机 SNMP 主机侧采集）+ **网络设备监控**（SNMP + ICMP / NetFlow / NETCONF / RESTCONF），详见「节点监控」节。

### 系统配置
- **引擎与规则（/env）**：**引擎**页签（探测 / 一键安装 nmap · trivy · ZAP · nuclei 与 Npcap 驱动，缺失自动降级内置引擎、不影响扫描）+ **规则**页签（内置 + 自定义漏洞库，按 scope / 等级 / 匹配方式过滤，粘贴 JSON 导入写入 `vuln/` 立即生效）。
- **AI 配置（/settings/ai）**：AI 全链路分析的统一配置页（接口参数 / 三套 Prompt 模板 / RAG 文档库 / 结构化记忆库），详见「AI 全链路分析」节。
- **授权管理（/license，仅管理员）**：用户管理（创建 / 改密 / 角色 / 停用 / 删除）/ 登录会话吊销 / 审计日志（清空 / 删除均留痕，不含渗透审计）/ 服务停止。
- **经典单文件页（/classic/）**：老 9 页签界面（IP 存活 / 端口 / Web 漏洞 / 主机 / 抓包 / 规则库 / 白名单误报 / 实时事件 / 引擎状态），Vue 界面无入口，`-ui old` 可设为主页。

## 目录结构

```
app/                主程序(package main, 2026-09-24 仓库整理从仓库根移入; 一个 Go 包只能
                    存在于一个目录, 故主程序文件平铺于此, 按 console_/scan_/auth_/probe_
                    等前缀分类):
  main.go           入口: 参数解析、路由注册(/api/* · /app/ · /classic/)、控制台常驻
  *_api.go          各模块的 HTTP 接口层(按功能拆文件: dashboard/report/probe/scheduler …)
  frontend/         Vue3 前端(源码 src/, 构建产物 dist/ 经 go:embed 嵌入)
  web/              经典单文件 UI(/classic/)+ 报告模板
                    (frontend/ 与 web/ 必须与主程序同树: go:embed 的嵌入源不能跨包目录)
build/              构建输入资产: geoip/(IP 地理段表) globe/(three.js 等前端资源) report_templates/
                    图标(icon.rc + yugsight_icon_128px.ico + rsrc.syso) / npcap-1.86.exe(安装器)
cmd/agent/          探针端程序(独立二进制, 见"分布式扫描")
cmd/gen-rules-manifest/  规则清单生成工具(自建更新源用)
cmd/snmpcheck/      SNMP 连通性自检小工具
internal/           全部库包(主程序之外的 Go 包统一收在这, 2026-09-24 仓库整理):
  account/          账号口令哈希(bcrypt + blowfish, 自实现)
  agentpkg/         探针包管理(缓存、就地补包)
  ai/               AI 配置/Prompt/RAG/记忆库/分析
  bigscreen/        安全大屏数据聚合
  collect/          节点监控采集底座(调度/限速/白名单/时序/事件 + WinRM/SSH/SNMP/ICMP/NetFlow/NETCONF/RESTCONF 协议采集器)
  db/               内置数据引擎(sqlite 文件, 无外部数据库依赖)
  engine/           内置引擎(nmap 参数/输出解析/编排)
  engmgr/           外部引擎下载、安装、版本管理
  envdetect/        运行环境自检(外部引擎 / Npcap / JDK)
  geoip/            地理库查询(读取 exe 同目录 res/geoip/, 缺失降级 unknown)
  models/           领域模型(资产/漏洞/等级)
  monitor/          SNMP 监控采集与存储
  normalizer/       外部引擎输出归一化
  pathrel/          路径工具
  penta/            渗透测试模块
  probe/            分布式探针(协议 + 中心端服务端 + 探针端客户端)
  report/           报告引擎(评分/拓扑/历史对比) + 原始报告(业务模块原始结果实体与多报告合并算法)
  scanctl/          扫描任务控制层
  scanner/          扫描能力实现(漏洞库/CPE 字典/规则更新/ARP 等)
  scheduler/        任务队列调度(排队/并发/限速/策略)
  server/           中间件、统一响应、路由
  snmp/             SNMP 协议实现(v1/v2c/v3)
  sse/              Server-Sent Events 实时推送
  weakpass/         弱口令检测各协议实现
scripts/            构建与数据生成脚本(build.ps1 / build-agents.ps1 / geoip_sync.go …) + e2e/(本地冒烟脚本, 不入库)
```

未入库的目录（`dist/` 运行期产物、`nuclei-templates/` 第三方模板等）见 `.gitignore` 顶部说明。
仓库根只留 `go.mod / go.sum / LICENSE / README / VERSION / settings.example.json` 与上述目录。

## 构建与重新编译

前置：Go 1.25+；改动前端时另需 Node 20+（开发用 Node 22 / npm 10）。

```powershell
# 推荐: 构建脚本(自动注入图标与版本号, 多平台可选, 产物名带平台后缀)
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -OutDir dist
# 只构建 Linux 服务端: -Targets linux/amd64
# 不动版本号只重编一次: -NoBumpVersion; 试构建不留痕: -VersionDryRun

# 手工构建(仅当前平台; 主程序包在 app/)
go build -trimpath -ldflags "-s -w" -o yugsight_windows_amd64.exe ./app

# 探针端 = 独立程序(装到被扫描机器上; 只做出站连接, 无 Web UI)
go build -trimpath -ldflags "-s -w" -o yugsight-agent.exe ./cmd/agent
# 一条命令产出 6 平台探针包到 agents/(对应中心端 UI"探针下载"页的分发源)
powershell -ExecutionPolicy Bypass -File scripts/build-agents.ps1

# Linux / 其它平台(代码含跨平台桩, 抓包模块仅 Windows 可用)
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o yugsight_linux_amd64 ./app
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o yugsight-agent ./cmd/agent
```

**改动前端后必须先构建前端再编后端**（构建产物被 `go:embed` 嵌入 exe）：

```bash
cd app/frontend && npm install && npm run build   # 产出 app/frontend/dist/
cd ../.. && powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -OutDir dist
```

- `app/frontend/dist/` **随仓库提交**（它是 `go:embed all:frontend/dist` 的嵌入源，缺失会导致 `go build` 直接失败）。
- 版本号由 `VERSION` 文件管理，构建脚本每次自动末位 +1 并经 `-ldflags -X main.appVersion=` 注入（链接器对 main 包固定用 `main` 路径，与所在目录无关；勿手改 `app/main.go` 里的兜底值）。
- `npcap-1.86.exe` 不入库（第三方安装器）：需要"抓包驱动一键安装"能力时，自行下载后按此文件名放到 `build/`，构建脚本会把它拷进产物。
- 产物只保留平台名版本：不要额外留一个短名 `yugsight.exe`。两者进程名不同，会导致旧实例占住 8420 端口继续用**旧二进制的路由表**应答，新增接口表现为"一直 404"，极难排查。
- UI 改动需重新编译生效；报告/模板/漏洞库/配置放 exe 同目录，无需重编。

## 测试

```bash
go test ./...                    # 全部 Go 单测
go test . -run TestVueFSEmbeddedMatchesDisk   # 校验前端产物确实被嵌入(见下)
```

`TestVueFSEmbeddedMatchesDisk` 守着一条线上踩过的坑：`go:embed` 默认排除以 `_` / `.` 开头的文件，而 Vite 会产出 `assets/_plugin-vue_export-helper-<hash>.js`，漏掉它会导致部分页面点菜单无反应。因此嵌入必须写 `//go:embed all:frontend/dist`，且该用例会逐文件比对磁盘与嵌入内容，少一个就失败。

## 命令行参数

```
-port 8420       UI 监听起始端口(被占用自动顺延)
-no-browser      不自动打开浏览器
-bind-local      只绑定本机局域网 IP(默认绑 0.0.0.0 全部网卡: 机器 IP 变化后仍可访问)
-lan             (保留兼容)已默认绑定 0.0.0.0, 无需再带
-no-admin        不请求管理员权限(ICMP 将不可用)
-no-auth         测试模式: 跳过注册/登录(也可在 exe 同目录放 test_mode.txt, 生产构建请勿使用)
-ui vue|old      主页 UI: vue=Vue3 新前端(默认) | old=经典单文件页; 经典页始终可在 /classic/ 访问
-no-nuclei       关闭 Nuclei 模板扫描(默认启用, 无需额外参数)
-nuclei-dir DIR  Nuclei 模板目录(缺省用 exe 同目录 templates/)
-ai              全局启用 AI 后置分析(配置读 exe 同目录 settings.json 的 ai 节, 默认关闭)
-probe center|both  启用分布式探针中心端(both=中心端+同机探针, 供联调; 探针端请用独立的 yugsight-agent 程序)
-version         显示版本号
```

开发测试可用 `-no-auth -no-admin` 参数启动（免注册/免登录/免 UAC）。

## 配置文件（settings.json）

全部配置统一在 exe 同目录 `settings.json`（可复制仓库的 `settings.example.json` 改名起步；每节都可选，全缺省=全部默认值，程序照常运行）：

| 节 | 用途 | 默认 |
|---|---|---|
| `engine` | 外部引擎调用 + 一键下载/自动补装 | 关 |
| `ai` | AI 全链路分析（基础参数 / 模块开关 / Prompt 模板 / RAG 文档库 / 结构化记忆库） | 关（模块开关默认开，受全局约束） |
| `capture` | 抓包（环路检测 / 全量采集） | 全量开、环路检测关 |
| `collect` | 节点监控采集（开关 / 间隔 / 并发 / 限速 / 白名单 / NetFlow 接收 / 告警阈值 / 采集任务） | 关 |
| `updater` | Nuclei 模板与 CPE 库在线更新 | 官方仓库通道开、后台自动更新关 |
| `probe` | 分布式探针（center 中心端 / client 探针端） | 全关 |
| `scheduler` | 任务队列调度（排队/并发/限速/策略） | 开（即时扫描不受影响） |
| `report` | 报告生成引擎（评分/拓扑/历史对比/自动触发）+ 原始报告（`autoSave` 执行完成自动存档 / `maxRaw` 存储上限） | 开（`autoSave` 默认开，`maxRaw` 默认 500） |
| `screen` | 大屏 Prometheus 指标端点 | 关 |
| `database` | 数据库（内置文件引擎） | sqlite 内置 |
| `auth` | 登录开关与初始账密（程序读写） | 开，admin/admin123 |
| `whitelist` | 白名单（程序读写） | - |
| `tls` | HTTPS（`{enabled,cert,key}`，证书缺失降级 HTTP） | 关 |
| `authcheck` | 弱口令检测（目标 CIDR 白名单 + 限速） | 缺失即关 |

- 改完**重启生效**（前端页面上改的配置由程序自动写回本文件，无需重启）。
- 程序自动保存（账号/白名单等）只替换自己的节，你在其它节手写的注释与格式不会丢；兼容 UTF-8 BOM。
- `settings.json` 里没有的节会回退读旧单文件（`engine.json` / `probe.json` 等），从旧版本升级不丢配置；把内容挪进对应节后即可删旧文件。

## 账户与安全

- **初始账号**：全新安装按 `settings.json` 的 `auth` 节 `user/pass` 自动创建（未配置默认 `admin / admin123` 并回写配置文件）；校验始终走 SHA-256 + 随机 salt 哈希，无明文旁门。重置密码 = 删掉 auth 节的 `users`/`salt` 两行后重启
- **2FA 动态码**：常驻启用。登录页直接展示当前 6 位动态码（90 秒时间片），账号 + 密码 + 动态码一屏提交（一次登录，无第二步）；码值本地计算无外网请求，未配置时首次拉取自动初始化
- **记住密码**：1 天内自动回填表单（浏览器 localStorage，动态码仍需输入，不削弱 2FA）
- **登录限流**：5 分钟内失败 5 次锁定 15 分钟
- **多用户 / RBAC**：授权页可创建账号并分配角色 —— `admin` 管理员（全权限）/ `operator` 操作员（除授权管理页外全部功能）/ `auditor` 只读；支持改密/改角色/停用/删除（权限边界见"角色与权限"）
- **测试模式**：exe 同目录存在 `test_mode.txt` 时跳过所有鉴权（开发调试用，正式使用请删除）

## 漏洞库（可导入）

- 内置 10 条常见规则（`internal/scanner/vuln_builtin.json`，编译进 exe）
- **自定义导入**：两种方式 —— UI「引擎与规则 → 规则」页粘贴 JSON 导入（校验后写入 `vuln/` 并立即生效，无需重启）；或直接在 exe 同目录建 `vuln/` 文件夹放入 `*.json`（重启后加载）。UI 中还可查看全部已加载规则与内置规则原始 JSON
- 规则格式（三种 type）：

```json
{
  "rules": [
    { "id": "MY-0001", "name": "目录列表", "severity": "low",
      "type": "body", "pattern": "<title>\\s*Index of /", "detail": "响应为目录列表" },
    { "id": "MY-0002", "name": "ASP.NET 版本", "severity": "info",
      "type": "header", "pattern": "(?m)^X-AspNet-Version: .*\\d", "detail": "版本暴露" },
    { "id": "MY-0003", "name": "敏感路径", "severity": "medium",
      "type": "path", "pattern": "/.env.local", "detail": "路径存在即报" }
  ]
}
```

`body`/`header` 的 `pattern` 是 Go 正则；`path` 的 `pattern` 是探测路径（非 404 即命中）。
规则无需自己从零收集：可参考 Nuclei 社区模板（github.com/projectdiscovery/nuclei）把现成规则转成上述格式导入。

## Nuclei 模板扫描

- 两套独立规则：内置漏洞库（`vuln_builtin.json`）与 Nuclei 模板互不影响；**默认启用**（带 `-no-nuclei` 启动可关闭），主界面勾选框默认选中，勾选后可设置 tag 参数
- 内置 5 个模板已打包进 exe；外部模板放 exe 同目录 `templates/`（或 `-nuclei-dir` 指定），同 ID 可覆盖内置
- 支持 tag 黑白名单过滤；扫描中可热更新模板（`/api/nuclei/reload`，无需重启）
- 规则库在线更新（`settings.json` 的 `updater` 节）：官方 GitHub 仓库直连通道或自建镜像源，页面可查新版/一键更新/回滚
- 生成自用规则包：`nuclei-templates/`（自行 clone 官方仓库到仓库根）→ `go run scripts/nuclei2json.go -dir ./nuclei-templates -out dist/vuln/nuclei.json`

## 外部引擎（可选）

内置引擎开箱即用；需要专业引擎的完整能力（OS 探测 / 容器镜像 / 主动攻击）时：

1. UI「引擎与规则」页的**引擎**页签**一键下载安装**（支持代理 / GitHub 镜像，自动测速选最快），或手动把二进制放到 exe 同目录 `bin/`（`nmapcore` / `trivycore` / `zapcore` / `nucleicore`，前缀匹配即可）
2. `settings.json` 设 `engine.enabled=true` 接入扫描编排：**外部引擎优先，缺失/失败自动降级内置引擎**（超时/取消不算失败，直接透传）
3. ZAP 是 Java 程序：下载模块会**自动装一个专用 JDK 17**（放在 `bin/zapcore/ZAP_<ver>/jre/`，与系统 Java 隔离，不污染 PATH）

默认全关：不启用时不启动任何外部进程，行为与单机内置引擎完全一致。

## 弱口令 / 空口令检测（可选）

- `settings.json` 的 `authcheck` 节启用（**节缺失即关闭，零连接**）；目标 CIDR 白名单外的请求直接拒绝
- 支持 10 种协议：redis / mysql / postgresql / ftp / telnet / ssh / smb / vnc / rdp / oracle，用 top100 常见口令字典（内置）+ exe 同目录自定义字典做**真实试探**
- 明确的能力边界：写不到"可靠判定"的分支一律返回"协议不支持"并在结果里标明（不伪造成"口令错误"）；MSSQL 的 TDS 登录未实现，界面上不展示该协议
- 令牌桶限速 + 尝试次数上限；每次尝试落审计日志（口令只在命中时出现）

## AI 全链路分析（可选插件）

**默认关闭**（关闭时零 LLM 调用）。开启：`-ai` 参数，或 `settings.json` 的 `ai` 节 `enabled=true`，或「AI 配置」页点「测试并保存」（连通通过才落盘，热生效免重启）。

**数据流**：业务页（抓包 / 扫描 / 弱口令 / 监控）点 **AI 分析** → 组装绑定的 Prompt 模板 + 变量（**强制脱敏**）+ RAG 文档库 TopK + 结构化记忆库历史 → 提交 Ollama / OpenAI 兼容 LLM（**只解读、不判定、不生成 POC**，LLM 失败不写报告）→ 研判**回写报告中心对应报告**（`aiNote` / `aiData` / `aiAnalyzedAt`），原始数据与 AI 研判同时查看，合并时 AI 内容随源报告保留。

**两类知识库（严格区分）**：**RAG 文档库** = 用户上传的**非结构化文档**（自动分片 + 内置 TF-IDF 离线向量化，存 `data/ai_docs.jsonl`）；**结构化记忆库** = 平台业务表**历史**的只读检索（资产/漏洞/告警/抓包/节点指标，时间窗 + 范围，不额外存储，注入 `{{structured_memory}}` 变量）。

`ai` 节字段与 `/api/ai/*` 路由（状态 / 配置 / 模板 / RAG / 记忆库 / 分析）完整结构见 `settings.example.json`；写操作需 admin/operator。

## 报告模板

- **报告生成引擎**（`settings.json` 的 `report` 节启用，默认关闭）：风险评分、修复建议、资产拓扑、两轮扫描历史对比（新增/修复/持续存在三分桶）、扫描结束自动触发；PDF 走浏览器打印通道（纯标准库无 PDF 库），由浏览器另存为
- 默认模板已内置（`web/report.html`），导出为 A4 排版 HTML：封面（标题/风险等级/目标/操作者）、风险概况统计、逐次扫描明细（发现 + 结果表）、总体建议、免责声明
- **自定义模板**：在 exe 同目录放 `report_template.html`（Go text/template 语法），修改后立即生效（无需重启）
- 可用变量：`.Title` `.Operator` `.Tool` `.Time` `.RiskLevel`(高/中/低/无) `.TotalFindings` `.High` `.Medium` `.Low` `.Info`，`.Scans` 数组（每项含 `typeName` `target` `startTime` `duration` `summary` `rowHead` `rows` `findings[severity/title/detail]`），函数 `add`

## 报告中心（原始报告底座）

「报告中心 → 原始报告」：四大业务模块（抓包 / 扫描 / 弱口令 / 节点监控）执行完成后的**原始结构化结果**自动存到这里 —— 只存原始数据、不做加工，AI 结果字段已预留。存档是 best-effort（失败只记日志、不影响业务）；`report.autoSave`（默认开）/ `report.maxRaw`（默认 500 份，超限按时间淘汰最旧）。

- **存储时机**：抓包 = 点"停止抓包"；扫描 = 本地管线收尾 + 探针回传落库；弱口令 = 批次结束；节点监控 = 仅"立即采集一轮"完成（**周期轮询不自动存档**，60s 一轮会刷屏，可手动存快照）。
- **筛选**：来源模块 / 标签 / 资产 IP / 时间范围 / 关键字，可组合。
- **合并**（勾选 ≥2 份）：**整合不是聚合** —— 各源正文按模块分组进 `sections` **原文照搬不改写**，资产 / 标签取并集，`sourceIds` 记录全部源 ID 可下钻，**源报告不被合并消耗**，8MB 正文上限。
- 数据存 `data/raw_reports.jsonl`（每份一行），`payload` 为各模块原始结果完整 JSON（抓包含环形缓冲内全部报文 ≤2000 条，扫描口径与落库一致，口令字段展示层剥离）。

API：`/api/v2/raw/*`（list / {id} 详情 / 删除 / merge / snapshot / options），均 requireAuth + 写操作 admin/operator。

## 分布式扫描（中心端 + 探针端）

两个独立程序，各有各的部署位置：

| 程序 | 部署位置 | 作用 |
| --- | --- | --- |
| `yugsight_windows_amd64.exe` | 中心机器 | Web UI、本地扫描、探针管理、任务下发、结果落库 |
| `yugsight-agent.exe` | 各探针机器 | 上报节点信息、接收并执行任务、回传结果（无 Web UI、零入站端口） |

> 探针不是必需件：中心端本身已具备完整的网络扫描 / 漏洞扫描 / 监控能力（覆盖它能直接到达的目标）。探针把采集范围延伸到装探针的机器 —— 跨网段 / 跨三层中心端够不到的本地网络信息、机器系统层面的中间件 / 数据库 / 进程 / 服务 / 已安装软件，只有部署了探针才能采集。

**中心端**：exe 同目录 `settings.json` 的 `probe.center` 节（或启动加 `-probe=center`）：

```json
{ "probe": { "center": { "enabled": true, "listen": ":8600", "token": "你的密钥" } } }
```

**探针端**：把 `yugsight-agent.exe` 拷过去，同目录放 `settings.json` 的 `probe.client` 节：

```json
{ "probe": { "client": { "enabled": true, "centerAddr": "192.168.1.10:8600", "token": "你的密钥" } } }
```

也可以直接用命令行（免配置，适合容器/批量部署）：

```
yugsight-agent.exe -center 192.168.1.10:8600 -token 你的密钥
```

探针包无需手工拷：中心端 UI「节点监控 → 探针节点管理」提供**下载探针**入口（`agents/` 目录下的 6 平台包，由 `scripts/build-agents.ps1` 产出），页面还给出逐平台的部署命令；探针支持**自动更新**（中心端版本比对，带签名的临时 URL 下发）。

探针日志写 exe 同目录 `yugsight-agent.log`。断线自动重连（指数退避，上限 60s），中心端恢复后自动重新上线。

**默认全关**：不写 `probe` 节时，两个程序都保持单机 / 待命状态，不监听端口、不发起外连。

> 提示：为确保两台机器通信正常，中心端 `listen` 需绑定到探针可达的地址（如 `0.0.0.0:8600`），并放行该端口。

## 节点监控（阶段 1：采集底座）

「诊断与观测 → 节点监控」（/nodemonitor）是主机侧与网络侧的统一监控入口，页内两个 Tab，阶段 1 只建**采集底座**（调度 / 限速 / 白名单 / 时序存储 / 异常事件 / 标准化输出）。**默认关闭**：`settings.json` 没有 `collect` 节 = 未启用（不跑循环、不监听、不外连），在页面「采集配置」区显式开启。

### Tab 1：探针节点管理
上半 = agent 分布式探针全部功能（节点表 / 任务下发 / 下载探针 / 任务明细，见「分布式扫描」节）；下半 = **主机侧扩展采集（无代理）**，目标机装不了探针时走协议：

| 协议 | 目标 | 采集内容 |
|---|---|---|
| WinRM | `host:5985`（HTTP）/ `host:5986`（TLS） | CPU、内存、各盘容量、进程 TOP10 |
| SSH 命令采集 | `host:22` + 用户名，**仅密钥登录** | CPU（/proc/stat 双采样差分）、内存、负载、磁盘、进程 TOP10、系统告警 |
| 主机 SNMP | `host:161` + 社区串（v2c）或 v3 认证 | HR-MIB 只读：CPU / 内存 / 磁盘 / 运行时长 |

### Tab 2：网络设备监控
上半 = SNMP 设备监控（v2c / v3，轮询 ≥5s，CPU / 内存 / 流量 / 接口 up 数，随时「立即采集一轮」；全程只读 GET/GETBULK 不改设备配置）；下半 = **网络侧扩展采集（SNMP 之外）**：

| 协议 | 目标 | 采集内容 |
|---|---|---|
| ICMP 链路探测 | `ip`（次数 1–20） | 平均 / 最小 / 最大时延、抖动、丢包率 |
| NetFlow/IPFIX | **监听地址**（默认 `0.0.0.0:2000`，UDP 接收） | 活跃流数、流入速率、TOP5 五元组流 |
| NETCONF | `host:8300` + 账密，TLS 通道（RFC 8012） | 接口状态 + 数值计数器 |
| RESTCONF | `host:443` + 账密，HTTPS + JSON（YANG） | 接口状态 + 计数器 |

### 采集配置与事件
- **采集配置**（页面底部、两 Tab 共用，写 `collect` 节、保存即热生效）：总开关 / 间隔 / 并发 / 全局限速 / 保留时长 / **IP 白名单**（防误配对外网段发流量；NetFlow 被动接收不拦）/ NetFlow 接收 / **告警阈值**。
- **口令**（SNMP / WinRM / SSH / NETCONF / RESTCONF 账密）密文存储：密钥取环境变量 `YUGSIGHT_MONITOR_KEY`；API 永不回传明文，编辑留空 = 不修改。
- **异常事件**全部**边缘触发**：`offline` / `recover` / `high_cpu` / `high_mem` / `high_rtt` / `high_loss`，落 `collect_events`（保留 30 天）+ SSE 广播；每轮结果落 `collect_samples`（保留时长 + 每任务轮数双限）。
- 能力边界（不支持的如实报错、不做假降级）：NETCONF 仅 TLS 通道；SSH 仅密钥登录；NetFlow 支持 v5 / IPFIX（v9 忽略）；WinRM 用 HTTP Basic（域 / Negotiate 不支持）；RESTCONF 数据路径由设备 YANG 模型决定。

## 常见问题

| 现象 | 原因与处理 |
|---|---|
| 点菜单没反应、控制台报 `Failed to fetch dynamically imported module` | 页面引用的前端资源没取到。① 升级/重新构建后**旧标签页**里的 chunk hash 已失效 → Ctrl+F5 强刷；② 构建时漏了前端产物（`frontend/dist/` 未提交或未 `npm run build`）→ 见"构建与重新编译" |
| 服务进程还在、端口也在听，但怎么都连不上 | 绑定的是**单个 IP**且该 IP 已不在本机（DHCP 换租 / 插拔 VPN / 网卡切换）。默认已绑 `0.0.0.0`（全部网卡）不受影响；若用 `-bind-local` 启动，重新启动进程即可恢复正常 |
| 启动后端口不是 8420 | 8420 起连续 20 个端口被占用时会自动顺延，真实地址看控制台标题栏或启动日志的 `UI 地址` |
| 想清空历史数据（漏洞记录 / 审计日志） | 漏洞记录：**漏洞管理**页右上「清空全部漏洞」（admin/operator，需输入"清空"确认，只清漏洞表、资产台账不动）；审计日志：**授权管理**页审计区的「清空日志」或行内「删除」（仅 admin）。两者都会留下清理审计记录，属设计如此 |
| 找不到"停止服务"按钮 | 只在两处：登录页底部链接、授权管理页"服务管理"卡片（`/api/quit` 免登录）。关控制台窗口不会停服务 |
| 抓包页提示"未找到安装器" | exe 同目录缺 `npcap-1.86.exe`（构建时未附带），从 Nmap 官网下载该版本放到 exe 同目录即可 |
| 大屏地球白屏 / 地理信息全 unknown | exe 同目录缺 `globe/` 或 `geoip/` 数据（构建时 `build/` 下对应目录缺失会跳过），属降级而非报错：跑 `scripts/geoip_sync.go` 生成后重新构建 |

## 安全声明

本工具仅可用于扫描**自己拥有或已获书面授权**的目标系统。未经授权对他人系统扫描可能违反相关法律法规，后果自负。

## 许可证

MIT，见 `LICENSE`。

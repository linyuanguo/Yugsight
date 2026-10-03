// ===== 扫描类型常量(立即扫描与任务队列共用的唯一事实来源) =====
// 合并前 Console 与 Scans 各自维护一份类型下拉 / 目标 label / placeholder /
// quick→unified|ip 映射, KIND_NAME 还是任务表展示用的第四份 —— 改一处要同步
// 四处。菜单 B 方案(2026-09-22)把两页合并后统一到这里。

// 三种展示类型: value 是前端表单取值, label 是下拉显示文案
// 2026-09-25 用户口径命名: "主机漏扫 / web 漏扫"(原来叫"深度主机/Web 漏洞"),
// 控制台"下一步"按钮与下拉选项用同一套名字, 用户选哪个就填哪种目标。
export const SCAN_TYPES = [
  { value: 'quick', label: '快速发现(存活+端口)' },
  { value: 'host', label: '主机漏扫' },
  { value: 'web', label: 'Web 漏扫' },
  // 2026-09-26: 镜像/文件扫描(trivy SCA) —— 独立维度, 扫本地文件/镜像/容器的依赖漏洞,
  // 与"远程主机端口/服务扫描"(quick/host/web)是两回事, 目标填镜像名或本地路径。
  { value: 'image', label: '镜像/文件扫描 (trivy)' }
]

// 展示类型 -> 后端 scanReq.type 的 kind:
// quick 映射到统一扫描引擎 unified, "仅存活检查"时映射到 ip(不枚举端口);
// host/web 与后端 kind 同名, 原样透传。
export function typeToKind(type, aliveOnly) {
  if (type === 'quick') return aliveOnly ? 'ip' : 'unified'
  return type
}

// 各类型目标输入框的 label 与 placeholder(2026-09-25: 命名扫描放宽为多目标
// —— 快速发现/主机漏扫可多个 IP/子网, web 漏扫可多个域名, 逗号/空格分隔)
export const TARGET_LABEL = { quick: '目标 (IP/子网)', host: '目标 IP (可多个)', web: '目标域名 (可多个)', image: '镜像名 / 本地路径' }
export const TARGET_PH = {
  quick: 'IP/子网, 多个用逗号或空格分隔, 如 192.168.1.10 10.0.0.0/24',
  host: '单个或多个 IP, 如 192.168.1.10, 192.168.1.11',
  web: '域名或 URL, 如 example.com, http://192.168.1.20',
  image: 'Docker 镜像名(如 nginx:1.25) 或 本地路径(如 ./myapp、/opt/repo)'
}

// 任意后端 kind 的显示名。任务表历史任务可能带旧 kind(ip/port/unified),
// 必须保留映射, 否则旧数据会直接把英文原文显示给用户。
export const KIND_NAME = {
  quick: '快速发现', unified: '快速发现', ip: '存活检查', port: '端口扫描',
  web: 'Web 漏扫', host: '主机漏扫',
  image: '镜像/文件扫描', fs: '镜像/文件扫描', container: '镜像/文件扫描',
  // 2026-09-27: 探针端 ARP 异常监测(环路/IP 冲突/MAC 漂移)
  arp: 'ARP 异常监测'
}

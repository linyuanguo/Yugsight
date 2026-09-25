// ===== 扫描类型常量(立即扫描与任务队列共用的唯一事实来源) =====
// 合并前 Console 与 Scans 各自维护一份类型下拉 / 目标 label / placeholder /
// quick→unified|ip 映射, KIND_NAME 还是任务表展示用的第四份 —— 改一处要同步
// 四处。菜单 B 方案(2026-09-22)把两页合并后统一到这里。

// 三种展示类型: value 是前端表单取值, label 是下拉显示文案
export const SCAN_TYPES = [
  { value: 'quick', label: '快速发现(存活+端口)' },
  { value: 'host', label: '深度主机' },
  { value: 'web', label: 'Web 漏洞' }
]

// 展示类型 -> 后端 scanReq.type 的 kind:
// quick 映射到统一扫描引擎 unified, "仅存活检查"时映射到 ip(不枚举端口);
// host/web 与后端 kind 同名, 原样透传。
export function typeToKind(type, aliveOnly) {
  if (type === 'quick') return aliveOnly ? 'ip' : 'unified'
  return type
}

// 各类型目标输入框的 label 与 placeholder(网段/单机/URL 三种填法)
export const TARGET_LABEL = { quick: '网段 CIDR', host: '目标 IP', web: '目标 URL' }
export const TARGET_PH = { quick: '如 192.168.1.0/24', host: '如 192.168.1.10', web: '如 http://192.168.1.10' }

// 任意后端 kind 的显示名。任务表历史任务可能带旧 kind(ip/port/unified),
// 必须保留映射, 否则旧数据会直接把英文原文显示给用户。
export const KIND_NAME = {
  quick: '快速发现', unified: '快速发现', ip: '存活检查', port: '端口扫描',
  web: 'Web 漏洞', host: '深度主机'
}

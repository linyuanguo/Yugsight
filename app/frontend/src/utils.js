// 通用小工具(纯前端, 无依赖)

export function fmtDT(s) {
  if (!s) return '-'
  const d = new Date(s)
  if (isNaN(d.getTime())) return s
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

export function fmtNow() {
  return fmtDT(new Date())
}

export function sevRank(sev) {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[String(sev || '').toLowerCase()] ?? 5
}

export const SEV_NAME = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
export const SEV_CLASS = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low', info: 'sev-info' }

export const STATUS_NAME = {
  open: '开放', new: '新发现', duplicate: '重复', fixed: '已修复',
  pending: '待执行', running: '执行中', success: '成功', failed: '失败', cancelled: '已取消'
}

// 漏洞两态展示口径: 库内 new/duplicate/open 对用户都是"开放",
// "重复发现"不再是状态 —— 它由最后命中时间(lastSeenAt)表达(见 Vulns 页"最后命中"列)。
export function vulnStatus(s) {
  return s === 'fixed' ? 'fixed' : 'open'
}

// copyText 一键复制。局域网 http://IP:8420 是非安全上下文, navigator.clipboard 为
// undefined —— 必须回退 execCommand, 否则"复制"按钮在真实部署形态下永远静默失败。
export async function copyText(s) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(s)
      return true
    }
  } catch (e) { /* 落到下面的回退路径 */ }
  try {
    const ta = document.createElement('textarea')
    ta.value = s
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch (e) {
    return false
  }
}

// datetime-local 输入框值 -> ISO 字符串(本地时区), 空返回 ''
export function localToISO(v) {
  if (!v) return ''
  const d = new Date(v)
  return isNaN(d.getTime()) ? '' : d.toISOString()
}

// ===== 字节/速度/时长格式化(引擎下载与规则库更新共用) =====
// 从 EnvStatus.vue 提取到公共模块: 规则库更新同样有几十 MB 的源码包下载,
// 两处都要显示"已下载/总量/速度/剩余时间", 复制一份会立刻漂移。

// fmtBytes 字节数 -> 可读大小。null/undefined/负数返回 '-' 而不是 'NaN B',
// 上游对"未知长度"就是用 0/缺失表达的, 显示成 NaN 会让人以为程序出错。
export function fmtBytes(n) {
  if (n === null || n === undefined || n < 0) return '-'
  if (n < 1024) return n + ' B'
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB'
  return (n / 1073741824).toFixed(2) + ' GB'
}

// fmtSpeed 字节/秒 -> 可读速度。0 或未知返回空串(速度没测出来时不要显示 "0 B/s")
export function fmtSpeed(bps) {
  if (!bps || bps <= 0) return ''
  if (bps < 1024) return bps + ' B/s'
  if (bps < 1048576) return (bps / 1024).toFixed(0) + ' KB/s'
  return (bps / 1048576).toFixed(2) + ' MB/s'
}

// fmtDuration 秒 -> 可读剩余时间(用于"剩余约 X")。<=0 或非有限值返回空串。
export function fmtDuration(sec) {
  if (!sec || !isFinite(sec) || sec <= 0) return ''
  if (sec < 60) return Math.round(sec) + ' 秒'
  const m = Math.floor(sec / 60)
  return m < 60 ? m + ' 分 ' + Math.round(sec % 60) + ' 秒' : Math.floor(m / 60) + ' 小时 ' + (m % 60) + ' 分'
}

// etaSeconds 由"剩余字节 / 速度"估算剩余秒数。
// totalBytes<=0 表示对端未给 Content-Length, 此时无法估算, 返回 0 由调用方隐藏 ETA。
export function etaSeconds(bytes, totalBytes, speed) {
  if (!totalBytes || totalBytes <= 0 || !speed || speed <= 0) return 0
  const left = totalBytes - (bytes || 0)
  return left <= 0 ? 0 : Math.round(left / speed)
}

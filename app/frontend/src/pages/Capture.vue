<template>
  <div>
    <PageHeader title="实时抓包分析" desc="抓包、过滤与报文十六进制详情">
      <span class="chip" :class="running ? 'on' : 'off'">{{ running ? '抓包中' : '未抓包' }}</span>
      <button class="btn sm" @click="loadDevices(true)"><span class="spinner" v-if="devLoading"></span> 刷新适配器</button>
    </PageHeader>

    <!-- 捕获控制 -->
    <div class="card">
      <div class="card-title">捕获控制 <span class="sub">过滤器为 BPF 语法; 默认全量采集, 细过滤在下方展示层做</span></div>
      <div class="form-row">
        <div class="field">
          <label class="label">捕获适配器</label>
          <select class="select" v-model="device">
            <option v-for="d in devices" :key="d.name" :value="d.name">{{ (d.desc || d.name) + devLabel(d) }}</option>
          </select>
          <div class="muted small" v-if="!devices.length">未枚举到适配器{{ devErr ? ': ' + devErr : ', 请先安装 Npcap' }}</div>
          <div class="muted small" v-else>
            抓不到 ping? ping <b>本机自己</b>(含本机 IP)请选回环适配器; ping 其它主机请选实际出口网卡;
            交换网络里抓不到<b>另外两台机器之间</b>的单播流量(只能看到广播/组播与本机流量)。
          </div>
        </div>
        <div class="field">
          <label class="label">BPF 过滤器(可选)</label>
          <input class="input mono" v-model.trim="filter" placeholder="如 tcp port 80 / arp / icmp" @keyup.enter="start">
        </div>
      </div>
      <!-- ping 自己抓不到的根因提示: 把本机 IP 直接摆出来(用户 ping 的目标若等于它,
           流量只走回环适配器, 选物理网卡必然抓空) -->
      <div class="alert warn" v-if="localIP" style="margin-top:8px">
        本机 IP: <b class="mono">{{ localIP }}</b> —— 如果 ping 的目标是这个 IP(本机自己),
        流量只走<b>回环适配器 NPF_Loopback</b>(列表中已单独标出), 选物理网卡抓不到
      </div>
      <div class="cap-actions">
        <button class="btn primary" :disabled="busy || running" @click="start">开始抓包</button>
        <button class="btn" :disabled="busy || !running" @click="stop">停止</button>
        <!-- 仅 Windows 且未装 Npcap 时给入口: 其它平台走系统 libpcap, 没有安装器可下 -->
        <button class="btn green" v-if="showInstall" :disabled="busy" @click="installNpcap">
          <span class="spinner" v-if="installing"></span> 安装 Npcap
        </button>
        <span class="muted small">{{ hint }}</span>
      </div>
      <div class="alert error" v-if="capErr">{{ capErr }}</div>
    </div>

    <!-- 统计 -->
    <div class="grid cols-4" style="margin-top:14px">
      <StatCard label="总包数" :value="fmtNum(stats.total)" :sub="'速率 ' + (stats.pps || 0).toFixed(1) + '/s'" tone="blue" />
      <StatCard label="持续时长" :value="(stats.durationSec || 0) + 's'" :sub="'环路检测 ' + (stats.loopDetect ? '开' : '关')" tone="green" />
      <StatCard label="ARP / IPv4" :value="fmtNum(stats.arpTotal) + ' / ' + fmtNum(stats.ipv4)"
                :sub="'ARP ' + (stats.arpPps || 0).toFixed(1) + '/s · 广播 ' + fmtNum(stats.broadcast)" tone="orange" />
      <StatCard label="报文留存" :value="(stats.pktBuffered || 0) + '/' + (stats.pktCapacity || 2000)"
                :sub="'解码跳过 ' + fmtNum(stats.pktUndecodable) + ' · 畸形帧 ' + fmtNum(stats.badFrames)" tone="purple" />
    </div>

    <!-- 报文列表(抽屉式: 标题行常驻, 表体可展开/收起; 表头冻结) -->
    <div class="card" style="margin-top:14px">
      <div class="card-title cap-pkt-head" @click="listOpen = !listOpen" :title="listOpen ? '点击收起报文列表' : '点击展开报文列表'">
        报文列表
        <span class="sub">内存环形缓冲(≤2000 条), 不写本地磁盘, 停止抓包即清空; 需要留存请导出 PCAP</span>
        <div class="spacer" style="flex:1"></div>
        <span class="muted small" v-if="!listOpen">当前 {{ packets.length }} 条 · 点击展开</span>
        <button class="btn sm" :disabled="!packets.length || pcapBusy"
                :title="packets.length ? '把当前缓冲的全部报文导出为 pcap 文件(Wireshark/tcpdump 可打开)' : '还没有报文'"
                @click.stop="exportPcap">
          <span class="spinner" v-if="pcapBusy"></span> 导出 PCAP
        </button>
        <button class="btn sm" @click.stop="listOpen = !listOpen">{{ listOpen ? '收起' : '展开' }}</button>
      </div>
      <div v-show="listOpen" class="cap-pkt-body">
        <div class="cap-actions">
          <input class="input mono" style="max-width:280px" v-model="displayFilter"
                 placeholder="通用: 192.168.1.1 port:443 proto:tcp">
          <input class="input mono" style="max-width:190px" v-model="srcQ"
                 placeholder="源搜索(如 192.168.1.6)">
          <input class="input mono" style="max-width:190px" v-model="dstQ"
                 placeholder="目的搜索">
          <label class="checkbox"><input type="checkbox" v-model="autoScroll">自动滚动</label>
          <div class="spacer" style="flex:1"></div>
          <button class="btn sm danger" @click="clearList">清空列表</button>
        </div>
        <!-- 经典页迁移(P1-3): 过滤示例 chips, 点击立即生效(展示层语义: 空格=与, 前缀限定字段) -->
        <div class="filter-chips">
          <span v-for="x in FILTER_EXAMPLES" :key="x.f" class="chip"
                :class="{ on: displayFilter === x.f }" :title="x.tip"
                @click="displayFilter = x.f">{{ x.f || '全部' }}</span>
        </div>
        <div class="muted small" style="margin:8px 0">{{ listHint }}</div>

        <div class="table-wrap cap-pkts" ref="listBox">
          <table class="table" v-if="view.length">
            <thead>
              <tr><th>时间</th><th>协议</th><th>源</th><th>目的</th><th>长度</th><th>摘要</th></tr>
            </thead>
            <tbody>
              <tr v-for="p in view" :key="p.seq" class="clickable"
                  :class="{ 'cap-sel': detail && detail.seq === p.seq, 'cap-bcast': isBcast(p) }"
                  @click="openDetail(p)">
                <td class="mono muted small">{{ p.time }}</td>
                <td><span class="badge">{{ p.protocol || '?' }}</span></td>
                <td class="mono">{{ endpoint(p.srcIp, p.srcMac, p.srcPort) }}</td>
                <td class="mono">{{ endpoint(p.dstIp, p.dstMac, p.dstPort) }}</td>
                <td class="mono muted">{{ p.length || 0 }}</td>
                <td class="cap-info">{{ p.info || '' }}</td>
              </tr>
            </tbody>
          </table>
          <Empty v-else :text="emptyText" />
        </div>
      </div>
    </div>

    <!-- 报文详情 -->
    <div class="card" v-if="detail" style="margin-top:14px">
      <div class="card-title">
        报文 #{{ detail.seq }} 详情
        <span class="sub">{{ detail.time }} · {{ detail.length }} 字节</span>
        <button class="btn xs" style="margin-left:auto" @click="detail = null">关闭</button>
      </div>
      <div class="kv">
        <div class="k">协议</div><div class="v">{{ detail.protocol || '-' }}</div>
        <div class="k">源 MAC</div><div class="v mono">{{ detail.srcMac || '-' }}</div>
        <div class="k">目的 MAC</div><div class="v mono">{{ detail.dstMac || '-' }}</div>
        <div class="k">源地址</div><div class="v mono">{{ endpoint(detail.srcIp, detail.srcMac, detail.srcPort) }}</div>
        <div class="k">目的地址</div><div class="v mono">{{ endpoint(detail.dstIp, detail.dstMac, detail.dstPort) }}</div>
        <div class="k">TTL</div><div class="v mono">{{ detail.ttl || '-' }}</div>
        <div class="k">以太类型</div><div class="v mono">{{ detail.etherType || '-' }}</div>
        <div class="k">摘要</div><div class="v">{{ detail.info || '-' }}</div>
      </div>
      <template v-if="hexRows.length">
        <div class="muted small" style="margin:12px 0 6px">
          原始字节({{ hexBytes.length }} 字节{{ detail.length > hexBytes.length ? ', 完整帧请用 PCAP 导出' : '' }})
        </div>
        <pre class="code-block cap-hex">{{ hexText }}</pre>
      </template>
      <div class="muted small" v-else>该报文无原始字节载荷</div>
    </div>

    <!-- 经典页迁移(P1-3): 智能分析(内置引擎) + 阶段 3 AI 全链路分析 -->
    <div class="card" style="margin-top:14px">
      <div class="card-title">
        抓包分析
        <div class="spacer"></div>
        <button class="btn sm" :disabled="analyzing" @click="runAnalysis">
          <span class="spinner" v-if="analyzing"></span> 智能分析(内置引擎)
        </button>
        <!-- 阶段 3: AI 分析(模板+RAG+记忆库, 结果存报告中心)。抓包中点击 = 先停止
             抓包(会话自动存档)再分析本会话; 未启用/模块关闭时按钮自动置灰。 -->
        <AiAnalyzeButton ref="aiBtn" module="capture" label="AI 分析" :before="aiBefore" />
      </div>
      <p class="muted small" style="margin:0 0 8px">
        AI 参数/模板/知识库在
        <router-link to="/settings/ai">系统配置 → AI 配置</router-link>
        中管理; 分析结果存报告中心对应报告(原始报文 + AI 研判可同时查看)。
      </p>
      <pre class="code-block cap-ai" v-if="analysisText">{{ analysisText }}</pre>
    </div>

    <!-- 经典页迁移(P1-3): 检测事件流(环路/风暴/ARP 漂移) + ARP 绑定表 -->
    <div class="grid cols-2" style="margin-top:14px">
      <div class="card">
        <div class="card-title">检测事件 <span class="sub">环路 / 广播风暴 / ARP 漂移</span>
          <div class="spacer"></div>
          <button class="btn xs" @click="events = []">清空</button>
        </div>
        <div class="cap-events">
          <div v-if="!events.length" class="empty">无事件(开启环路检测后, 命中判据会实时列在这里)</div>
          <div v-for="(e, i) in events" :key="e.seq || i" class="cap-ev">
            <span class="mono muted small">{{ e.time }}</span>
            <span class="badge" :class="e.severity === 'high' ? 'st-failed' : (e.severity === 'medium' ? 'st-pending' : 'st-success')">
              {{ e.severity === 'high' ? '高危' : (e.severity === 'medium' ? '中危' : '低危') }}
            </span>
            <span class="small">{{ e.title }} — {{ e.detail }}</span>
            <div class="muted small" v-if="e.advice" style="margin-left:26px">建议: {{ e.advice }}</div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">ARP 绑定表 <span class="sub">MAC 漂移即告警</span></div>
        <div class="table-wrap" style="max-height:280px; overflow-y:auto">
          <table class="table" v-if="bindings.length">
            <thead><tr><th>IP</th><th>MAC</th><th>次数</th><th>最近操作</th><th>首次发现</th><th>最近发现</th><th>状态</th></tr></thead>
            <tbody>
              <tr v-for="b in bindings" :key="b.ip + b.mac">
                <td class="mono small">{{ b.ip }}</td>
                <td class="mono small">{{ b.mac }}</td>
                <td>{{ b.count }}</td>
                <td class="small">{{ b.lastOp || '-' }}</td>
                <td class="mono small muted">{{ b.firstSeen || '-' }}</td>
                <td class="mono small muted">{{ b.lastSeen || '-' }}</td>
                <td><span class="badge" :class="b.flapping ? 'st-failed' : 'st-success'">{{ b.flapping ? '漂移' : '正常' }}</span></td>
              </tr>
            </tbody>
          </table>
          <Empty v-else text="开始抓包后显示 ARP 绑定表" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import Empty from '../components/Empty.vue'
import StatCard from '../components/StatCard.vue'
import AiAnalyzeButton from '../components/AiAnalyzeButton.vue'
import { api } from '../api/http'

// 页面最多保留的报文条数(与后端环形缓冲同容量: 再多前端也拿不到更旧的数据)
const CAP_PKT_MAX = 2000
// 一次渲染的行数上限: 几千个 <tr> 会让浏览器明显卡顿, 而排障只关心最近发生的事
const VIEW_MAX = 500
const POLL_MS = 1500

const devices = ref([])
const device = ref('')
const devErr = ref('')
const devLoading = ref(false)
const filter = ref('')

const running = ref(false)
const busy = ref(false)
const capErr = ref('')
const hint = ref('')
const stats = reactive({})
const platform = ref('')
const npcapInstalled = ref(true)
const installing = ref(false)
// 本机 IP(服务端回带): 用于"ping 自己抓不到"提示 —— 用户 ping 的目标若等于它,
// 流量只走回环适配器
const localIP = ref('')

const packets = ref([])
const cursor = ref(0)
const displayFilter = ref('')
// 源/目的独立搜索框: 通用过滤里 "80" 会同时命中 IP 与端口, 独立框直接锁定字段
const srcQ = ref('')
const dstQ = ref('')
const autoScroll = ref(true)
const detail = ref(null)
const listBox = ref(null)
// 抽屉式展开/收起(默认展开, 收起时标题行仍常驻显示条数)
const listOpen = ref(true)
const pcapBusy = ref(false)

let timer = null

const showInstall = computed(() => platform.value === 'windows' && !npcapInstalled.value)

// ===== 展示层过滤示例 chips =====
// 语义与 matchPkt 一致: 空格=与, 前缀限定字段。空值=不过滤。
// (原先还有一个"协议下拉", 与这里的 chips 职能重叠 —— 两处筛选并存会让用户
// 不知道以哪个为准, 已统一到下面的示例中。)
const FILTER_EXAMPLES = [
  { f: '', tip: '不过滤(显示全部)' },
  { f: 'icmp', tip: '只看 ICMP (ping / 回显)' },
  { f: 'arp', tip: '只看 ARP' },
  { f: 'tcp', tip: '只看 TCP' },
  { f: 'udp', tip: '只看 UDP' },
  { f: 'ipv6', tip: '只看 IPv6' },
  { f: 'icmpv6', tip: '只看 ICMPv6' },
  { f: 'igmp', tip: '只看 IGMP(组播)' },
  { f: 'syn', tip: '只看 SYN 包(建连/扫描)' },
  { f: 'rst', tip: '只看 RST 包(连接被拒)' },
  { f: 'fin', tip: '只看 FIN 包(断连)' },
  { f: '广播', tip: '只看广播帧' },
  { f: 'port:80', tip: 'HTTP' },
  { f: 'port:443', tip: 'HTTPS' },
  { f: 'port:53', tip: 'DNS' },
  { f: 'port:22', tip: 'SSH' },
  { f: 'port:3389', tip: '远程桌面' },
  { f: 'port:445', tip: 'SMB 文件共享' },
  { f: 'proto:icmp', tip: '按协议字段限定 ICMP' },
  { f: 'ip:192.168.1.1', tip: '只看涉及该 IP 的报文' },
  { f: 'src:192.168.1.1', tip: '只看该 IP 发出的报文' },
  { f: 'dst:192.168.1.1', tip: '只看发给该 IP 的报文' },
]



// ===== 展示层过滤: 与经典页 web/index.html 的 capMatch 同口径 =====
//
// 多个关键字之间是"与"(全部满足); 同一关键字在任意常见字段命中即可。
// 前缀形式(ip:/port:/proto:/mac:/src:/dst:)把匹配限定到具体字段 —— 否则 "80"
// 会同时命中端口 80 与 IP 里的 80, 结果混进一堆无关报文。
// 协议关键字的严格口径(同 Wireshark): 过滤 "icmp" 只看 IPv4 的 ICMP —— 子串匹配
// 会把 "ICMPv6" 的邻居发现/通告一起混进来, 用户想看 ping 却看到一堆 v6 噪声。
// tcp/udp 按协议族包含 v6 变体(说"只看 TCP"通常不区分 IP 版本); ipv6 匹配全部 v6。
const PROTO_ALIAS = {
  tcp: ['TCP', 'TCPv6'],
  udp: ['UDP', 'UDPv6'],
  icmp: ['ICMP'],
  icmpv6: ['ICMPv6'],
  igmp: ['IGMP'],
  arp: ['ARP'],
}
function protoHit(tok, p) {
  const pr = p.protocol || ''
  if (PROTO_ALIAS[tok]) return PROTO_ALIAS[tok].includes(pr)
  if (tok === 'ipv6') return pr === 'IPv6' || /v6$/i.test(pr)
  return null // 不是协议关键字: 交给文本匹配
}

// 源/目的独立搜索: 各自匹配 IP + MAC + 端口三个字段(含子串), 两框同时生效
function srcField(p) {
  return [p.srcIp, p.srcMac, String(p.srcPort || '')].filter(Boolean).join(' ').toLowerCase()
}
function dstField(p) {
  return [p.dstIp, p.dstMac, String(p.dstPort || '')].filter(Boolean).join(' ').toLowerCase()
}
function matchPkt(p) {
  const s = (srcQ.value || '').trim().toLowerCase()
  if (s && !srcField(p).includes(s)) return false
  const d = (dstQ.value || '').trim().toLowerCase()
  if (d && !dstField(p).includes(d)) return false
  const q = (displayFilter.value || '').trim()
  if (!q) return true
  const hay = [p.srcIp, p.dstIp, p.srcMac, p.dstMac, p.protocol, p.info,
    String(p.srcPort || ''), String(p.dstPort || ''), p.etherType]
    .filter(Boolean).join(' ').toLowerCase()
  for (const tok of q.toLowerCase().split(/\s+/).filter(Boolean)) {
    if (tok === '广播') { if (!isBcast(p)) return false; continue }
    const m = tok.match(/^(ip|port|proto|mac|src|dst):(.*)$/)
    if (!m) {
      const hit = protoHit(tok, p)
      if (hit !== null) { if (!hit) return false; continue }
      if (!hay.includes(tok)) return false
      continue
    }
    const [, field, val] = m
    let ok = false
    switch (field) {
      case 'ip': ok = [p.srcIp, p.dstIp].some(x => x && x.toLowerCase().includes(val)); break
      case 'port': ok = String(p.srcPort || '') === val || String(p.dstPort || '') === val; break
      case 'proto': ok = (p.protocol || '').toLowerCase().includes(val); break
      case 'mac': ok = [p.srcMac, p.dstMac].some(x => x && x.toLowerCase().includes(val)); break
      case 'src': ok = [p.srcIp, p.srcMac, String(p.srcPort || '')].filter(Boolean).join(' ').toLowerCase().includes(val); break
      case 'dst': ok = [p.dstIp, p.dstMac, String(p.dstPort || '')].filter(Boolean).join(' ').toLowerCase().includes(val); break
    }
    if (!ok) return false
  }
  return true
}

const shown = computed(() => packets.value.filter(matchPkt))
const view = computed(() => shown.value.slice(-VIEW_MAX))

const emptyText = computed(() => {
  if (running.value) return '等待报文...'
  return packets.value.length
    ? `已抓到 ${packets.value.length} 个报文, 但当前过滤条件下没有匹配项`
    : '开始抓包后, 这里会列出每个报文的源/目的/协议与摘要'
})

const listHint = computed(() => {
  const hidden = shown.value.length - view.value.length
  let s = `显示 ${view.value.length}/${shown.value.length} 条`
  if (packets.value.length > shown.value.length) s += ` (过滤自 ${packets.value.length} 条)`
  if (hidden > 0) s += `, 已省略较早的 ${hidden} 条`
  return s
})

function fmtNum(n) { return n === undefined || n === null ? '-' : String(n) }
// isBcast 广播帧: 目的 MAC 全 f, 或目的 IP 是受限/直接广播地址(如 192.168.1.255)
function isBcast(p) {
  return /^ff:ff:ff:ff:ff:ff$/i.test(p.dstMac || '') ||
    /^255\.255\.255\.255$/.test(p.dstIp || '') || /\.255$/.test(p.dstIp || '')
}
function endpoint(ip, mac, port) {
  if (ip) return ip + (port ? ':' + port : '')
  return mac || '-'
}

// ===== 十六进制 dump =====
//
// Go 的 []byte 在 JSON 里是 base64 字符串, 必须先解成字节数组再逐字节渲染
// (直接当数组用会拿到字符串, slice 出来的是字符片段, 输出全是乱码)。
function hexBytesOf(p) {
  const raw = p && p.payload
  if (!raw) return []
  if (Array.isArray(raw)) return raw
  try {
    const bin = atob(raw)
    const out = new Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff
    return out
  } catch (e) { return [] }
}

const hexBytes = computed(() => hexBytesOf(detail.value))

const hexRows = computed(() => {
  const b = hexBytes.value
  const rows = []
  for (let i = 0; i < b.length; i += 16) {
    const chunk = b.slice(i, i + 16)
    rows.push({
      off: i.toString(16).padStart(4, '0'),
      hex: chunk.map(x => x.toString(16).padStart(2, '0')).join(' '),
      ascii: chunk.map(x => (x >= 32 && x < 127) ? String.fromCharCode(x) : '.').join('')
    })
  }
  return rows
})

const hexText = computed(() =>
  hexRows.value.map(r => r.off + '  ' + r.hex.padEnd(47) + '  ' + r.ascii).join('\n'))

function openDetail(p) { detail.value = p }
function clearList() {
  packets.value = []
  cursor.value = 0
  detail.value = null
  hint.value = '列表已清空(后端仍在抓包)'
}

// ===== PCAP 导出 =====
// 走原生 fetch 取 blob(api() 会强制 JSON 解析, 二进制会乱码)。
// 导出范围=后端环形缓冲全部留存报文(≤2000 条), 与页面过滤无关 ——
// 过滤是展示层的, 导出应是"抓到的原样"。
async function exportPcap() {
  if (!packets.value.length) return
  pcapBusy.value = true
  try {
    const resp = await fetch('/api/capture/export?limit=2000', { credentials: 'same-origin' })
    if (!resp.ok) {
      let msg = 'HTTP ' + resp.status
      try { const e = await resp.json(); if (e.error) msg = e.error } catch (e2) { /* 非 JSON 忽略 */ }
      throw new Error(msg)
    }
    const blob = await resp.blob()
    const name = 'yugsight_capture_' + new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19) + '.pcap'
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = name
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(a.href)
    hint.value = '已导出 ' + name + ' (' + (blob.size / 1024).toFixed(1) + ' KB, 共 ' + packets.value.length + ' 条, 可用 Wireshark/tcpdump 打开)'
  } catch (e) {
    hint.value = 'PCAP 导出失败: ' + e.message
  } finally { pcapBusy.value = false }
}

// ===== 适配器 =====
// 回环适配器是唯一能抓到"本机访问本机"流量的设备(ping 自己、访问本机服务都只走它,
// 不过物理网卡)。不标注的话, 用户选物理网卡 ping 自己时永远抓不到包, 会以为工具坏了。
const LOOPBACK_DEV = /(loopback|回环)/i
const PSEUDO_DEV = /(wan miniport|bluetooth|tunnel|isatap|pseudo|virtual|vethernet|hyper-v|host virtual)/i

function devRank(d) {
  const s = (d.name || '') + ' ' + (d.desc || '')
  if (LOOPBACK_DEV.test(s)) return 1
  if (PSEUDO_DEV.test(s)) return 2
  return 0
}
function devLabel(d) {
  const s = (d.name || '') + ' ' + (d.desc || '')
  if (LOOPBACK_DEV.test(s)) return ' (回环适配器: ping 本机自己 / 本机互访选它)'
  if (PSEUDO_DEV.test(s)) return ' (伪适配器, 不建议抓包)'
  return ''
}

async function loadDevices(refresh) {
  devLoading.value = true
  devErr.value = ''
  try {
    const d = await api('/api/capture/devices' + (refresh ? '?refresh=1' : ''))
    // 真实网卡 -> 回环适配器 -> 其它伪适配器(默认选第 1 个, 排序错了就会"抓不到包")
    devices.value = (d.devices || []).slice().sort((a, b) => devRank(a) - devRank(b))
    if (!device.value && devices.value.length) device.value = devices.value[0].name
  } catch (e) {
    devices.value = []
    devErr.value = e.message
  } finally { devLoading.value = false }
}

// ===== 开始 / 停止 =====
async function start() {
  busy.value = true
  capErr.value = ''
  hint.value = '正在打开适配器...'
  try {
    const d = await api('/api/capture/start', {
      method: 'POST',
      body: { device: device.value, filter: filter.value, displayFilter: displayFilter.value }
    })
    running.value = true
    detail.value = null
    // 新会话的 seq 从 1 重来: 游标不归零会拉不到任何报文(后端按 seq>since 增量给)
    cursor.value = 0
    // 检测事件同理: 新会话清空旧事件, 游标归零
    events.value = []
    evtCursor = 0
    hint.value = '正在抓包: ' + (d.device || device.value)
      + (d.captureAll ? '(全量采集, 展示层过滤: ' + (displayFilter.value || '无') + ')' : '')
    await poll()
  } catch (e) {
    capErr.value = e.message
    hint.value = ''
  } finally { busy.value = false }
}

async function stop() {
  busy.value = true
  try {
    await api('/api/capture/stop', { method: 'POST' })
    running.value = false
    hint.value = '已停止'
    await pollPackets() // 补最后一批
  } catch (e) { capErr.value = e.message }
  finally { busy.value = false }
}

async function installNpcap() {
  if (!confirm('将运行 exe 同目录的 npcap-*.exe 官方安装器, 按向导完成后需重启本程序。继续?')) return
  installing.value = true
  hint.value = '正在安装 Npcap(最长等待 5 分钟)...'
  try {
    await api('/api/capture/install', { method: 'POST' })
    hint.value = 'Npcap 安装完成, 正在刷新适配器...'
    npcapInstalled.value = true
    await loadDevices(true)
  } catch (e) {
    capErr.value = 'Npcap 安装失败: ' + e.message
    hint.value = ''
  } finally { installing.value = false }
}

// ===== 轮询 =====
async function pollPackets() {
  const q = cursor.value > 0 ? `?since=${cursor.value}&limit=800` : '?limit=500'
  const d = await api('/api/capture/packets' + q)
  const list = d.packets || []
  if (list.length) {
    for (const p of list) packets.value.push(p)
    if (packets.value.length > CAP_PKT_MAX) packets.value = packets.value.slice(-CAP_PKT_MAX)
  }
  // maxSeq 游标只前进: 后端重开会话或异常时若回带更小的 seq, 会导致旧报文重复混入
  if (d.maxSeq > cursor.value) cursor.value = d.maxSeq
}

// ===== 经典页迁移(P1-3): 检测事件流 + ARP 绑定表 =====
// 事件走增量游标(since=seq), 与报文游标分开 —— 两者速率差几个数量级, 共用游标会互相拖累。
const events = ref([])
const bindings = ref([])
let evtCursor = 0

async function poll() {
  try {
    const s = await api('/api/capture/state' + (evtCursor > 0 ? `?since=${evtCursor}` : ''))
    running.value = !!s.running
    capErr.value = s.error || ''
    Object.assign(stats, s.stats || {})
    platform.value = s.platform || ''
    npcapInstalled.value = s.npcapInstalled !== false
    localIP.value = s.localIP || ''
    // 事件: 只收 seq 大于游标的新事件(服务端按 since 过滤, 这里再兜一次防重复)
    for (const e of (s.events || [])) {
      if (e.seq && e.seq > evtCursor) {
        events.value.push(e)
        evtCursor = e.seq
      }
    }
    if (events.value.length > 500) events.value = events.value.slice(-500)
    // ARP 绑定表: 全量替换(本身是小表)
    bindings.value = s.bindings || []
    if (s.running) await pollPackets()
  } catch (e) { /* 瞬时抖动, 下一轮重试 */ }
}

// ===== 经典页迁移(P1-3): 智能分析(内置引擎) =====
const analysisText = ref('')
const analyzing = ref(false)

async function runAnalysis() {
  analyzing.value = true
  try {
    const d = await api('/api/capture/analysis')
    analysisText.value = d.text || '(无数据, 请先开始抓包)'
  } catch (e) { analysisText.value = '分析失败: ' + e.message }
  finally { analyzing.value = false }
}

// ===== 阶段 3: AI 全链路分析(模板 + RAG + 记忆库, 结果存报告中心) =====
// AI 配置不在本页(统一移到 系统配置 → AI 配置 页); 本页只放触发按钮。
// before 钩子: 抓包中点击 AI 分析 = 先停止抓包(停止时会话自动存档为原始
// 报告), 再让后端按 module=capture 取本会话报告分析 —— 避免"边抓边分析"
// 后又停一次产生两份重复报告。
const aiBtn = ref(null)
async function aiBefore() {
  if (running.value) {
    try {
      await api('/api/capture/stop', { method: 'POST' })
      running.value = false
      hint.value = '已停止抓包(本会话已存入报告中心), 正在 AI 分析…'
      await pollPackets()
    } catch (e) {
      throw new Error('停止抓包失败: ' + e.message)
    }
  }
}

// 自动滚动: 数据变化后把列表容器滚到底(关掉后停在原地便于翻看)
watch([view, autoScroll], async () => {
  if (!autoScroll.value) return
  await nextTick()
  const box = listBox.value
  if (box) box.scrollTop = box.scrollHeight
})

onMounted(async () => {
  await loadDevices(false)
  await poll()
  timer = setInterval(poll, POLL_MS)
})

onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.cap-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
.cap-pkts { max-height: 520px; overflow-y: auto; }
/* 抽屉式报文列表: 表头行冻结 —— 列表滚动时第一行(表头)始终可见,
   否则滚动到 2000 条深处时用户已不知道各列是什么 */
.cap-pkts thead th { position: sticky; top: 0; z-index: 2; }
.cap-pkt-head { cursor: pointer; user-select: none; }
.cap-pkt-body { animation: capSlideIn .18s ease-out; }
@keyframes capSlideIn {
  from { opacity: 0; transform: translateY(-8px); }
  to { opacity: 1; transform: none; }
}
.cap-pkts table.table { min-width: 760px; }
.cap-info { max-width: 420px; word-break: break-all; color: var(--muted); }
.cap-bcast { background: rgba(251, 146, 60, .06); }
.cap-sel { background: rgba(56, 189, 248, .1) !important; }
.cap-hex { white-space: pre; word-break: normal; font-size: 12px; line-height: 1.55; }
.cap-ai { white-space: pre-wrap; word-break: break-word; font-size: 12px; line-height: 1.6; max-height: 400px; overflow-y: auto; }
.card-title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

/* 过滤示例 chips: 点击填入展示层过滤框, 高亮当前生效项 */
.filter-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 4px; }
.filter-chips .chip { cursor: pointer; user-select: none; }
.filter-chips .chip.on { border-color: var(--accent); color: var(--accent); }

/* AI 配置折叠区 */
.ai-cfg { margin-top: 8px; }
.ai-cfg summary { cursor: pointer; color: var(--muted); font-size: 12px; }

/* 检测事件流 */
.cap-events { max-height: 280px; overflow-y: auto; }
.cap-ev { padding: 7px 2px; border-bottom: 1px solid var(--border); display: flex; align-items: flex-start; gap: 8px; flex-wrap: wrap; }
</style>

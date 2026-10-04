<template>
  <div>
    <PageHeader :title="t('cp.title')" :desc="t('cp.desc')">
      <span class="chip" :class="running ? 'on' : 'off'">{{ running ? t('cp.running') : t('cp.idle') }}</span>
      <button class="btn sm" @click="loadDevices(true)"><span class="spinner" v-if="devLoading"></span> {{ t('cp.refreshDev') }}</button>
    </PageHeader>

    <!-- 捕获控制 -->
    <div class="card">
      <div class="card-title">{{ t('cp.capCtl') }} <span class="sub">{{ t('cp.capCtlSub') }}</span></div>
      <div class="form-row">
        <div class="field">
          <label class="label">{{ t('cp.fDevice') }}</label>
          <select class="select" v-model="device">
            <option v-for="d in devices" :key="d.name" :value="d.name">{{ (d.desc || d.name) + devLabel(d) }}</option>
          </select>
          <div class="muted small" v-if="!devices.length">{{ devErr ? t('cp.noDev') + ': ' + devErr : t('cp.noDev2') }}</div>
          <div class="muted small" v-else>
            {{ t('cp.pingNote1') }}<b>{{ t('cp.pingNote1b') }}</b>{{ t('cp.pingNote1c') }}
            {{ t('cp.pingNote2') }}<b>{{ t('cp.pingNote2b') }}</b>{{ t('cp.pingNote2c') }}
          </div>
        </div>
        <div class="field">
          <label class="label">{{ t('cp.fBpf') }}</label>
          <input class="input mono" v-model.trim="filter" placeholder="如 tcp port 80 / arp / icmp" @keyup.enter="start">
        </div>
      </div>
      <!-- ping 自己抓不到的根因提示: 把本机 IP 直接摆出来(用户 ping 的目标若等于它,
           流量只走回环适配器, 选物理网卡必然抓空) -->
      <div class="alert warn" v-if="localIP" style="margin-top:8px">
        {{ t('cp.localIp1') }}<b class="mono">{{ localIP }}</b>{{ t('cp.localIp2') }}
        {{ t('cp.localIp3') }}<b>{{ t('cp.loopbackB') }}</b>{{ t('cp.localIp4') }}
      </div>
      <div class="cap-actions">
        <button class="btn primary" :disabled="busy || running" @click="start">{{ t('cp.start') }}</button>
        <button class="btn" :disabled="busy || !running" @click="stop">{{ t('cp.stop') }}</button>
        <!-- 仅 Windows 且未装 Npcap 时给入口: 其它平台走系统 libpcap, 没有安装器可下 -->
        <button class="btn green" v-if="showInstall" :disabled="busy" @click="installNpcap">
          <span class="spinner" v-if="installing"></span> {{ t('cp.installNpcap') }}
        </button>
        <span class="muted small">{{ hint }}</span>
      </div>
      <div class="alert error" v-if="capErr">{{ capErr }}</div>
    </div>

    <!-- 统计 -->
    <div class="grid cols-4" style="margin-top:14px">
      <StatCard :label="t('cp.stTotal')" :value="fmtNum(stats.total)" :sub="t('cp.rate', { x: (stats.pps || 0).toFixed(1) })" tone="blue" />
      <StatCard :label="t('cp.stDuration')" :value="(stats.durationSec || 0) + 's'" :sub="t('cp.loopDetect', { x: stats.loopDetect ? t('cp.on') : t('cp.off') })" tone="green" />
      <StatCard :label="t('cp.stArpIpv4')" :value="fmtNum(stats.arpTotal) + ' / ' + fmtNum(stats.ipv4)"
                :sub="t('cp.arpSub', { x: (stats.arpPps || 0).toFixed(1), y: fmtNum(stats.broadcast) })" tone="orange" />
      <StatCard :label="t('cp.stBuffer')" :value="(stats.pktBuffered || 0) + '/' + (stats.pktCapacity || 2000)"
                :sub="t('cp.bufferSub', { x: fmtNum(stats.pktUndecodable), y: fmtNum(stats.badFrames) })" tone="purple" />
    </div>

    <!-- 报文列表(抽屉式: 标题行常驻, 表体可展开/收起; 表头冻结) -->
    <div class="card" style="margin-top:14px">
      <div class="card-title cap-pkt-head" @click="listOpen = !listOpen" :title="listOpen ? t('cp.listCollapse') : t('cp.listExpand')">
        {{ t('cp.pktList') }}
        <span class="sub">{{ t('cp.pktListSub') }}</span>
        <div class="spacer" style="flex:1"></div>
        <span class="muted small" v-if="!listOpen">{{ t('cp.listCount', { n: packets.length }) }}</span>
        <button class="btn sm" :disabled="!packets.length || pcapBusy"
                :title="packets.length ? t('cp.exportTip') : t('cp.noPktYet')"
                @click.stop="exportPcap">
          <span class="spinner" v-if="pcapBusy"></span> {{ t('cp.exportPcap') }}
        </button>
        <button class="btn sm" @click.stop="listOpen = !listOpen">{{ listOpen ? t('cp.collapse') : t('cp.expand') }}</button>
      </div>
      <div v-show="listOpen" class="cap-pkt-body">
        <div class="cap-actions">
          <input class="input mono" style="max-width:280px" v-model="displayFilter"
                 :placeholder="t('cp.phDisplayFilter')">
          <input class="input mono" style="max-width:190px" v-model="srcQ"
                 :placeholder="t('cp.phSrc')">
          <input class="input mono" style="max-width:190px" v-model="dstQ"
                 :placeholder="t('cp.phDst')">
          <label class="checkbox"><input type="checkbox" v-model="autoScroll">{{ t('cp.autoScroll') }}</label>
          <div class="spacer" style="flex:1"></div>
          <button class="btn sm danger" @click="clearList">{{ t('cp.clearList') }}</button>
        </div>
        <!-- 经典页迁移(P1-3): 过滤示例 chips, 点击立即生效(展示层语义: 空格=与, 前缀限定字段) -->
        <div class="filter-chips">
          <span v-for="x in FILTER_EXAMPLES" :key="x.f" class="chip"
                :class="{ on: displayFilter === x.f }" :title="t(x.tip)"
                @click="displayFilter = x.f">{{ x.f || t('cp.all') }}</span>
        </div>
        <div class="muted small" style="margin:8px 0">{{ listHint }}</div>

        <div class="table-wrap cap-pkts" ref="listBox">
          <table class="table" v-if="view.length">
            <thead>
              <tr><th>{{ t('cp.cTime') }}</th><th>{{ t('cp.cProto') }}</th><th>{{ t('cp.cSrc') }}</th><th>{{ t('cp.cDst') }}</th><th>{{ t('cp.cLen') }}</th><th>{{ t('cp.cInfo') }}</th></tr>
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
        {{ t('cp.pktDetail', { n: detail.seq }) }}
        <span class="sub">{{ detail.time }} · {{ t('cp.bytes', { x: detail.length }) }}</span>
        <button class="btn xs" style="margin-left:auto" @click="detail = null">{{ t('common.close') }}</button>
      </div>
      <div class="kv">
        <div class="k">{{ t('cp.kProto') }}</div><div class="v">{{ detail.protocol || '-' }}</div>
        <div class="k">{{ t('cp.kSrcMac') }}</div><div class="v mono">{{ detail.srcMac || '-' }}</div>
        <div class="k">{{ t('cp.kDstMac') }}</div><div class="v mono">{{ detail.dstMac || '-' }}</div>
        <div class="k">{{ t('cp.kSrc') }}</div><div class="v mono">{{ endpoint(detail.srcIp, detail.srcMac, detail.srcPort) }}</div>
        <div class="k">{{ t('cp.kDst') }}</div><div class="v mono">{{ endpoint(detail.dstIp, detail.dstMac, detail.dstPort) }}</div>
        <div class="k">TTL</div><div class="v mono">{{ detail.ttl || '-' }}</div>
        <div class="k">{{ t('cp.kEther') }}</div><div class="v mono">{{ detail.etherType || '-' }}</div>
        <div class="k">{{ t('cp.kInfo') }}</div><div class="v">{{ detail.info || '-' }}</div>
      </div>
      <template v-if="hexRows.length">
        <div class="muted small" style="margin:12px 0 6px">
          {{ t('cp.rawBytes', { x: hexBytes.length, y: detail.length > hexBytes.length ? t('cp.rawBytesMore') : '' }) }}
        </div>
        <pre class="code-block cap-hex">{{ hexText }}</pre>
      </template>
      <div class="muted small" v-else>{{ t('cp.noPayload') }}</div>
    </div>

    <!-- 经典页迁移(P1-3): 智能分析(内置引擎) + 阶段 3 AI 全链路分析 -->
    <div class="card" style="margin-top:14px">
      <div class="card-title">
        {{ t('cp.analysis') }}
        <div class="spacer"></div>
        <button class="btn sm" :disabled="analyzing" @click="runAnalysis">
          <span class="spinner" v-if="analyzing"></span> {{ t('cp.smartAnalysis') }}
        </button>
        <!-- 阶段 3: AI 分析(模板+RAG+记忆库, 结果存报告中心)。抓包中点击 = 先停止
             抓包(会话自动存档)再分析本会话; 未启用/模块关闭时按钮自动置灰。 -->
        <AiAnalyzeButton ref="aiBtn" module="capture" :label="t('cp.aiAnalyze')" :before="aiBefore" />
      </div>
      <p class="muted small" style="margin:0 0 8px">
        {{ t('cp.aiCfg1') }}
        <router-link to="/license?tab=ai">{{ t('cp.aiCfgLink') }}</router-link>
        {{ t('cp.aiCfg2') }}
      </p>
      <pre class="code-block cap-ai" v-if="analysisText">{{ analysisText }}</pre>
    </div>

    <!-- 经典页迁移(P1-3): 检测事件流(环路/风暴/ARP 漂移) + ARP 绑定表 -->
    <div class="grid cols-2" style="margin-top:14px">
      <div class="card">
        <div class="card-title">{{ t('cp.events') }} <span class="sub">{{ t('cp.eventsSub') }}</span>
          <div class="spacer"></div>
          <button class="btn xs" @click="events = []">{{ t('cp.clearEv') }}</button>
        </div>
        <div class="cap-events">
          <div v-if="!events.length" class="empty">{{ t('cp.noEvents') }}</div>
          <div v-for="(e, i) in events" :key="e.seq || i" class="cap-ev">
            <span class="mono muted small">{{ e.time }}</span>
            <span class="badge" :class="e.severity === 'high' ? 'st-failed' : (e.severity === 'medium' ? 'st-pending' : 'st-success')">
              {{ e.severity === 'high' ? t('sev.high') : (e.severity === 'medium' ? t('sev.medium') : t('sev.low')) }}
            </span>
            <span class="small">{{ e.title }} — {{ e.detail }}</span>
            <div class="muted small" v-if="e.advice" style="margin-left:26px">{{ t('cp.advice', { x: e.advice }) }}</div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">{{ t('cp.arpTable') }} <span class="sub">{{ t('cp.arpSub') }}</span></div>
        <div class="table-wrap" style="max-height:280px; overflow-y:auto">
          <table class="table" v-if="bindings.length">
            <thead><tr><th>IP</th><th>MAC</th><th>{{ t('cp.cCount') }}</th><th>{{ t('cp.cLastOp') }}</th><th>{{ t('cp.cFirst') }}</th><th>{{ t('cp.cLast') }}</th><th>{{ t('cp.cState') }}</th></tr></thead>
            <tbody>
              <tr v-for="b in bindings" :key="b.ip + b.mac">
                <td class="mono small">{{ b.ip }}</td>
                <td class="mono small">{{ b.mac }}</td>
                <td>{{ b.count }}</td>
                <td class="small">{{ b.lastOp || '-' }}</td>
                <td class="mono small muted">{{ b.firstSeen || '-' }}</td>
                <td class="mono small muted">{{ b.lastSeen || '-' }}</td>
                <td><span class="badge" :class="b.flapping ? 'st-failed' : 'st-success'">{{ b.flapping ? t('cp.flapping') : t('cp.normal') }}</span></td>
              </tr>
            </tbody>
          </table>
          <Empty v-else :text="t('cp.arpEmpty')" />
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
import { t } from '../i18n'

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
// f 是过滤功能 token(matchPkt 按字面匹配, 不翻); tip 是词条键, 渲染期 t() 解析
const FILTER_EXAMPLES = [
  { f: '', tip: 'cp.tipAll' },
  { f: 'icmp', tip: 'cp.tipIcmp' },
  { f: 'arp', tip: 'cp.tipArp' },
  { f: 'tcp', tip: 'cp.tipTcp' },
  { f: 'udp', tip: 'cp.tipUdp' },
  { f: 'ipv6', tip: 'cp.tipIpv6' },
  { f: 'icmpv6', tip: 'cp.tipIcmpv6' },
  { f: 'igmp', tip: 'cp.tipIgmp' },
  { f: 'syn', tip: 'cp.tipSyn' },
  { f: 'rst', tip: 'cp.tipRst' },
  { f: 'fin', tip: 'cp.tipFin' },
  { f: '广播', tip: 'cp.tipBcast' },
  { f: 'port:80', tip: 'cp.tip80' },
  { f: 'port:443', tip: 'cp.tip443' },
  { f: 'port:53', tip: 'cp.tip53' },
  { f: 'port:22', tip: 'cp.tip22' },
  { f: 'port:3389', tip: 'cp.tip3389' },
  { f: 'port:445', tip: 'cp.tip445' },
  { f: 'proto:icmp', tip: 'cp.tipProtoIcmp' },
  { f: 'ip:192.168.1.1', tip: 'cp.tipIp' },
  { f: 'src:192.168.1.1', tip: 'cp.tipSrc' },
  { f: 'dst:192.168.1.1', tip: 'cp.tipDst' },
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
  if (running.value) return t('cp.waitPackets')
  return packets.value.length
    ? t('cp.someFiltered', { n: packets.value.length })
    : t('cp.emptyHint')
})

const listHint = computed(() => {
  const hidden = shown.value.length - view.value.length
  let s = t('cp.showing', { a: view.value.length, b: shown.value.length })
  if (packets.value.length > shown.value.length) s += t('cp.filteredFrom', { n: packets.value.length })
  if (hidden > 0) s += t('cp.omitted', { n: hidden })
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
  hint.value = t('cp.listCleared')
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
    hint.value = t('cp.exported', { name, kb: (blob.size / 1024).toFixed(1), n: packets.value.length })
  } catch (e) {
    hint.value = t('cp.exportFail', { err: e.message })
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
  if (LOOPBACK_DEV.test(s)) return t('cp.loopLabel')
  if (PSEUDO_DEV.test(s)) return t('cp.pseudoLabel')
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
  hint.value = t('cp.openingDev')
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
    hint.value = t('cp.capturing', { x: d.device || device.value })
      + (d.captureAll ? t('cp.captureAllNote', { x: displayFilter.value || t('cp.none') }) : '')
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
    hint.value = t('cp.stopped')
    await pollPackets() // 补最后一批
  } catch (e) { capErr.value = e.message }
  finally { busy.value = false }
}

async function installNpcap() {
  if (!confirm(t('cp.installConfirm'))) return
  installing.value = true
  hint.value = t('cp.installing')
  try {
    await api('/api/capture/install', { method: 'POST' })
    hint.value = t('cp.installDone')
    npcapInstalled.value = true
    await loadDevices(true)
  } catch (e) {
    capErr.value = t('cp.installFail', { err: e.message })
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
    analysisText.value = d.text || t('cp.noData')
  } catch (e) { analysisText.value = t('cp.analysisFail', { err: e.message }) }
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
      hint.value = t('cp.aiStopped')
      await pollPackets()
    } catch (e) {
      throw new Error(t('cp.stopFail', { err: e.message }))
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

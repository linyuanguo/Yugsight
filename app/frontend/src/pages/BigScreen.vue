<template>
  <div class="screen" ref="screenEl" :class="{ 'is-fs': isFullscreen }">
    <!-- 顶栏 -->
    <div class="screen-head">
      <div class="logo" style="width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,#0ea5e9,#6366f1);display:flex;align-items:center;justify-content:center;font-weight:800;color:#fff;font-size:13px;box-shadow:0 4px 18px rgba(56,189,248,.35)">YS</div>
      <div>
        <div class="screen-title">Yugsight 安全运维大屏</div>
        <div class="muted small">
          资产 · 风险 · 探针 · 任务 实时态势
          <span v-if="refreshedAt" style="margin-left:8px">数据更新于 {{ refreshedAt }}</span>
        </div>
      </div>
      <div class="screen-clock">
        <span v-if="lastError" class="chip off" style="margin-right:12px" :title="lastError">数据获取异常</span>
        <span v-if="snap && snap.warnings && snap.warnings.length" class="chip warn" style="margin-right:12px" :title="snap.warnings.join('\n')">{{ snap.warnings.length }} 项提示</span>
        <span>{{ clock }}</span>
        <span style="margin-left:14px"><a href="javascript:void(0)" @click="refresh()">立即刷新</a></span>
        <span style="margin-left:14px"><a href="javascript:void(0)" @click="toggleFullscreen">{{ isFullscreen ? '退出全屏' : '全屏' }}</a></span>
        <!-- 阶段 4: 大屏并入首页仪表盘 Tab2, 此处回到概览 Tab(原独立页的"返回控制台") -->
        <span style="margin-left:14px"><a href="javascript:void(0)" @click="$router.replace({ path: '/', query: {} })">返回概览 →</a></span>
      </div>
    </div>

    <!-- 数字卡片 -->
    <div class="screen-cards">
      <div class="card stat-card tone-blue">
        <div class="stat-label">资产总量</div>
        <div class="stat-value">{{ ov.assets }}</div>
        <div class="stat-sub">存活 {{ ov.assetsAlive }} / 未响应 {{ ov.assetsDown }}</div>
      </div>
      <div class="card stat-card tone-green">
        <div class="stat-label">存活资产</div>
        <div class="stat-value">{{ ov.assetsAlive }}</div>
        <div class="stat-sub">{{ aliveRate }}% 存活率</div>
      </div>
      <div class="card stat-card tone-red">
        <div class="stat-label">严重漏洞</div>
        <div class="stat-value">{{ ov.vulns.critical }}</div>
        <div class="stat-sub">风险合计 {{ ov.vulns.risk }}</div>
      </div>
      <div class="card stat-card tone-orange">
        <div class="stat-label">高危漏洞</div>
        <div class="stat-value">{{ ov.vulns.high }}</div>
        <div class="stat-sub">中危 {{ ov.vulns.medium }} / 低危 {{ ov.vulns.low }}</div>
      </div>
      <div class="card stat-card tone-purple">
        <div class="stat-label">在线探针</div>
        <div class="stat-value">{{ ov.probesOnline }}<span class="stat-unit">/{{ ov.probes }}</span></div>
        <div class="stat-sub">离线 {{ ov.probesOffline }} 个节点</div>
      </div>
      <div class="card stat-card tone-yellow">
        <div class="stat-label">运行中任务</div>
        <div class="stat-value">{{ ov.tasksRunning }}</div>
        <div class="stat-sub">今日 {{ ov.tasksToday }} · 成功 {{ ov.tasksSuccess }}</div>
      </div>
    </div>

    <!-- 中栏: 趋势 + 占比 -->
    <div class="screen-mid">
      <!-- 近 7 天新增/修复趋势(纯 SVG 折线图, 无图表库) -->
      <div class="card">
        <div class="card-title">
          近 {{ trendDays }} 天漏洞趋势
          <span class="sub">新增 {{ trend.newTotal }} · 修复 {{ trend.fixedTotal }}</span>
        </div>
        <svg class="trend-svg" :viewBox="`0 0 ${chart.w} ${chart.h}`" preserveAspectRatio="none" aria-label="漏洞趋势图">
          <!-- 横向网格 -->
          <g>
            <line v-for="(g, i) in chart.grid" :key="'g' + i"
                  :x1="chart.padL" :x2="chart.w - chart.padR" :y1="g.y" :y2="g.y"
                  stroke="var(--border)" stroke-width="1" stroke-dasharray="4 6" />
            <text v-for="(g, i) in chart.grid" :key="'gt' + i"
                  :x="chart.padL - 6" :y="g.y + 4" text-anchor="end"
                  fill="var(--muted)" font-size="10">{{ g.v }}</text>
          </g>
          <!-- 面积 + 折线: 新增 -->
          <path :d="chart.newArea" fill="url(#gradNew)" opacity=".45" />
          <polyline :d="chart.newLine" fill="none" stroke="#f87171" stroke-width="2" stroke-linejoin="round" />
          <!-- 面积 + 折线: 修复 -->
          <polyline :d="chart.fixedLine" fill="none" stroke="#34d399" stroke-width="2"
                    stroke-dasharray="5 4" stroke-linejoin="round" />
          <!-- 数据点 + X 轴标签 -->
          <g>
            <circle v-for="(p, i) in chart.points" :key="'c' + i" :cx="p.x" :cy="p.ny" r="3" fill="#f87171" />
            <circle v-for="(p, i) in chart.points" :key="'cf' + i" :cx="p.x" :cy="p.fy" r="2.5" fill="#34d399" />
            <text v-for="(p, i) in chart.points" :key="'t' + i" :x="p.x" :y="chart.h - 4"
                  text-anchor="middle" fill="var(--muted)" font-size="10">{{ p.label }}</text>
          </g>
          <defs>
            <linearGradient id="gradNew" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#f87171" stop-opacity=".55" />
              <stop offset="100%" stop-color="#f87171" stop-opacity="0" />
            </linearGradient>
          </defs>
          <!-- 空数据提示(用 SVG 内文本, 避免叠层脱离图框) -->
          <text v-if="!chart.hasData" :x="chart.w / 2" :y="chart.h / 2"
                text-anchor="middle" fill="var(--muted)" font-size="12">近 {{ trendDays }} 天无新增/修复记录</text>
        </svg>
        <div class="legend">
          <span><i class="dot" style="background:#f87171"></i>新增</span>
          <span><i class="dot" style="background:#34d399"></i>修复</span>
        </div>
      </div>

      <!-- 漏洞风险占比(纯 SVG 环形图) -->
      <div class="card">
        <div class="card-title">漏洞风险占比 <span class="sub">未修复 · 不含信息</span></div>
        <div v-if="!ov.vulns.risk" class="screen-placeholder" style="min-height:200px">
          <span class="ph-tag">无数据</span>暂无风险漏洞
        </div>
        <div v-else class="donut-wrap">
          <svg class="donut" viewBox="0 0 120 120" aria-label="漏洞风险占比">
            <circle cx="60" cy="60" r="46" fill="none" stroke="var(--panel2)" stroke-width="14" />
            <circle v-for="(s, i) in chart.donut" :key="s.key"
                    cx="60" cy="60" r="46" fill="none"
                    :stroke="s.color" stroke-width="14"
                    :stroke-dasharray="s.dash" :stroke-dashoffset="s.offset"
                    transform="rotate(-90 60 60)" />
            <text x="60" y="57" text-anchor="middle" fill="var(--text)" font-size="20" font-weight="700">{{ ov.vulns.risk }}</text>
            <text x="60" y="73" text-anchor="middle" fill="var(--muted)" font-size="10">风险漏洞</text>
          </svg>
          <div class="donut-legend">
            <div class="top-item" v-for="s in sevRows" :key="s.key">
              <span class="dot" :style="{ background: s.color }"></span>
              <span class="t-title">{{ s.name }}</span>
              <span class="mono">{{ s.count }}</span>
              <span class="mono muted" style="width:48px;text-align:right">{{ s.pct }}%</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 高危漏洞 TOP -->
      <div class="card">
        <div class="card-title">高危漏洞 TOP {{ topVulns.length }} <span class="sub">按等级 / CVSS / 置信度</span></div>
        <div v-if="!topVulns.length" class="screen-placeholder" style="min-height:200px">
          <span class="ph-tag">无数据</span>暂无风险漏洞
        </div>
        <div v-else class="scroll-list">
          <div class="top-item" v-for="(v, i) in topVulns" :key="v.id">
            <span class="rank">{{ i + 1 }}</span>
            <SevTag :sev="v.severity" />
            <span class="t-title" :title="v.title">{{ v.title }}</span>
            <span class="mono small muted">{{ v.assetIp }}<template v-if="v.port">:{{ v.port }}</template></span>
          </div>
        </div>
      </div>
    </div>

    <!-- 3D 地球 IP 流向 + SNMP 监控(任务 10b/10d) -->
    <div class="screen-globe">
      <!-- 3D 地球: IP 流向弧线 + 城市热点(Globe.gl 渲染, 资源缺失自动降级) -->
      <div class="card globe-card">
        <div class="card-title">
          IP 流向图
          <span class="sub">3D 地球 · 弧线聚合到城市层级</span>
          <span class="sub" v-if="flows && flows.stats" style="margin-left:auto">
            已知 {{ flows.stats.known || 0 }} · 内网 {{ flows.stats.private || 0 }} · 未收录 {{ flows.stats.unknown || 0 }}
          </span>
        </div>
        <div class="globe-body">
          <GlobeFlow :flows="flows" :frames="flowFrames" />
        </div>
      </div>

      <!-- SNMP 网络监控: 设备在线状态 + 流量速率(10a 采集数据, 大屏只读展示) -->
      <div class="card">
        <div class="card-title">
          SNMP 网络监控
          <span class="sub">{{ monOnline }} 在线 / {{ monTargets.length }} 目标</span>
          <span class="chip" :class="monRunning ? 'on' : 'off'" style="margin-left:auto">{{ monRunning ? '采集中' : '未采集' }}</span>
        </div>
        <div v-if="!monEnabled" class="screen-placeholder" style="min-height:220px">
          <span class="ph-tag">未配置</span>
          未配置监控目标
          <div class="muted small">在「网络监控」页添加 SNMP 目标后, 此处展示设备在线与流量</div>
        </div>
        <div v-else-if="!monTargets.length" class="screen-placeholder" style="min-height:220px">
          <span class="ph-tag">无目标</span>监控已启用但尚无目标
        </div>
        <div v-else class="scroll-list">
          <div class="mon-row" v-for="t in monTargets" :key="t.id">
            <span class="dot" :class="t.online ? 'on' : 'off'"></span>
            <span class="t-title">
              {{ t.name || t.addr }}
              <span class="muted small mono" v-if="t.addr" style="margin-left:6px">{{ t.addr }}</span>
            </span>
            <span class="mono small muted" :title="'累计流量差分(每采集周期)'">
              {{ fmtRate(t.inRateBps) }}↓ / {{ fmtRate(t.outRateBps) }}↑
            </span>
            <span class="mono small" style="width:64px;text-align:right" :title="'CPU 负载% (0=设备不支持)'">
              {{ t.cpuLoad ? t.cpuLoad + '%' : '-' }}
            </span>
            <span class="mono small" :title="'接口 up/total'" style="width:40px;text-align:right">
              {{ t.ifUp }}/{{ t.ifaceCount }}
            </span>
            <span class="mono small muted" style="width:56px;text-align:right">{{ timeShort(t.lastAt) }}</span>
          </div>
        </div>
        <div v-if="lastRound" class="mon-foot">
          最近一轮 {{ timeShort(lastRound.at) }} · {{ lastRound.ok }}/{{ lastRound.total }} 成功 · {{ lastRound.durationMs }}ms
        </div>
      </div>

      <!-- 漏洞热力图(二期 14 多卡片): 资产 × 风险等级, 一眼看出风险集中在哪台 -->
      <div class="card">
        <div class="card-title">
          漏洞热力图
          <span class="sub">风险资产 × 等级</span>
        </div>
        <div v-if="!topAssets.length" class="screen-placeholder" style="min-height:220px">
          <span class="ph-tag">无数据</span>暂无风险资产
        </div>
        <div v-else class="heat-wrap">
          <div class="heat-row heat-head">
            <span class="h-ip">资产</span><span>严重</span><span>高危</span><span>其它</span><span>端口</span>
          </div>
          <div class="heat-row" v-for="a in heatAssets" :key="a.ip">
            <span class="h-ip mono small" :title="a.hostname || a.os || ''">{{ a.ip }}</span>
            <span class="cell" :style="heatStyle(a.critical, maxAssetRisk, '239,68,68')">{{ a.critical || 0 }}</span>
            <span class="cell" :style="heatStyle(a.high, maxAssetRisk, '249,115,22')">{{ a.high || 0 }}</span>
            <span class="cell" :style="heatStyle(otherRisk(a), maxAssetRisk, '234,179,8')">{{ otherRisk(a) }}</span>
            <span class="cell" :style="heatStyle(a.openPorts, maxPorts, '56,189,248')">{{ a.openPorts || 0 }}</span>
          </div>
          <div class="muted small heat-foot">色深 = 数量; 「其它」= 风险漏洞数减去严重与高危</div>
        </div>
      </div>
    </div>

    <!-- 底栏: 探针 / 风险资产 / 最近任务 -->
    <div class="screen-bot">
      <!-- 探针状态 + 负载 -->
      <div class="card">
        <div class="card-title">
          探针在线状态
          <span class="sub">{{ ov.probesOnline }} 在线 / {{ ov.probes }} 登记</span>
        </div>
        <div v-if="!probes.length" class="screen-placeholder" style="min-height:160px">
          <span class="ph-tag">未启用</span>
          未登记探针节点
          <div class="muted small">exe 同目录放置 probe.json 并设 center.enabled=true 后重启</div>
        </div>
        <div v-else class="scroll-list">
          <div class="probe-row" v-for="p in probes" :key="p.id">
            <span class="dot" :class="p.online ? 'on' : 'off'"></span>
            <span class="t-title">
              {{ p.name || p.id }}
              <span class="muted small mono" v-if="p.addr" style="margin-left:6px">{{ p.addr }}</span>
            </span>
            <span class="load-cell">
              <span class="load-label">CPU</span>
              <span class="mini-track"><span class="mini-fill" :style="{ width: barW(p.cpuPercent), background: loadColor(p.cpuPercent) }"></span></span>
              <span class="mono small" style="width:46px;text-align:right">{{ pct(p.cpuPercent) }}</span>
            </span>
            <span class="load-cell">
              <span class="load-label">内存</span>
              <span class="mini-track"><span class="mini-fill" :style="{ width: barW(p.memPercent), background: loadColor(p.memPercent) }"></span></span>
              <span class="mono small" style="width:46px;text-align:right">{{ pct(p.memPercent) }}</span>
            </span>
            <span class="mono small muted" style="width:52px;text-align:right" :title="p.currentTask || ''">
              {{ p.tasksRunning }} 任务
            </span>
          </div>
        </div>
      </div>

      <!-- 风险资产 TOP -->
      <div class="card">
        <div class="card-title">风险资产 TOP {{ topAssets.length }} <span class="sub">按风险漏洞数</span></div>
        <div v-if="!topAssets.length" class="screen-placeholder" style="min-height:160px">
          <span class="ph-tag">无数据</span>暂无资产风险统计
        </div>
        <div v-else class="scroll-list">
          <div class="bar-row" v-for="a in topAssets" :key="a.ip">
            <div class="bar-label mono" style="width:118px" :title="a.hostname || a.ip">{{ a.ip }}</div>
            <div class="bar-track">
              <div class="bar-fill" :style="{ width: assetPct(a.risk), background: 'linear-gradient(90deg,#f87171,#fb923c)' }"></div>
            </div>
            <div class="bar-val">{{ a.risk }}</div>
          </div>
        </div>
      </div>

      <!-- 最近任务 -->
      <div class="card">
        <div class="card-title">最近扫描任务 <span class="sub">今 {{ ov.tasksToday }} · 挂 {{ ov.tasksFailed }}</span></div>
        <div v-if="!recentTasks.length" class="screen-placeholder" style="min-height:160px">
          <span class="ph-tag">无数据</span>暂无扫描任务
        </div>
        <div v-else class="scroll-list">
          <div class="top-item" v-for="t in recentTasks" :key="t.id">
            <span class="chip" :class="taskChip(t.status)" style="min-width:52px;justify-content:center">{{ statusName(t.status) }}</span>
            <span class="mono small" style="width:42px">{{ t.type }}</span>
            <span class="t-title mono" :title="t.target">{{ t.target }}</span>
            <span class="mono small muted" v-if="t.probeNode">@{{ t.probeNode }}</span>
            <span class="mono small muted" style="width:64px;text-align:right">{{ timeShort(t.createdAt) }}</span>
          </div>
        </div>
      </div>
    </div>


  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import SevTag from '../components/SevTag.vue'
import GlobeFlow from '../components/GlobeFlow.vue'
import { v2, v2dash } from '../api/http'
import { STATUS_NAME, sevRank } from '../utils'

const INTERVAL_SEC = 15   // 大屏常驻, 15s 刷新接近"准实时"又不至于压垮单机服务
const TREND_DAYS = 7
const TOP_N = 10

const snap = ref(null)
const clock = ref('')
const refreshedAt = ref('')
const lastError = ref('')
const screenEl = ref(null)
const isFullscreen = ref(false)
let timer = null
let fsHandler = null

// ===== 视图数据(全部来自后端一次聚合, 前端不做统计口径决策) =====
const ov = computed(() => (snap.value && snap.value.overview) || {
  assets: 0, assetsAlive: 0, assetsDown: 0,
  vulns: { critical: 0, high: 0, medium: 0, low: 0, info: 0, risk: 0, total: 0 },
  probes: 0, probesOnline: 0, probesOffline: 0,
  tasksRunning: 0, tasksToday: 0, tasksSuccess: 0, tasksFailed: 0
})
const trend = computed(() => (snap.value && snap.value.trend) || { days: TREND_DAYS, points: [], newTotal: 0, fixedTotal: 0 })
const trendDays = computed(() => (snap.value && snap.value.trendDays) || TREND_DAYS)
const probes = computed(() => (snap.value && snap.value.probes) || [])
const topVulns = computed(() => (snap.value && snap.value.topVulns) || [])
const topAssets = computed(() => (snap.value && snap.value.topAssets) || [])
const recentTasks = computed(() => (snap.value && snap.value.recentTasks) || [])
const intervalSec = computed(() => INTERVAL_SEC)

// ===== 3D 地球 IP 流向 + SNMP 监控(任务 10b/10d) =====
const flows = ref(null)          // /api/dashboard/flows 数据(未启用为 null)
const flowFrames = ref([])       // 时序回放帧(?timeline=1, 二期 14)
const monStatus = ref(null)      // /api/v2/monitor/status 数据
const monEnabled = computed(() => !!(monStatus.value && monStatus.value.enabled))
const monRunning = computed(() => !!(monStatus.value && monStatus.value.running))
const monTargets = computed(() => (monStatus.value && monStatus.value.targets) || [])
const monOnline = computed(() => monTargets.value.filter(t => t.online).length)
const lastRound = computed(() => (monStatus.value && monStatus.value.lastRound) || null)

// 流量速率展示: 每采集周期的字节差分 → 人类可读(B/KB/MB)
function fmtRate(bps) {
  const n = Number(bps) || 0
  if (n >= 1048576) return (n / 1048576).toFixed(1) + 'MB'
  if (n >= 1024) return (n / 1024).toFixed(1) + 'KB'
  return n + 'B'
}

const SEV_META = {
  critical: { name: '严重', color: '#ff6b6b' },
  high: { name: '高危', color: '#f87171' },
  medium: { name: '中危', color: '#fb923c' },
  low: { name: '低危', color: '#facc15' },
  info: { name: '信息', color: '#60a5fa' }
}

const sevRows = computed(() => {
  const rows = (snap.value && snap.value.severity) || []
  return rows.map(s => ({ ...s, name: (SEV_META[s.key] || {}).name || s.key, color: (SEV_META[s.key] || {}).color || '#94a3b8' }))
})

const aliveRate = computed(() => {
  const total = ov.value.assets
  return total ? Math.round(ov.value.assetsAlive / total * 100) : 0
})

// ===== SVG 图表(零图表库: 纯标准库项目, 不引入 echarts 以免破坏单二进制离线约束) =====
const chart = computed(() => {
  const w = 720, h = 220, padL = 34, padR = 12, padT = 14, padB = 22
  const pts = trend.value.points || []
  const grid = [0, 0.25, 0.5, 0.75, 1].map((r, i) => ({
    y: padT + (h - padT - padB) * r,
    v: 0 // 稍后按峰值回填
  }))
  const innerH = h - padT - padB
  const innerW = w - padL - padR
  const maxVal = Math.max(1, ...pts.map(p => Math.max(p.new || 0, p.fixed || 0)))
  // Y 轴刻度按峰值等比换算(4 等分向上取整到便于阅读的整数)
  const step = niceStep(maxVal / 4)
  const top = step * 4
  for (let i = 0; i < grid.length; i++) {
    grid[i].v = Math.round(top * (1 - (grid[i].y - padT) / innerH))
  }
  const xAt = (i) => pts.length <= 1 ? padL + innerW / 2 : padL + innerW * (i / (pts.length - 1))
  const yAt = (v) => padT + innerH * (1 - Math.min(v || 0, top) / top)

  const points = pts.map((p, i) => ({ x: xAt(i), label: p.label, ny: yAt(p.new), fy: yAt(p.fixed) }))
  const line = (key) => points.map((p, i) => `${i ? 'L' : 'M'}${p.x.toFixed(1)},${p[key].toFixed(1)}`).join(' ')
  let area = ''
  if (points.length) {
    const base = padT + innerH
    area = `${line('ny')} L${points[points.length - 1].x.toFixed(1)},${base} L${points[0].x.toFixed(1)},${base} Z`
  }

  // 环形图: 每段用 stroke-dasharray/offset 画弧(比 canvas 简单且自适应缩放)
  const total = ov.value.vulns.risk || 0
  const C = 2 * Math.PI * 46
  let acc = 0
  const donut = sevRows.value
    .filter(s => s.key !== 'info' && s.count > 0)
    .map(s => {
      const frac = s.count / total
      const seg = { key: s.key, color: s.color, dash: `${(frac * C).toFixed(2)} ${C.toFixed(2)}`, offset: (-acc * C).toFixed(2) }
      acc += frac
      return seg
    })

  return {
    w, h, padL, padR, grid, points,
    newLine: line('ny'), fixedLine: line('fy'), newArea: area,
    donut, hasData: pts.some(p => (p.new || 0) > 0 || (p.fixed || 0) > 0)
  }
})

// niceStep 把刻度间隔取整到 1/2/5/10 的倍数, 避免出现 "3.75" 这种刻度。
function niceStep(raw) {
  const v = Math.max(1, raw)
  const mag = Math.pow(10, Math.floor(Math.log10(v)))
  const n = v / mag
  let m = 10
  if (n <= 1) m = 1
  else if (n <= 2) m = 2
  else if (n <= 5) m = 5
  return Math.max(1, m * mag)
}

const maxAssetRisk = computed(() => Math.max(1, ...topAssets.value.map(a => a.risk || 0)))
function assetPct(n) { return Math.max(6, Math.round((n || 0) / maxAssetRisk.value * 100)) }

// barW / pct 对 null 的显式处理: 后端用 null 表示"探针未上报负载",
// 与 0% 是两种含义(未上报 vs 真的空闲), 不能混为一谈。
function barW(v) { return v == null ? 0 : Math.max(2, Math.min(100, v)) }
function pct(v) { return v == null ? '-' : Math.round(v) + '%' }
function loadColor(v) {
  if (v == null) return 'var(--border2)'
  if (v >= 85) return '#f87171'
  if (v >= 60) return '#fb923c'
  return '#34d399'
}

function statusName(s) { return STATUS_NAME[s] || s }
const TASK_CHIP = { running: 'on', pending: 'warn', success: 'on', failed: 'off', cancelled: '' }
function taskChip(s) { return TASK_CHIP[s] || '' }

function timeShort(s) {
  if (!s) return '-'
  const d = new Date(s)
  if (isNaN(d.getTime())) return '-'
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

// ===== 数据加载 =====
async function load() {
  try {
    // 一次请求拿全部指标: 分多次拉会在刷新周期里出现"卡片是新的、图是旧的"的
    // 自相矛盾画面, 运维看到会怀疑数据准确性。
    const d = await v2(`/screen/overview?days=${TREND_DAYS}&top=${TOP_N}&recent=8`)
    if (d) {
      snap.value = d
      lastError.value = ''
      const t = new Date()
      const p = (n) => String(n).padStart(2, '0')
      refreshedAt.value = `${p(t.getHours())}:${p(t.getMinutes())}:${p(t.getSeconds())}`
    }
  } catch (e) {
    // 保留上一帧数据 + 顶部提示: 大屏空屏比"稍旧的数据"更让人恐慌
    lastError.value = e && e.message ? e.message : '数据获取失败'
  }
  // 3D 地球流向 + SNMP 监控: 独立加载, 任一失败不影响另一块与主指标。
  // flows 未启用时后端 404, 置 null 让前端显示"无数据"占位(非报错)。
  loadFlows()
  loadMonitor()
}

async function loadFlows() {
  try {
    flows.value = await v2dash('/api/dashboard/flows')
  } catch (e) {
    flows.value = null // 未启用(404)/失败 → 空态占位, 不弹错
  }
  // 时序帧: 失败只影响回放(不弹错), 总量聚合照常展示
  try {
    const d = await v2dash('/api/dashboard/flows?timeline=1')
    flowFrames.value = (d && d.frames) || []
    if (d && d.center && flows.value) flows.value.center = d.center
  } catch (e) {
    flowFrames.value = []
  }
}

// ===== 漏洞热力图 =====
const heatAssets = computed(() => topAssets.value.slice(0, 6))
const maxPorts = computed(() => Math.max(1, ...heatAssets.value.map(a => a.openPorts || 0)))
function otherRisk(a) {
  const v = (a.risk || 0) - (a.critical || 0) - (a.high || 0)
  return v > 0 ? v : 0
}
// heatStyle 数值 → 色块(rgb 三元组), 值越大色越实。
// 0 值不着色: 热力图里"没有"必须一眼看出是空的, 染色后 0 和 1 就分不出来了。
function heatStyle(v, max, rgb) {
  const n = Math.max(0, v || 0)
  if (n === 0) return { background: 'transparent' }
  const a = 0.2 + 0.6 * Math.min(1, n / Math.max(1, max))
  return { background: 'rgba(' + rgb + ',' + a.toFixed(2) + ')' }
}

async function loadMonitor() {
  try {
    monStatus.value = await v2('/monitor/status')
  } catch (e) {
    monStatus.value = null
  }
}

function refresh() { load() }

function tick() {
  const d = new Date()
  const p = (n) => String(n).padStart(2, '0')
  clock.value = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}  ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

// ===== 全屏 =====
async function toggleFullscreen() {
  const el = screenEl.value
  if (!el) return
  try {
    if (document.fullscreenElement) {
      await document.exitFullscreen()
    } else if (el.requestFullscreen) {
      await el.requestFullscreen()
    }
    // 不支持全屏的环境(部分内嵌浏览器)静默失败, 不弹错误打断展示
  } catch (e) { /* 忽略 */ }
}

onMounted(() => {
  load()
  tick()
  timer = setInterval(() => { tick(); load() }, INTERVAL_SEC * 1000)
  fsHandler = () => { isFullscreen.value = !!document.fullscreenElement }
  document.addEventListener('fullscreenchange', fsHandler)
})

onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
  if (fsHandler) document.removeEventListener('fullscreenchange', fsHandler)
  // 离开页面时若仍在全屏, 主动退出 —— 否则用户回到控制台会被困在全屏里
  if (document.fullscreenElement && document.exitFullscreen) document.exitFullscreen().catch(() => {})
})
</script>

<template>
  <div>
    <PageHeader :title="t('en.title')" :desc="t('en.desc')">
      <button class="btn sm" :disabled="busy || (env && env.detecting)" @click="refresh">
        <span class="spinner" v-if="busy || (env && env.detecting)"></span> {{ t('en.redetect') }}
      </button>
      <button class="btn sm danger" v-if="canInstall" :disabled="installing" @click="install">
        <span class="spinner" v-if="installing"></span> {{ t('en.installDriver') }}
      </button>
      <button class="btn sm" :disabled="dlBusy || dlRunning" @click="installDefaults">
        <span class="spinner" v-if="dlRunning"></span> {{ t('en.installAll') }}
      </button>
      <button class="btn sm" :disabled="dlBusy" @click="loadDl">{{ t('en.refreshList') }}</button>
    </PageHeader>

    <div class="alert" v-if="installing" style="margin-bottom:14px">
      <span class="spinner"></span> {{ t('en.waitingInstall') }}</div>
    <div class="alert info" v-else-if="installMsg" style="margin-bottom:14px">{{ installMsg }}</div>

    <!-- 引擎下载: 进行中实时进度 / 空闲时逐项结果(失败项带官方下载页兜底) -->
    <div class="card dl-progress-card" v-if="dlRunning" style="margin-bottom:14px">
      <div class="dl-head">
        <span class="spinner"></span>
        <strong>{{ dl.progress.phase || dl.progress.status || t('en.processing') }}</strong>
        <span class="mono muted" v-if="dl.progress.engine">{{ engineLabel(dl.progress.engine) }}</span>
        <span class="mono muted" v-if="dl.progress.version">v{{ dl.progress.version }}</span>
        <span v-if="dl.progress.status === 'downloading' && dl.progress.total" class="mono small muted">
          {{ t('en.itemOf', { a: Math.min((dl.progress.done || 0) + 1, dl.progress.total), b: dl.progress.total }) }}
        </span>
      </div>

      <!-- 总进度: 按"已完成引擎数 + 当前引擎内进度"折算, 多引擎批量安装时不会永远停在 0% -->
      <div class="bar-row">
        <span class="bar-label">{{ t('en.overall') }}</span>
        <div class="bar-track">
          <div class="bar-fill" :style="{ width: overallPercent + '%', background: 'var(--accent)' }"></div>
        </div>
        <span class="bar-val">{{ overallPercent }}%</span>
      </div>

      <!-- 当前引擎的下载进度: 只有 downloading 阶段才有意义(查版本/解包/落位无百分比) -->
      <div class="bar-row" v-if="dl.progress.status === 'downloading' && dl.progress.percent >= 0">
        <span class="bar-label">{{ t('en.currentPkg') }}</span>
        <div class="bar-track">
          <div class="bar-fill" :style="{ width: dl.progress.percent + '%', background: 'var(--green)' }"></div>
        </div>
        <span class="bar-val">{{ dl.progress.percent }}%</span>
      </div>

      <div class="dl-meta small" v-if="dl.progress.status === 'downloading'">
        <span class="mono">{{ fmtBytes(dl.progress.bytes) }} / {{ fmtBytes(dl.progress.totalBytes) }}</span>
        <span v-if="dl.progress.speed > 0" class="mono"> · {{ fmtSpeed(dl.progress.speed) }}</span>
        <span v-if="etaText" class="mono"> · {{ t('en.remaining', { x: etaText }) }}</span>
        <!-- 当前下载的是哪个包: ZAP 会连下两个包(273MB 的 ZAP + 190MB 的 JDK),
             若不说明, 用户会看到"进度条走完又从头开始"而以为任务重跑了。 -->
        <span v-if="dl.progress.phase" class="muted"> · {{ dl.progress.phase }}</span>
      </div>

      <!-- 镜像探测结论: 让"先检测再下载"这件事可见, 而不是黑箱 -->
      <div class="dl-mirror" v-if="mirrorProbeList.length">
        <span class="small muted">{{ t('en.mirrorProbe') }}</span>
        <span v-for="(m, i) in mirrorProbeList" :key="i" class="mirror-item" :class="m.ok ? 'ok' : 'bad'">
          <span class="mono">{{ m.prefix }}</span>
          <template v-if="m.ok"> {{ fmtSpeed(m.speed) }}</template>
          <template v-else> {{ m.error }}</template>
          <span v-if="m.prefix === dl.mirrorInUse" class="badge st-success">{{ t('en.inUse') }}</span>
        </span>
      </div>
      <div class="dl-note small muted" v-if="dlNote">{{ dlNote }}</div>
    </div>
    <!-- 任务级失败原因(如"所有镜像均不可用"): 必须显式呈现, 否则用户只看到进度条
         消失却不知道发生了什么, 也无从判断该改哪个配置 -->
    <div class="alert" v-if="dlErr && !dlRunning" style="margin-bottom:14px">
      {{ dlErr }}
    </div>

    <div class="alert info" v-else-if="dlResults.length" style="margin-bottom:14px; display:block">
      <div v-for="(r, i) in dlResults" :key="i" class="small">
        <span :class="r.ok ? 'ok' : (r.skipped ? 'muted' : 'bad')">
          {{ r.ok ? t('en.ok') : (r.skipped ? t('en.skip') : t('en.fail')) }}
        </span>
        <span class="mono">{{ r.display }}</span>
        <span v-if="r.version" class="mono">v{{ r.version }}</span>
        <span v-if="r.installed" class="mono muted"> → {{ r.installed }}</span>
        <span v-if="r.error" class="muted"> · {{ r.error }}</span>
        <!-- ZAP 会额外带一个 JDK 结果: 失败时不能只说"成功", 否则用户以为万事俱备,
             实际 ZAP 一起动就报 UnsupportedClassVersionError。 -->
        <span v-if="r.jdkNote" class="muted" :class="{ bad: !r.jdkVersion }">
          · {{ r.jdkNote }}
        </span>
        <a v-if="r.homepage" :href="r.homepage" target="_blank" rel="noopener">{{ t('en.officialPage') }}</a>
      </div>
    </div>

    <div class="grid cols-4">
      <div class="card">
        <div class="stat-label">{{ t('en.detectState') }}</div>
        <div class="stat-value" style="font-size:20px">{{ env && env.detecting ? t('en.detecting') : t('en.ready') }}</div>
        <div class="stat-sub mono">{{ env ? fmtDT(env.checkedAt) : '-' }}</div>
      </div>
      <div class="card">
        <div class="stat-label">{{ t('en.enginesReady') }}</div>
        <div class="stat-value" style="font-size:20px">{{ okCount }} / {{ (env && env.engines && env.engines.length) || 0 }}</div>
        <div class="stat-sub">{{ t('en.enginesReadySub') }}</div>
      </div>
      <div class="card">
        <div class="stat-label">{{ t('en.npcapDriver') }}</div>
        <div class="stat-value" style="font-size:20px">{{ npcapText }}</div>
        <div class="stat-sub">{{ npcapSub }}</div>
      </div>
      <div class="card">
        <div class="stat-label">{{ t('en.degradedEng') }}</div>
        <div class="stat-value" style="font-size:20px">{{ degraded.length }}</div>
        <div class="stat-sub">{{ degraded.length ? degraded.join(', ') : t('en.noDegrade') }}</div>
      </div>
    </div>

    <!-- ===== 引擎解析编排 / 自动降级(移植自经典页 "引擎" 页签) =====
         这里的 6 项统计不是"文件是否存在"(那是上面的环境探测), 而是"实际跑起来之后发生了什么":
         外部引擎有没有真的被接入、降级过几次、最近一次结果是哪套引擎产出的。
         引擎不好用时这是唯一的排障线索。 -->
    <div class="card" style="margin-top:14px">
      <div class="card-title">
        {{ t('en.orchTitle') }}
        <span class="sub">{{ t('en.orchSub') }}</span>
        <div style="flex:1"></div>
        <button class="btn sm" :disabled="engBusy" @click="reloadEngine">
          <span class="spinner" v-if="engBusy"></span> {{ t('en.reloadEng') }}
        </button>
      </div>
      <div class="muted small err-line">{{ engMsg }}</div>
      <template v-if="eng">
        <div class="grid cols-3">
          <div class="card">
            <div class="stat-label">{{ t('en.orchExt') }}</div>
            <div class="stat-value" style="font-size:18px" :style="{ color: eng.enabled ? 'var(--green)' : 'var(--muted)' }">
              {{ eng.enabled ? t('common.enabled') : t('common.disabled') }}
            </div>
            <div class="stat-sub mono small">{{ t('en.engSection') }}</div>
          </div>
          <div class="card">
            <div class="stat-label">{{ t('en.executor') }}</div>
            <div class="stat-value" style="font-size:18px" :style="{ color: eng.execReady ? 'var(--green)' : 'var(--orange)' }">
              {{ eng.execReady ? t('en.execReady') : t('en.execNot') }}
            </div>
            <div class="stat-sub">{{ engineListText }}</div>
          </div>
          <div class="card">
            <div class="stat-label">{{ t('en.fallback') }}</div>
            <div class="stat-value" style="font-size:18px" :style="{ color: eng.fallbackReady ? 'var(--green)' : 'var(--red)' }">
              {{ eng.fallbackReady ? t('en.avail') : t('en.unavail') }}
            </div>
            <div class="stat-sub">{{ t('en.fallbackSub') }}</div>
          </div>
          <div class="card">
            <div class="stat-label">{{ t('en.degradeCount') }}</div>
            <div class="stat-value" style="font-size:18px" :style="{ color: degradeCount ? 'var(--orange)' : 'var(--green)' }">
              {{ degradeCount }}
            </div>
            <div class="stat-sub">{{ degradeCount ? t('en.degradedHappened') : t('en.noDegradeYet') }}</div>
          </div>
          <div class="card">
            <div class="stat-label">{{ t('en.lastSource') }}</div>
            <div class="stat-value mono" style="font-size:18px">{{ eng.lastSource || '-' }}</div>
            <div class="stat-sub">{{ t('en.lastSourceSub') }}</div>
          </div>
          <div class="card">
            <div class="stat-label">{{ t('en.engTimeout') }}</div>
            <div class="stat-value" style="font-size:18px">{{ eng.timeoutSec || '-' }}<span style="font-size:12px">s</span></div>
            <div class="stat-sub mono small" :title="eng.binDir">{{ 'bin: ' + (eng.binDir || '-') }}</div>
          </div>
        </div>
        <div class="card-title" style="margin-top:14px">{{ t('en.orchLog') }} <span class="sub">{{ t('en.orchLogSub') }}</span></div>
        <div class="log-box eng-log">
          <div class="log-line muted" v-for="(l, i) in degradeLogLines" :key="i">{{ l }}</div>
          <Empty v-if="!degradeLogLines.length" :text="t('en.noOrchLog')" />
        </div>
      </template>
      <Empty v-else :text="t('en.orchUnavailable')" />
    </div>

    <div class="card">
      <div class="card-title">{{ t('en.engList') }} <span class="sub">{{ t('en.dir') }}<span class="mono">{{ env ? env.binDir : t('en.binDirDefault') }}</span></span></div>
      <div class="table-wrap" v-if="env && env.engines.length">
        <table class="table">
          <thead>
            <tr><th>{{ t('en.cEngine') }}</th><th>{{ t('en.cState') }}</th><th>{{ t('en.cVersion') }}</th><th>{{ t('en.cPath') }}</th><th>{{ t('en.cDegrade') }}</th><th>{{ t('en.cNote') }}</th></tr>
          </thead>
          <tbody>
            <tr v-for="e in env.engines" :key="e.name">
              <td class="mono">{{ e.name }}</td>
              <td>
                <span class="badge" :class="e.state === 'ok' ? 'st-success' : (e.state === 'detecting' ? 'st-running' : 'st-failed')">
                  {{ stateName(e.state) }}
                </span>
              </td>
              <td class="mono small">{{ e.version || '-' }}</td>
              <td class="mono small muted" :title="e.path">{{ e.path ? e.path.split(/[/\\]/).slice(-2).join('/') : '-' }}</td>
              <td>
                <span class="badge" v-if="e.fallback" style="color:var(--orange); border-color:rgba(251,146,60,.5); background:rgba(251,146,60,.08)">{{ t('en.degradedBadge') }}</span>
                <span class="muted small" v-else>-</span>
              </td>
              <td class="small muted">{{ e.error || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else :text="t('en.envDetecting')" />
      <div class="muted small" style="margin-top:10px">
        {{ t('en.placeNote1') }}
        {{ t('en.placeNote2') }}
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        {{ t('en.dlTitle') }}
        <span class="sub">{{ t('en.dlSub') }}</span>
      </div>
      <div class="muted small" style="margin-bottom:10px" v-if="dl">
        {{ dl.configured
          ? t('en.dlDir', { dir: dl.binDir, mb: (dl.cacheBytes / 1048576).toFixed(1), n: dl.cacheFiles })
          : t('en.dlNotEnabled') }}
        <span v-if="dl.extractTools && dl.extractTools.length"> · {{ t('en.extractors') }}{{ dl.extractTools.join(', ') }}</span>
        <!-- 自动补装状态: 让用户不必翻配置文件就知道自动化有没有在工作、待补哪些引擎 -->
        <div v-if="autoInstall && autoInstall.enabled" style="margin-top:4px">
          <span class="badge st-success">{{ t('en.autoOn') }}</span>
          <span v-if="autoInstall.pending && autoInstall.pending.length">
            {{ t('en.autoPending', { x: autoInstall.pending.join(', ') }) }}<span v-if="dlRunning">{{ t('en.inProgress') }}</span>
          </span>
          <span v-else>{{ t('en.autoAllIn') }}</span>
          <span v-if="!autoInstall.explicit"> {{ t('en.autoSkipZap') }}</span>
        </div>
        <div v-else-if="autoInstall" style="margin-top:4px">
          {{ t('en.autoOff') }}
        </div>
      </div>
      <div class="table-wrap" v-if="dl && dl.engines && dl.engines.length">
        <table class="table">
          <thead>
            <tr><th>{{ t('en.cEngine') }}</th><th>{{ t('en.cInstState') }}</th><th>{{ t('en.cVersion') }}</th><th>{{ t('en.cPkg') }}</th><th>{{ t('en.cOps') }}</th><th>{{ t('en.cNote') }}</th></tr>
          </thead>
          <tbody>
            <tr v-for="e in dl.engines" :key="e.engine">
              <td>{{ e.display || e.engine }}</td>
              <td>
                <span class="badge" :class="e.installed ? 'st-success' : (e.supported ? 'st-failed' : 'st-running')">
                  {{ e.installed ? t('en.installed') : (e.supported ? t('en.notInstalled') : t('en.cannotFetch')) }}
                </span>
              </td>
              <td class="mono small">{{ e.installedVersion || e.latestVersion || '-' }}</td>
              <td class="mono small muted">{{ e.assetName || '-' }}</td>
              <td>
                <template v-if="e.supported && dl.configured">
                  <button class="btn sm" style="margin-right:6px" :disabled="dlRunning || dlBusy"
                          @click="installOne(e.engine, e.installed)">
                    {{ e.installed ? t('en.reinstall') : t('en.download') }}
                  </button>
                  <button class="btn sm danger" v-if="e.installed" :disabled="dlRunning || dlBusy"
                          @click="uninstall(e.engine)">{{ t('en.uninstall') }}</button>
                </template>
                <span class="muted small" v-else-if="!dl.configured">{{ t('en.needMaster') }}</span>
                <span class="muted small" v-else>{{ t('en.needManual') }}</span>
              </td>
              <td class="small muted">
                <!-- 运行时依赖缺失必须显著标出(红色), 不能混在灰色说明里:
                     ZAP 是 Java 程序且官方免安装包不含 Java, 本机没有 Java 17+ 时装完也起不来 ——
                     用户会以为"装成功了", 实际一执行就 class 版本报错, 极难自行定位。 -->
                <div v-if="e.runtimeMissing" style="color:var(--red); margin-bottom:4px">
                  ⚠ {{ e.runtimeMissing }}
                </div>
                {{ [e.note, e.defaultOff ? t('en.defaultOff', { x: e.defaultOff }) : '', e.unsupportedReason].filter(Boolean).join(' · ') }}
                <a v-if="e.homepage" :href="e.homepage" target="_blank" rel="noopener">{{ t('en.officialLink') }}</a>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else :text="t('en.noDlList')" />
      <!-- 审计 §4-10: 首行给结论, 细节折叠 -->
      <details class="muted small" style="margin-top:10px">
        <summary style="cursor:pointer">{{ t('en.pkgSummary') }}</summary>
        <div style="margin-top:6px">
          {{ t('en.pkgNote') }}
        </div>
      </details>
    </div>

    <div class="card">
      <div class="card-title">{{ t('en.javaTitle') }} <span class="sub">{{ t('en.javaSub') }}</span></div>
      <div class="kv" v-if="env">
        <div class="k">{{ t('en.javaReq') }}</div><div class="v">{{ t('en.javaMin', { x: env.java.minVersion }) }}</div>
        <div class="k">{{ t('en.detectState') }}</div>
        <div class="v">
          <span class="badge" :class="env.java.ok ? 'st-success' : 'st-failed'">
            {{ env.java.ok ? t('en.javaOk') : (env.java.found ? t('en.javaLow') : t('en.notInstalled')) }}
          </span>
          <span class="small muted" v-if="env.java.version" style="margin-left:8px">{{ env.java.version }}</span>
          <!-- "自带"与"系统"必须区分开: 自带 = 这台机器什么都不用装, 整个 zapcore 拷走
               也能跑; 系统 = 换台电脑还得再装一遍。笼统写成"满足"会让人白装一个 Java。 -->
          <span class="badge st-success" v-if="env.java.bundled" style="margin-left:6px">{{ t('en.javaBundled') }}</span>
        </div>
        <template v-if="env.java.path">
          <div class="k">{{ t('en.javaPath') }}</div>
          <div class="v mono small" style="word-break:break-all">{{ env.java.path }}</div>
        </template>
        <div class="k">{{ t('en.cNote') }}</div>
        <div class="v small" :style="{ color: env.java.ok ? 'var(--muted)' : 'var(--red)' }">
          {{ env.java.ok ? (env.java.note || t('en.javaOkNote')) : (env.java.note || t('en.javaDetecting')) }}
        </div>
      </div>
      <div class="muted small" style="margin-top:10px">
        <template v-if="env && env.java.bundled">
          {{ t('en.javaBundledNote1') }} <b>{{ t('en.javaBundledJdk') }}</b> {{ t('en.javaBundledNote2') }}
        </template>
        <template v-else>
          {{ t('en.javaNoJava1') }}<b>{{ t('en.javaNoJava2') }}</b>{{ t('en.javaNoJava3') }}
          <b>{{ t('en.javaAutoDl', { x: env ? env.java.minVersion : 17 }) }}</b> {{ t('en.javaNoJava4') }}
          {{ t('en.javaNoJava5', { x: env ? env.java.minVersion : 17 }) }}
        </template>
      </div>
    </div>

    <div class="card">
      <div class="card-title">{{ t('en.npcapTitle') }} <span class="sub">{{ t('en.npcapSub') }}</span></div>
      <div class="kv" v-if="env">
        <div class="k">{{ t('en.platform') }}</div><div class="v">{{ env.npcap.supported ? t('en.supported') : t('en.notSupported', { x: env.os }) }}</div>
        <div class="k">{{ t('en.instState') }}</div>
        <div class="v">
          <span class="badge" :class="npcapOk ? 'st-success' : 'st-failed'">{{ env.npcap.installed ? t('en.installed') : t('en.notInstalled') }}</span>
          <span class="small muted" v-if="env.npcap.version" style="margin-left:8px">v{{ env.npcap.version }}</span>
        </div>
        <div class="k">{{ t('en.evidence') }}</div><div class="v mono small">{{ env.npcap.source || '-' }}</div>
        <div class="k">{{ t('en.installer') }}</div><div class="v mono small" :title="env.npcap.installer">{{ env.npcap.installer || t('en.installerNotFound') }}</div>
      </div>
      <div class="muted small" style="margin-top:10px">
        {{ t('en.installHow') }}
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import Empty from '../components/Empty.vue'
import { api } from '../api/http'
import { fmtDT, fmtBytes, fmtSpeed, fmtDuration, etaSeconds } from '../utils'
import { t } from '../i18n'

// ===== 引擎解析编排 / 自动降级(GET /api/engine/status, POST /api/engine/refresh) =====
// 与上面的 /api/env 是两种视角: env 探测"文件在不在", engine/status 统计"实际跑过什么"。
const eng = ref(null)
const engBusy = ref(false)
const engMsg = ref('')

const degradeCount = computed(() => (eng.value && eng.value.degradeCount) || 0)
// 后端日志是环形缓冲(旧的在前), 展示倒序让最新一条在最上面
const degradeLogLines = computed(() => {
  const l = (eng.value && eng.value.degradeLog) || []
  return l.slice().reverse()
})
// 启用的引擎清单: 空表示不限(全部)
const engineListText = computed(() => {
  if (!eng.value) return ''
  const list = eng.value.engines || []
  return t('en.enginesLabel', { x: list.length ? list.join('/') : t('en.allEngines') })
})

async function loadEngine() {
  try {
    eng.value = await api('/api/engine/status')
    engMsg.value = ''
  } catch (e) { eng.value = null; engMsg.value = t('en.orchLoadFail', { err: e.message }) }
}

// 重载 = 重读 settings.json 的 engine 节并重建编排器(改完开关不必重启整个服务)
async function reloadEngine() {
  engBusy.value = true
  engMsg.value = ''
  try {
    const d = await api('/api/engine/refresh', { method: 'POST' })
    await loadEngine()
    engMsg.value = t('en.reloadOk', { x: d.enabled ? t('en.reloadOn') : t('en.reloadOff') })
  } catch (e) { engMsg.value = t('en.reloadFail', { err: e.message }) }
  finally { engBusy.value = false }
}

// 引擎状态键值化: 值存词条键, 渲染期 t() 解析(未知状态原样显示)
const STATE_NAME = { ok: 'en.stOk', missing: 'en.stMissing', detecting: 'en.stDetecting', error: 'en.stError' }
function stateName(s) { return STATE_NAME[s] ? t(STATE_NAME[s]) : s }

const env = ref(null)
const busy = ref(false)
const installing = ref(false)
const installMsg = ref('')
let pollTimer = null

const degraded = computed(() => (env.value && env.value.degraded) || [])
const okCount = computed(() => ((env.value && env.value.engines) || []).filter(e => e.state === 'ok').length)
const npcapText = computed(() => {
  if (!env.value) return '-'
  if (!env.value.npcap.supported) return 'N/A'
  return env.value.npcap.installed ? t('en.installed') : t('en.notInstalled')
})
const npcapSub = computed(() => {
  if (!env.value) return ''
  if (!env.value.npcap.supported) return t('en.captureWinOnly')
  return env.value.npcap.installed ? (env.value.npcap.version || '') + ' · ' + (env.value.npcap.source || '') : t('en.captureUnavailable')
})
const npcapOk = computed(() => !!env.value && (!env.value.npcap.supported || env.value.npcap.installed))
const canInstall = computed(() => !!env.value && env.value.npcap.supported && !env.value.npcap.installed && !!env.value.npcap.installer)

async function load() {
  try { env.value = await api('/api/env') } catch (e) { env.value = null }
}

async function refresh() {
  busy.value = true
  installMsg.value = ''
  try {
    env.value = await api('/api/env/refresh', { method: 'POST' })
  } catch (e) { installMsg.value = e.message }
  finally { busy.value = false }
  // 检测异步进行, 轮询到结束
  pollTimer = setInterval(async () => {
    await load()
    if (env.value && !env.value.detecting) { clearInterval(pollTimer); pollTimer = null }
  }, 2000)
}

async function install() {
  if (!confirm(t('en.installConfirm'))) return
  installing.value = true
  installMsg.value = ''
  try {
    const d = await api('/api/env/install', { method: 'POST' })
    installMsg.value = t('en.installDone', { x: d.installer || '' })
    await load()
  } catch (e) { installMsg.value = t('en.installFail', { x: e.message }) }
  finally { installing.value = false }
}

// ===== 外部引擎一键下载/安装 =====
const dl = ref(null)
const dlBusy = ref(false)
const dlRunning = ref(false)
const dlResults = ref([])
// dlErr 任务失败原因(来自 /progress 的 error 字段)。
// 后端会把"所有镜像均不可用, 已停止安装 + 逐个候选的失败原因"放在这里, 必须展示
// 出来 —— 否则用户只看到进度条消失、按钮恢复, 完全不知道刚才发生了什么。
const dlErr = ref('')
let dlTimer = null

const dlResultsComputed = computed(() => (dl.value && dl.value.results) || [])

// ===== 进度展示辅助 =====

// overallPercent 总进度百分比。
//
// 【为什么不能直接用 progress.percent】那个字段只描述"当前这一个引擎的下载百分比"。
// 批量安装 3 个引擎时, 第 2 个刚起步就会显示 0%, 用户会以为卡住了 —— 实际上第 1 个
// 已经装完了。这里按 "已完成个数 + 当前引擎内进度" 折算成整体进度:
//   (done + 当前进度) / total * 100
// 阶段(解包/落位)没有百分比, 按"当前引擎已完成 90%"估, 保证进度条不会突然回退。
const overallPercent = computed(() => {
  const p = (dl.value && dl.value.progress) || {}
  const total = p.total || 0
  if (!total) return 0
  const done = p.done || 0
  let cur = 0
  if (p.status === 'downloading') {
    cur = p.percent >= 0 ? p.percent / 100 : 0
  } else if (p.status === 'done') {
    cur = 1
  } else if (p.status === 'extracting' || p.status === 'installing') {
    // 包已下完, 只剩本地解包/落位(通常几秒), 用 0.9 表示"当前这个快好了"
    cur = 0.9
  } else if (p.status === 'checking') {
    cur = 0.05
  }
  // 注意: 不 clamp 到 100 之上, 也避免 done 已满时还显示 100 以下
  const v = Math.round(((done + cur) / total) * 100)
  return Math.max(0, Math.min(100, v))
})

// engineLabel 把引擎 key 转成可读名(优先用列表里的 display 名)
function engineLabel(key) {
  if (!key) return ''
  const list = (dl.value && dl.value.engines) || []
  const hit = list.find((e) => e.engine === key)
  return hit ? hit.display || key : key
}

// etaText 剩余时间估算。上游未给总长度(totalBytes<=0)时无法估算, 返回空。
const etaText = computed(() => {
  const p = (dl.value && dl.value.progress) || {}
  if (p.status !== 'downloading') return ''
  return fmtDuration(etaSeconds(p.bytes, p.totalBytes, p.speed))
})

// mirrorProbeList 镜像探测明细(后端已按"可用优先 + 速度降序"排好, 直接展示)
const mirrorProbeList = computed(() => {
  const p = (dl.value && dl.value.mirrorProbe) || (dl.value && dl.value.progress && dl.value.progress.mirrorProbe)
  return Array.isArray(p) ? p : []
})

// dlNote 各阶段的补充说明: 把"为什么这一阶段可能很久"讲清楚,
// 避免用户以为卡死(ZAP 233MB / 解包器缺失 / 镜像生效等)
const dlNote = computed(() => {
  const p = (dl.value && dl.value.progress) || {}
  // 阶段文案里的关键字优先于状态文案: ZAP 的 JDK 环节会复用 downloading/extracting
  // 状态(语义上确实是同一个 ZAP 任务), 但用户需要知道"现在下的是 Java 而不是 ZAP 本身",
  // 否则看到 273MB 之后又冒出一个 190MB 的下载会以为出错了。
  const phase = p.phase || ''
  if (phase.indexOf('JDK') >= 0) {
    if (p.status === 'downloading') {
      return t('en.dlNoteJdk')
    }
    if (p.status === 'extracting') {
      return t('en.dlNoteJdkExtract')
    }
  }
  if (phase.indexOf('JDK 17 最新版本') >= 0) {
    return t('en.dlNoteJdkQuery')
  }
  switch (p.status) {
    case 'checking':
      return t('en.dlNoteCheck')
    case 'extracting':
      return t('en.dlNoteExtract')
    case 'installing':
      return t('en.dlNoteInstall')
    case 'downloading':
      if (dl.value && dl.value.mirror) return t('en.dlNoteMirror')
      return t('en.dlNoteDirect')
    default:
      return ''
  }
})

async function loadDl() {
  dlBusy.value = true
  try {
    dl.value = await api('/api/engine/downloads')
    dlRunning.value = !!dl.value.running
    dlResults.value = dlResultsComputed.value
    dlErr.value = dl.value.lastError || ''
    if (dlRunning.value) startDlPoll()
  } catch (e) { dl.value = null }
  finally { dlBusy.value = false }
}

function startDlPoll() {
  if (dlTimer) return
  dlTimer = setInterval(async () => {
    try {
      const p = await api('/api/engine/downloads/progress')
      // 进度端点与状态端点的 progress 字段同构, 直接合并进 dl 保证模板只认一份数据
      if (dl.value) {
        dl.value.progress = p.progress || {}
        // 镜像探测结论随进度一起回来: 探测发生在下载之前, 若不等这一路, 用户会看到
        // "检测镜像可用性"的阶段条却没有明细, 像是卡住了
        if (p.mirrorProbe) dl.value.mirrorProbe = p.mirrorProbe
        if (p.mirrorInUse) dl.value.mirrorInUse = p.mirrorInUse
      }
      dlRunning.value = !!p.running
      // 失败时把后端的具体原因带出来(如"所有下载镜像均不可用"), 而不是只显示"失败"
      dlErr.value = p.running ? '' : (p.error || '')
      if (!p.running) {
        clearInterval(dlTimer); dlTimer = null
        await loadDl()
        await load() // 装完刷新引擎探测结果
      }
    } catch (e) { /* 瞬时抖动, 下一轮重试 */ }
  }, 1500)
}

async function startDownload(engines) {
  try {
    const d = await api('/api/engine/downloads/start', {
      method: 'POST',
      body: JSON.stringify(engines ? { engines } : {})
    })
    dlRunning.value = true
    dlResults.value = []
    if (dl.value) dl.value.progress = { phase: t('en.taskStarted'), engine: (engines || [t('en.defaultSet')]).join(',') }
    startDlPoll()
  } catch (e) { alert(t('en.startFail', { x: e.message })) }
}

async function installOne(engine, installed) {
  // 确认提示保持一行(审计 §4.11): 版本选择细节属实现决策, 不该塞进用户确认框。
  const extra = engine === 'zap' ? t('en.zapNote')
    : (engine === 'nmap' ? t('en.nmapNote') : '')
  if (!confirm(t('en.confirmInstall', { re: installed ? t('en.redo') : '', x: engine }) + extra)) return
  await startDownload([engine])
}

async function uninstall(engine) {
  if (!confirm(t('en.confirmUninstall', { x: engine }))) return
  try {
    await api('/api/engine/downloads/uninstall', { method: 'POST', body: JSON.stringify({ engine }) })
    await loadDl(); await load()
  } catch (e) { alert(t('en.uninstallFail', { x: e.message })) }
}

// 引擎自动补装: 把后端回报的"能补什么/为什么不能"如实翻成给用户看的一句话。
// 不在这里做任何"自动开启"的暗示 —— 开关在配置文件里, 页面只负责说清楚怎么开
// (在用户机器上悄悄改配置文件比不帮他更糟)。
const autoInstall = computed(() => (dl.value && dl.value.autoInstall) || null)

async function installDefaults() {
  if (!dl.value || !dl.value.configured) {
    // 未启用时给出最省事的开启方式: 只写 autoInstall 一项即可(它蕴含允许下载)
    alert(t('en.dlDisabled1') + '\n\n  { "downloads": { "autoInstall": true } }\n\n' + t('en.dlDisabled2'))
    return
  }
  if (!confirm(t('en.confirmDefaults'))) return
  await startDownload(null)
}

onMounted(() => {
  load()
  loadDl()
  loadEngine()
  pollTimer = setInterval(async () => {
    await load()
    if (env.value && !env.value.detecting) { clearInterval(pollTimer); pollTimer = null }
  }, 3000)
})

onBeforeUnmount(() => {
  if (pollTimer) clearInterval(pollTimer)
  if (dlTimer) { clearInterval(dlTimer); dlTimer = null }
})
</script>

<style scoped>
/* 降级日志只做排障线索, 给固定高度滚动即可, 不必占满 420px */
.eng-log { height: 180px; font-size: 12px; }
.err-line { color: var(--red); min-height: 16px; }
</style>

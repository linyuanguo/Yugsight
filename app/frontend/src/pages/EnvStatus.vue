<template>
  <div>
    <PageHeader title="引擎状态" desc="本地引擎 ./bin/ 探测 + Npcap 驱动检测, 缺失自动降级内置引擎">
      <button class="btn sm" :disabled="busy || (env && env.detecting)" @click="refresh">
        <span class="spinner" v-if="busy || (env && env.detecting)"></span> 重新检测
      </button>
      <button class="btn sm danger" v-if="canInstall" :disabled="installing" @click="install">
        <span class="spinner" v-if="installing"></span> 安装网络驱动 (Npcap)
      </button>
      <button class="btn sm" :disabled="dlBusy || dlRunning" @click="installDefaults">
        <span class="spinner" v-if="dlRunning"></span> 一键安装引擎
      </button>
      <button class="btn sm" :disabled="dlBusy" @click="loadDl">刷新可下载列表</button>
    </PageHeader>

    <div class="alert" v-if="installing" style="margin-bottom:14px">
      <span class="spinner"></span> 正在等待 Npcap 安装向导完成(最长 5 分钟, 请在弹出的安装窗口中点完)...</div>
    <div class="alert info" v-else-if="installMsg" style="margin-bottom:14px">{{ installMsg }}</div>

    <!-- 引擎下载: 进行中实时进度 / 空闲时逐项结果(失败项带官方下载页兜底) -->
    <div class="card dl-progress-card" v-if="dlRunning" style="margin-bottom:14px">
      <div class="dl-head">
        <span class="spinner"></span>
        <strong>{{ dl.progress.phase || dl.progress.status || '处理中' }}</strong>
        <span class="mono muted" v-if="dl.progress.engine">{{ engineLabel(dl.progress.engine) }}</span>
        <span class="mono muted" v-if="dl.progress.version">v{{ dl.progress.version }}</span>
        <span v-if="dl.progress.status === 'downloading' && dl.progress.total" class="mono small muted">
          (第 {{ Math.min((dl.progress.done || 0) + 1, dl.progress.total) }}/{{ dl.progress.total }} 个)
        </span>
      </div>

      <!-- 总进度: 按"已完成引擎数 + 当前引擎内进度"折算, 多引擎批量安装时不会永远停在 0% -->
      <div class="bar-row">
        <span class="bar-label">总进度</span>
        <div class="bar-track">
          <div class="bar-fill" :style="{ width: overallPercent + '%', background: 'var(--accent)' }"></div>
        </div>
        <span class="bar-val">{{ overallPercent }}%</span>
      </div>

      <!-- 当前引擎的下载进度: 只有 downloading 阶段才有意义(查版本/解包/落位无百分比) -->
      <div class="bar-row" v-if="dl.progress.status === 'downloading' && dl.progress.percent >= 0">
        <span class="bar-label">当前包</span>
        <div class="bar-track">
          <div class="bar-fill" :style="{ width: dl.progress.percent + '%', background: 'var(--green)' }"></div>
        </div>
        <span class="bar-val">{{ dl.progress.percent }}%</span>
      </div>

      <div class="dl-meta small" v-if="dl.progress.status === 'downloading'">
        <span class="mono">{{ fmtBytes(dl.progress.bytes) }} / {{ fmtBytes(dl.progress.totalBytes) }}</span>
        <span v-if="dl.progress.speed > 0" class="mono"> · {{ fmtSpeed(dl.progress.speed) }}</span>
        <span v-if="etaText" class="mono"> · 剩余约 {{ etaText }}</span>
        <!-- 当前下载的是哪个包: ZAP 会连下两个包(273MB 的 ZAP + 190MB 的 JDK),
             若不说明, 用户会看到"进度条走完又从头开始"而以为任务重跑了。 -->
        <span v-if="dl.progress.phase" class="muted"> · {{ dl.progress.phase }}</span>
      </div>

      <!-- 镜像探测结论: 让"先检测再下载"这件事可见, 而不是黑箱 -->
      <div class="dl-mirror" v-if="mirrorProbeList.length">
        <span class="small muted">镜像探测:</span>
        <span v-for="(m, i) in mirrorProbeList" :key="i" class="mirror-item" :class="m.ok ? 'ok' : 'bad'">
          <span class="mono">{{ m.prefix }}</span>
          <template v-if="m.ok"> {{ fmtSpeed(m.speed) }}</template>
          <template v-else> {{ m.error }}</template>
          <span v-if="m.prefix === dl.mirrorInUse" class="badge st-success">使用中</span>
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
          {{ r.ok ? '成功' : (r.skipped ? '跳过' : '失败') }}
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
        <a v-if="r.homepage" :href="r.homepage" target="_blank" rel="noopener">官方下载页</a>
      </div>
    </div>

    <div class="grid cols-4">
      <div class="card">
        <div class="stat-label">检测状态</div>
        <div class="stat-value" style="font-size:20px">{{ env && env.detecting ? '检测中' : '已就绪' }}</div>
        <div class="stat-sub mono">{{ env ? fmtDT(env.checkedAt) : '-' }}</div>
      </div>
      <div class="card">
        <div class="stat-label">引擎就绪</div>
        <div class="stat-value" style="font-size:20px">{{ okCount }} / {{ (env && env.engines && env.engines.length) || 0 }}</div>
        <div class="stat-sub">本地引擎, 缺失自动降级</div>
      </div>
      <div class="card">
        <div class="stat-label">Npcap 驱动</div>
        <div class="stat-value" style="font-size:20px">{{ npcapText }}</div>
        <div class="stat-sub">{{ npcapSub }}</div>
      </div>
      <div class="card">
        <div class="stat-label">降级引擎</div>
        <div class="stat-value" style="font-size:20px">{{ degraded.length }}</div>
        <div class="stat-sub">{{ degraded.length ? degraded.join(', ') : '无降级' }}</div>
      </div>
    </div>

    <!-- ===== 引擎解析编排 / 自动降级(移植自经典页 "引擎" 页签) =====
         这里的 6 项统计不是"文件是否存在"(那是上面的环境探测), 而是"实际跑起来之后发生了什么":
         外部引擎有没有真的被接入、降级过几次、最近一次结果是哪套引擎产出的。
         引擎不好用时这是唯一的排障线索。 -->
    <div class="card" style="margin-top:14px">
      <div class="card-title">
        解析编排 / 自动降级
        <span class="sub">引擎异常时自动回落内置引擎, 不中断任务</span>
        <div style="flex:1"></div>
        <button class="btn sm" :disabled="engBusy" @click="reloadEngine">
          <span class="spinner" v-if="engBusy"></span> 重载引擎配置
        </button>
      </div>
      <div class="muted small err-line">{{ engMsg }}</div>
      <template v-if="eng">
        <div class="grid cols-3">
          <div class="card">
            <div class="stat-label">外部引擎编排</div>
            <div class="stat-value" style="font-size:18px" :style="{ color: eng.enabled ? 'var(--green)' : 'var(--muted)' }">
              {{ eng.enabled ? '已启用' : '未启用' }}
            </div>
            <div class="stat-sub mono small">settings.json · engine 节</div>
          </div>
          <div class="card">
            <div class="stat-label">外部执行器</div>
            <div class="stat-value" style="font-size:18px" :style="{ color: eng.execReady ? 'var(--green)' : 'var(--orange)' }">
              {{ eng.execReady ? '就绪' : '未接入' }}
            </div>
            <div class="stat-sub">{{ engineListText }}</div>
          </div>
          <div class="card">
            <div class="stat-label">内置引擎兜底</div>
            <div class="stat-value" style="font-size:18px" :style="{ color: eng.fallbackReady ? 'var(--green)' : 'var(--red)' }">
              {{ eng.fallbackReady ? '可用' : '不可用' }}
            </div>
            <div class="stat-sub">始终存在, 零外部依赖</div>
          </div>
          <div class="card">
            <div class="stat-label">累计降级次数</div>
            <div class="stat-value" style="font-size:18px" :style="{ color: degradeCount ? 'var(--orange)' : 'var(--green)' }">
              {{ degradeCount }}
            </div>
            <div class="stat-sub">{{ degradeCount ? '已回落内置, 见下方日志' : '未发生降级' }}</div>
          </div>
          <div class="card">
            <div class="stat-label">最近结果来源</div>
            <div class="stat-value mono" style="font-size:18px">{{ eng.lastSource || '-' }}</div>
            <div class="stat-sub">内置: portscan / 外部: 引擎名</div>
          </div>
          <div class="card">
            <div class="stat-label">单引擎超时</div>
            <div class="stat-value" style="font-size:18px">{{ eng.timeoutSec || '-' }}<span style="font-size:12px">s</span></div>
            <div class="stat-sub mono small" :title="eng.binDir">{{ 'bin: ' + (eng.binDir || '-') }}</div>
          </div>
        </div>
        <div class="card-title" style="margin-top:14px">编排 / 降级日志 <span class="sub">按时间倒序, 最多保留 100 条</span></div>
        <div class="log-box eng-log">
          <div class="log-line muted" v-for="(l, i) in degradeLogLines" :key="i">{{ l }}</div>
          <Empty v-if="!degradeLogLines.length" text="暂无编排日志" />
        </div>
      </template>
      <Empty v-else text="编排状态不可用" />
    </div>

    <div class="card">
      <div class="card-title">本地引擎列表 <span class="sub">目录: <span class="mono">{{ env ? env.binDir : 'exe 同目录 ./bin/' }}</span></span></div>
      <div class="table-wrap" v-if="env && env.engines.length">
        <table class="table">
          <thead>
            <tr><th>引擎</th><th>状态</th><th>版本</th><th>路径</th><th>降级</th><th>说明</th></tr>
          </thead>
          <tbody>
            <tr v-for="e in env.engines" :key="e.name">
              <td class="mono">{{ e.name }}</td>
              <td>
                <span class="badge" :class="e.state === 'ok' ? 'st-success' : (e.state === 'detecting' ? 'st-running' : 'st-failed')">
                  {{ STATE_NAME[e.state] || e.state }}
                </span>
              </td>
              <td class="mono small">{{ e.version || '-' }}</td>
              <td class="mono small muted" :title="e.path">{{ e.path ? e.path.split(/[/\\]/).slice(-2).join('/') : '-' }}</td>
              <td>
                <span class="badge" v-if="e.fallback" style="color:var(--orange); border-color:rgba(251,146,60,.5); background:rgba(251,146,60,.08)">已降级</span>
                <span class="muted small" v-else>-</span>
              </td>
              <td class="small muted">{{ e.error || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else text="环境检测中或不可用" />
      <div class="muted small" style="margin-top:10px">
        放置方式: 将 nmapcore / trivycore / zapcore 可执行文件放入 exe 同目录 bin/ 子目录(Windows 需 .exe 后缀)。
        未放置不影响使用 —— 内置引擎兜底, 仅多引擎能力降级。
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        外部引擎一键安装
        <span class="sub">从厂商官方发行页自动获取, 解包后装入 bin/</span>
      </div>
      <div class="muted small" style="margin-bottom:10px" v-if="dl">
        {{ dl.configured
          ? `安装目录: ${dl.binDir} · 下载缓存 ${(dl.cacheBytes / 1048576).toFixed(1)}MB / ${dl.cacheFiles} 个包`
          : '未启用: 在 exe 同目录 engine.json 中增加 downloads.allowDownload=true 后重启即可一键安装官方引擎' }}
        <span v-if="dl.extractTools && dl.extractTools.length"> · 解包器: {{ dl.extractTools.join(', ') }}</span>
        <!-- 自动补装状态: 让用户不必翻配置文件就知道自动化有没有在工作、待补哪些引擎 -->
        <div v-if="autoInstall && autoInstall.enabled" style="margin-top:4px">
          <span class="badge st-success">自动补装已开启</span>
          <span v-if="autoInstall.pending && autoInstall.pending.length">
            · 待补: {{ autoInstall.pending.join(', ') }}<span v-if="dlRunning"> (进行中)</span>
          </span>
          <span v-else>· 缺失的引擎已全部就位</span>
          <span v-if="!autoInstall.explicit"> · 默认跳过 ZAP(体积大且需 Java), 需要请写 autoInstallEngines</span>
        </div>
        <div v-else-if="autoInstall" style="margin-top:4px">
          未开启自动补装: engine.json 的 downloads.autoInstall=true 后, 启动时会自动装好缺失的引擎
        </div>
      </div>
      <div class="table-wrap" v-if="dl && dl.engines && dl.engines.length">
        <table class="table">
          <thead>
            <tr><th>引擎</th><th>安装状态</th><th>版本</th><th>将下载的包</th><th>操作</th><th>说明</th></tr>
          </thead>
          <tbody>
            <tr v-for="e in dl.engines" :key="e.engine">
              <td>{{ e.display || e.engine }}</td>
              <td>
                <span class="badge" :class="e.installed ? 'st-success' : (e.supported ? 'st-failed' : 'st-running')">
                  {{ e.installed ? '已安装' : (e.supported ? '未安装' : '不可自动获取') }}
                </span>
              </td>
              <td class="mono small">{{ e.installedVersion || e.latestVersion || '-' }}</td>
              <td class="mono small muted">{{ e.assetName || '-' }}</td>
              <td>
                <template v-if="e.supported && dl.configured">
                  <button class="btn sm" style="margin-right:6px" :disabled="dlRunning || dlBusy"
                          @click="installOne(e.engine, e.installed)">
                    {{ e.installed ? '重新安装' : '下载安装' }}
                  </button>
                  <button class="btn sm danger" v-if="e.installed" :disabled="dlRunning || dlBusy"
                          @click="uninstall(e.engine)">卸载</button>
                </template>
                <span class="muted small" v-else-if="!dl.configured">需开启总开关</span>
                <span class="muted small" v-else>需手动获取</span>
              </td>
              <td class="small muted">
                <!-- 运行时依赖缺失必须显著标出(红色), 不能混在灰色说明里:
                     ZAP 是 Java 程序且官方免安装包不含 Java, 本机没有 Java 17+ 时装完也起不来 ——
                     用户会以为"装成功了", 实际一执行就 class 版本报错, 极难自行定位。 -->
                <div v-if="e.runtimeMissing" style="color:var(--red); margin-bottom:4px">
                  ⚠ {{ e.runtimeMissing }}
                </div>
                {{ [e.note, e.defaultOff ? '默认不装: ' + e.defaultOff : '', e.unsupportedReason].filter(Boolean).join(' · ') }}
                <a v-if="e.homepage" :href="e.homepage" target="_blank" rel="noopener">官方页</a>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else text="无法获取可下载列表" />
      <!-- 审计 §4-10: 首行给结论, 细节折叠 -->
      <details class="muted small" style="margin-top:10px">
        <summary style="cursor:pointer">官方免安装包, 解压即用(ZAP 需 Java 17+, 已内置 JDK)</summary>
        <div style="margin-top:6px">
          下载源为各厂商官方发布页, 不写系统目录、不运行安装向导。
          ZAP 包约 273MB, 默认不勾选; 全部失败时表格内给出官方下载页链接。
          国内网络可在 settings.json 的 engine.downloads 中配置 proxy 或 githubMirror。
        </div>
      </details>
    </div>

    <div class="card">
      <div class="card-title">Java 运行时 <span class="sub">仅 ZAP 依赖; 其它引擎是原生二进制不需要</span></div>
      <div class="kv" v-if="env">
        <div class="k">版本要求</div><div class="v">Java {{ env.java.minVersion }} 或更高</div>
        <div class="k">检测状态</div>
        <div class="v">
          <span class="badge" :class="env.java.ok ? 'st-success' : 'st-failed'">
            {{ env.java.ok ? '满足' : (env.java.found ? '版本过低' : '未安装') }}
          </span>
          <span class="small muted" v-if="env.java.version" style="margin-left:8px">{{ env.java.version }}</span>
          <!-- "自带"与"系统"必须区分开: 自带 = 这台机器什么都不用装, 整个 zapcore 拷走
               也能跑; 系统 = 换台电脑还得再装一遍。笼统写成"满足"会让人白装一个 Java。 -->
          <span class="badge st-success" v-if="env.java.bundled" style="margin-left:6px">ZAP 内置</span>
        </div>
        <template v-if="env.java.path">
          <div class="k">位置</div>
          <div class="v mono small" style="word-break:break-all">{{ env.java.path }}</div>
        </template>
        <div class="k">说明</div>
        <div class="v small" :style="{ color: env.java.ok ? 'var(--muted)' : 'var(--red)' }">
          {{ env.java.ok ? (env.java.note || 'ZAP 可正常启动') : (env.java.note || '检测中...') }}
        </div>
      </div>
      <div class="muted small" style="margin-top:10px">
        <template v-if="env && env.java.bundled">
          本机使用 <b>ZAP 自带 JDK</b>(装在 ZAP 目录的 jre/ 子目录), 与系统 Java 完全隔离 ——
          本机无需安装任何 Java, 把整个 bin/zapcore 目录拷到别的电脑也能直接跑。
        </template>
        <template v-else>
          官方跨平台免安装包<b>不含 Java</b>。在引擎下载页安装/重装 ZAP 时, 程序会<b>自动下载
          JDK {{ env ? env.java.minVersion : 17 }}</b> 到 ZAP 目录的 jre/ 子目录并改写启动脚本
          优先使用它, 不再需要手工装 Java; 未装成时也可自行安装 Java {{ env ? env.java.minVersion : 17 }}+。
        </template>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Npcap 抓包驱动 <span class="sub">仅 Windows 适用; 抓包功能依赖</span></div>
      <div class="kv" v-if="env">
        <div class="k">平台支持</div><div class="v">{{ env.npcap.supported ? '支持 (Windows)' : '不支持 (当前 ' + env.os + ')' }}</div>
        <div class="k">安装状态</div>
        <div class="v">
          <span class="badge" :class="npcapOk ? 'st-success' : 'st-failed'">{{ env.npcap.installed ? '已安装' : '未安装' }}</span>
          <span class="small muted" v-if="env.npcap.version" style="margin-left:8px">v{{ env.npcap.version }}</span>
        </div>
        <div class="k">检测证据</div><div class="v mono small">{{ env.npcap.source || '-' }}</div>
        <div class="k">安装器</div><div class="v mono small" :title="env.npcap.installer">{{ env.npcap.installer || '未在 exe 同目录找到 (npcap-setup.exe / npcap-*.exe)' }}</div>
      </div>
      <div class="muted small" style="margin-top:10px">
        安装方式: 将官方安装器放到 exe 同目录后点击"安装网络驱动", 程序拉起安装向导并自动轮询安装结果。
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
  return '引擎 ' + (list.length ? list.join('/') : 'nmap/trivy/zap(全部)')
})

async function loadEngine() {
  try {
    eng.value = await api('/api/engine/status')
    engMsg.value = ''
  } catch (e) { eng.value = null; engMsg.value = '编排状态读取失败: ' + e.message }
}

// 重载 = 重读 settings.json 的 engine 节并重建编排器(改完开关不必重启整个服务)
async function reloadEngine() {
  engBusy.value = true
  engMsg.value = ''
  try {
    const d = await api('/api/engine/refresh', { method: 'POST' })
    await loadEngine()
    engMsg.value = '引擎配置已重载' + (d.enabled ? ' (外部引擎编排已启用)' : ' (外部引擎关闭, 全部走内置引擎)')
  } catch (e) { engMsg.value = '重载失败: ' + e.message }
  finally { engBusy.value = false }
}

const STATE_NAME = { ok: '就绪', missing: '缺失', detecting: '检测中', error: '异常' }

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
  return env.value.npcap.installed ? '已安装' : '未安装'
})
const npcapSub = computed(() => {
  if (!env.value) return ''
  if (!env.value.npcap.supported) return '抓包为 Windows 专属'
  return env.value.npcap.installed ? (env.value.npcap.version || '') + ' · ' + (env.value.npcap.source || '') : '抓包功能不可用'
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
  if (!confirm('将拉起 Npcap 安装向导, 请在弹出窗口中完成安装(最长等待 5 分钟). 继续?')) return
  installing.value = true
  installMsg.value = ''
  try {
    const d = await api('/api/env/install', { method: 'POST' })
    installMsg.value = 'Npcap 安装完成: ' + (d.installer || '')
    await load()
  } catch (e) { installMsg.value = '安装失败或已取消: ' + e.message }
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
      return '正在下载 ZAP 运行所需的 JDK 17(约 190MB, 装好后与系统 Java 隔离, 不会改 PATH)。'
    }
    if (p.status === 'extracting') {
      return '正在解压 JDK 17 到 ZAP 目录(约几千个文件, 需十几秒)…'
    }
  }
  if (phase.indexOf('JDK 17 最新版本') >= 0) {
    return '正在向 Adoptium 查询最新的 JDK 17 版本…'
  }
  switch (p.status) {
    case 'checking':
      return '正在查询上游最新版本…'
    case 'extracting':
      return '下载完成, 正在解包并抽取可执行文件(大包需要 10 秒左右)…'
    case 'installing':
      return '正在写入引擎目录…'
    case 'downloading':
      if (dl.value && dl.value.mirror) return '已启用 GitHub 镜像加速。'
      return '国内网络直连 GitHub 可能很慢; 可在 engine.json 配置 downloads.githubMirror 或 downloads.proxy。'
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
    if (dl.value) dl.value.progress = { phase: '任务已启动', engine: (engines || ['默认集合']).join(',') }
    startDlPoll()
  } catch (e) { alert('无法启动下载: ' + e.message) }
}

async function installOne(engine, installed) {
  // 确认提示保持一行(审计 §4.11): 版本选择细节属实现决策, 不该塞进用户确认框。
  const extra = engine === 'zap' ? '\nZAP 约 233MB, 需 Java 17+ 运行。'
    : (engine === 'nmap' ? '\n此包不含 Npcap, 仅 -sT 扫描可用。' : '')
  if (!confirm(`确定要${installed ? '重新' : ''}下载安装 ${engine} 吗?${extra}`)) return
  await startDownload([engine])
}

async function uninstall(engine) {
  if (!confirm(`确定要卸载 ${engine} 吗? 将从 bin/ 删除对应可执行文件(内置引擎始终可用)。`)) return
  try {
    await api('/api/engine/downloads/uninstall', { method: 'POST', body: JSON.stringify({ engine }) })
    await loadDl(); await load()
  } catch (e) { alert('卸载失败: ' + e.message) }
}

// 引擎自动补装: 把后端回报的"能补什么/为什么不能"如实翻成给用户看的一句话。
// 不在这里做任何"自动开启"的暗示 —— 开关在配置文件里, 页面只负责说清楚怎么开
// (在用户机器上悄悄改配置文件比不帮他更糟)。
const autoInstall = computed(() => (dl.value && dl.value.autoInstall) || null)

async function installDefaults() {
  if (!dl.value || !dl.value.configured) {
    // 未启用时给出最省事的开启方式: 只写 autoInstall 一项即可(它蕴含允许下载)
    alert('引擎下载未启用。可在 exe 同目录 engine.json 中设置:\n\n'
      + '  { "downloads": { "autoInstall": true } }\n\n'
      + '开启后启动时会把缺失的引擎自动装好(也可只设 allowDownload=true 保留手动安装)。')
    return
  }
  if (!confirm('将按默认勾选项依次下载安装官方引擎(Trivy / Nuclei)。\n\n包体从几十到上百 MB, 请确认网络可达。继续?')) return
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

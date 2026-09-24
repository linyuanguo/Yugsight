<template>
  <div>
    <PageHeader title="探针管理" desc="分布式扫描节点">
      <button class="btn sm" :disabled="loading" @click="load"><span class="spinner" v-if="loading"></span> 刷新</button>
      <button class="btn sm" @click="openDownload">下载探针</button>
      <button class="btn sm primary" :disabled="!assignReady" @click="showAssign = !showAssign">下发扫描任务</button>
    </PageHeader>

    <!-- 未启用: 一行说明 + 一键开启(写 settings.json, 重启生效) + 部署指引 -->
    <div class="alert info" v-if="status && !status.centerEnabled && !status.clientEnabled">
      分布式探针未启用(默认关闭, 不影响单机扫描)。
      <button class="btn sm primary" style="margin-left:10px" :disabled="enabling" @click="enableProbe">
        {{ enabling ? '开启中...' : '一键开启' }}
      </button>
      <a class="small" href="/api/v2/probe/agent/install" target="_blank">部署指引</a>
      <span class="muted small" v-if="enableMsg" style="margin-left:8px">{{ enableMsg }}</span>
      <details style="margin-top:8px">
        <summary class="muted small" style="cursor:pointer">高级: 手动配置 / 命令行参数</summary>
        <div class="muted small" style="margin-top:6px">
          在 exe 同目录 <span class="mono">settings.json</span> 加 <span class="mono">probe</span> 节,
          或命令行 <span class="mono">-probe=center</span>(中心端) / <span class="mono">-probe=both</span>(同机联调)。
          被扫描机器部署独立探针 <span class="mono">yugsight-agent</span>(点右上角<b>下载探针</b>)。
        </div>
      </details>
    </div>
    <div class="alert info" v-else-if="status && status.clientEnabled && !status.clientOnline" style="margin-bottom:14px">
      探针端已启用但尚未连上中心端({{ status.centerAddr || '-' }}), 正在自动重连...
    </div>

    <!-- 状态卡 -->
    <div class="grid cols-4">
      <div class="card">
        <div class="stat-label">中心端</div>
        <div class="stat-value" style="font-size:20px">{{ centerText }}</div>
        <div class="stat-sub">TCP 长连接监听</div>
      </div>
      <div class="card">
        <div class="stat-label">在线探针</div>
        <div class="stat-value" style="font-size:20px">{{ online.filter(p => p.online).length }} / {{ total }}</div>
        <div class="stat-sub">已登记 {{ total }} 个节点</div>
      </div>
      <div class="card">
        <div class="stat-label">本机角色</div>
        <div class="stat-value" style="font-size:20px">{{ roleText }}</div>
        <div class="stat-sub mono">{{ status && status.clientId ? status.clientId : '-' }}</div>
      </div>
      <div class="card">
        <div class="stat-label">协议版本</div>
        <div class="stat-value" style="font-size:20px">{{ status ? status.protocol : '-' }}</div>
        <div class="stat-sub">中心/探针需一致</div>
      </div>
    </div>

    <!-- 调度节点负载(GET /api/v2/scheduler/nodes): 探针列表给的是"注册快照",
         这里是调度器视角的"此刻能不能接活" —— 槽位占用/负载/能力/拒绝原因。 -->
    <div class="card">
      <div class="card-title">
        执行节点负载
        <span class="sub">调度器视角 · 槽位 / 负载 / 能力 / 接纳判定</span>
        <div class="spacer"></div>
        <span class="chip" :class="schedOn ? 'on' : 'off'">{{ schedOn ? '调度已启用' : '调度未启用' }}</span>
        <span class="muted small" v-if="schedNodes.length">全局并发上限 {{ schedCapacity || '-' }}</span>
      </div>
      <div v-if="!schedNodes.length" class="empty" style="min-height:80px">
        暂无执行节点(启用调度并接入探针后此处显示各节点槽位与负载)
      </div>
      <div class="table-wrap" v-else>
        <table class="table">
          <thead>
            <tr><th>节点</th><th>类型</th><th>在线</th><th>槽位</th><th>CPU</th><th>内存</th><th>执行中</th><th>能力</th><th>接纳判定</th></tr>
          </thead>
          <tbody>
            <tr v-for="n in schedNodes" :key="n.id">
              <td>
                <div class="small">{{ n.name || (n.kind === 'local' ? '中心本地' : n.id) }}</div>
                <div class="muted small mono">{{ n.id }}</div>
              </td>
              <td class="small">{{ NODE_KIND[n.kind] || n.kind || '-' }}</td>
              <td><span class="badge" :class="n.online ? 'st-success' : 'st-failed'">{{ n.online ? '在线' : '离线' }}</span></td>
              <!-- 槽位是调度器真正关心的量: 探针自报的 tasksRunning 只作交叉校验 -->
              <td class="mono small">{{ n.running || 0 }} / {{ n.max || '-' }}</td>
              <td class="mono small">{{ pct(n.cpuPercent) }}</td>
              <td class="mono small">{{ pct(n.memPercent) }}</td>
              <td class="mono small">{{ n.tasksRunning || 0 }}</td>
              <td>
                <span class="badge" v-for="c in capListOf(n.capabilities)" :key="c" style="margin-right:4px">{{ c }}</span>
                <span class="muted small" v-if="!capListOf(n.capabilities).length">-</span>
              </td>
              <td>
                <span class="badge st-success" v-if="!n.reject">可接纳</span>
                <span class="badge st-failed" v-else :title="n.reject.msg">{{ n.reject.msg }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 下发任务 -->
    <div class="card" v-if="showAssign">
      <div class="card-title">下发扫描任务到探针 <span class="sub">任务经中心端转发, 执行由探针完成, 结果回传落库</span></div>
      <div class="form-row">
        <div class="field" style="max-width:240px">
          <label class="label">目标探针 *</label>
          <select class="select" v-model="assign.probeId">
            <option value="">请选择在线探针</option>
            <option v-for="p in onlineProbes" :key="p.id" :value="p.id">{{ p.name || p.id }} ({{ p.addr || '-' }})</option>
          </select>
        </div>
        <div class="field" style="max-width:150px">
          <label class="label">类型</label>
          <select class="select" v-model="assign.type">
            <option value="port">端口扫描</option>
            <option value="ip">IP 存活</option>
            <option value="web">Web 漏洞</option>
            <option value="host">主机扫描</option>
          </select>
        </div>
        <div class="field">
          <label class="label">{{ assignTargetLabel }} *</label>
          <input class="input mono" v-model.trim="assign.target" :placeholder="assignTargetPh" @keyup.enter="doAssign">
        </div>
        <div class="field" style="max-width:180px" v-if="assign.type === 'port'">
          <label class="label">端口 (可选)</label>
          <input class="input mono" v-model.trim="assign.ports" placeholder="空 = 常用端口">
        </div>
        <div class="field" style="max-width:120px; align-self:flex-end">
          <button class="btn primary" style="width:100%" :disabled="assigning" @click="doAssign">
            {{ assigning ? '下发中...' : '下发' }}
          </button>
        </div>
      </div>
      <div class="login-err" style="text-align:left">{{ assignErr }}</div>
      <div class="muted small" v-if="assignMsg" style="margin-top:8px">{{ assignMsg }}</div>
    </div>

    <!-- 探针列表 -->
    <div class="card">
      <div class="toolbar">
        <span class="muted small">探针节点列表</span>
        <button class="btn sm" @click="load"><span class="spinner" v-if="loading"></span> 刷新</button>
        <div class="spacer"></div>
        <label class="checkbox"><input type="checkbox" v-model="onlyOnline"> 仅在线</label>
      </div>

      <div class="table-wrap" v-if="displayList.length">
        <table class="table">
          <thead>
            <tr>
              <th>状态</th><th>探针 ID</th><th>名称</th><th>系统</th><th>版本</th><th>地址</th>
              <th>能力</th><th>最近心跳</th><th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in displayList" :key="p.id">
              <td>
                <span class="badge" :class="p.online ? 'st-success' : 'st-failed'">{{ p.online ? '在线' : '离线' }}</span>
              </td>
              <td class="mono small">{{ p.id }}</td>
              <td class="small">{{ p.name || '-' }}</td>
              <td class="small mono">{{ osText(p) }}</td>
              <td class="mono small">
                <!-- 版本不一致时标红并给提示: 探针会在下次注册时自动更新(中心端已在
                     注册应答里下发更新指令), 用户看到红色只需知道"它会自己修好"，
                     不必手工去替换文件。 -->
                <span v-if="verState(p) === 'diff'" class="badge st-failed"
                      :title="'版本偏旧, 下次注册时自动更新至 ' + centerAgentVer">
                  {{ p.version || '未知' }} ↑{{ centerAgentVer }}
                </span>
                <span v-else-if="verState(p) === 'same'">{{ p.version }}</span>
                <span v-else class="muted">{{ p.version || '-' }}</span>
              </td>
              <td>
                <span class="badge" v-for="c in capList(p)" :key="c" style="margin-right:4px">{{ c }}</span>
                <span class="muted small" v-if="!capList(p).length">-</span>
              </td>
              <td class="muted small mono">{{ fmtDT(p.lastSeenAt) }}</td>
              <td>
                <div class="row-actions">
                  <button class="btn xs" @click="openDetail(p)">详情</button>
                  <button class="btn xs" :disabled="!p.online" @click="quickAssign(p)">下发</button>
                  <button class="btn xs danger" :disabled="p.online" :title="p.online ? '在线探针需先停止探针进程' : ''" @click="del(p)">移除</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else text="暂无探针节点(请在被控机放置 probe.json 并启动程序)" />
    </div>

    <!-- 本机探针端状态 -->
    <div class="grid cols-2" v-if="status && status.clientEnabled">
      <div class="card">
        <div class="card-title">本机探针端 <span class="sub">作为探针连接中心端</span></div>
        <div class="kv">
          <div class="k">节点 ID</div><div class="v mono">{{ status.clientId || '-' }}</div>
          <div class="k">中心端地址</div><div class="v mono">{{ status.centerAddr || '-' }}</div>
          <div class="k">连接状态</div>
          <div class="v">
            <span class="badge" :class="status.clientOnline ? 'st-success' : 'st-failed'">{{ status.clientOnline ? '已连接' : '重连中' }}</span>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">节点信息上报 <span class="sub">注册时自动采集</span></div>
        <div class="kv">
          <div class="k">操作系统</div><div class="v mono">{{ myInfo.os }} {{ myInfo.arch }}</div>
          <div class="k">内核版本</div><div class="v mono small">{{ myInfo.osVersion || '-' }}</div>
          <div class="k">CPU / 内存</div><div class="v small">{{ myInfo.cpuCores || 0 }} 核 / {{ mb(myInfo.memTotal) }} MB</div>
          <div class="k">Npcap</div>
          <div class="v"><span class="badge" :class="myInfo.npcapInstalled ? 'st-success' : 'st-failed'">{{ myInfo.npcapInstalled ? '已安装' : '未安装' }}</span></div>
        </div>
      </div>
    </div>

    <!-- 任务明细 -->
    <div class="card">
      <div class="toolbar">
        <select class="select" v-model="taskProbeId" @change="loadTasks">
          <option value="">全部探针任务</option>
          <option v-for="p in online" :key="p.id" :value="p.id">{{ p.name || p.id }}</option>
        </select>
        <select class="select" v-model="taskStatus" @change="loadTasks">
          <option value="">全部状态</option>
          <option value="pending">待下发</option>
          <option value="sent">已下发</option>
          <option value="running">执行中</option>
          <option value="success">成功</option>
          <option value="failed">失败</option>
        </select>
        <button class="btn sm" @click="loadTasks"><span class="spinner" v-if="taskLoading"></span> 刷新</button>
        <div class="spacer"></div>
        <span class="muted small">共 {{ taskTotal }} 条探针任务</span>
      </div>
      <div class="table-wrap" v-if="tasks.length">
        <table class="table">
          <thead>
            <tr><th>任务 ID</th><th>探针</th><th>类型</th><th>目标</th><th>状态</th><th>进度</th><th>发现</th><th>耗时</th><th>操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="t in tasks" :key="t.id">
              <td class="mono small">{{ t.id }}</td>
              <td class="small">{{ t.probeNode || '-' }}</td>
              <td class="small">{{ TASK_KIND[t.kind] || t.kind }}</td>
              <td class="mono small" :title="t.target">{{ t.target }}</td>
              <td><span class="badge" :class="taskClass(t.status)">{{ TASK_STATUS[t.status] || t.status }}</span></td>
              <td class="small muted" :title="t.progress">{{ t.progress || '-' }}</td>
              <td class="small">{{ t.findingNum || 0 }}</td>
              <td class="small mono">{{ t.durationMs ? (t.durationMs / 1000).toFixed(1) + 's' : '-' }}</td>
              <td>
                <div class="row-actions">
                  <button class="btn xs" v-if="t.status === 'success' || t.status === 'failed'" @click="openResult(t)">结果</button>
                  <button class="btn xs danger" v-if="t.status === 'sent' || t.status === 'running'" @click="cancelTask(t)">取消</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else text="暂无探针任务" />
    </div>

    <!-- 探针详情弹窗 -->
    <div class="modal-mask" v-if="detail" @click.self="detail = null">
      <div class="modal">
        <div class="modal-head">
          <span>探针详情 · {{ detail.name || detail.id }}</span>
          <button class="btn xs" @click="detail = null">关闭</button>
        </div>
        <div class="kv">
          <div class="k">探针 ID</div><div class="v mono">{{ detail.id }}</div>
          <div class="k">状态</div>
          <div class="v"><span class="badge" :class="detail.online ? 'st-success' : 'st-failed'">{{ detail.online ? '在线' : '离线' }}</span></div>
          <div class="k">操作系统</div><div class="v mono">{{ osText(detail) }}</div>
          <div class="k">内核版本</div><div class="v mono small">{{ nodeOf(detail).kernel || '-' }}</div>
          <div class="k">CPU</div><div class="v small">{{ nodeOf(detail).cpuModel || '-' }} ({{ nodeOf(detail).cpuCores || 0 }} 核)</div>
          <div class="k">内存 / 磁盘</div>
          <div class="v small">
            {{ mb(nodeOf(detail).memTotal) }} MB<span v-if="nodeOf(detail).memUsed"> (已用 {{ mb(nodeOf(detail).memUsed) }} MB)</span>
            / {{ gb(nodeOf(detail).diskTotal) }} GB<span v-if="nodeOf(detail).diskUsed"> (已用 {{ gb(nodeOf(detail).diskUsed) }} GB)</span>
          </div>
          <div class="k">网关 / DNS</div>
          <div class="v mono small">{{ nodeOf(detail).gateway || '-' }} / {{ (nodeOf(detail).dns || []).join(', ') || '-' }}</div>
          <div class="k">OS 版本</div><div class="v mono small">{{ nodeOf(detail).osVersion || '-' }}</div>
          <div class="k">Npcap</div>
          <div class="v small">{{ nodeOf(detail).npcapInstalled ? '已安装(抓包/ SYN 扫描可用)' : '未安装(抓包不可用)' }}</div>
          <div class="k">本地引擎</div>
          <div class="v small">
            <span v-for="e in (nodeOf(detail).engines || [])" :key="e.name" class="badge" style="margin-right:4px">
              {{ e.name }}{{ e.found ? ' ' + (e.version || 'ok') : ' (缺失)' }}
            </span>
            <span class="muted" v-if="!(nodeOf(detail).engines || []).length">无外部引擎, 内置引擎</span>
          </div>
          <div class="k">探针版本</div><div class="v mono small">{{ nodeOf(detail).version || '-' }} · 启动 {{ nodeOf(detail).startedAt || '-' }}</div>
          <div class="k">网卡</div>
          <div class="v small mono">{{ nicText(detail) }}</div>
          <div class="k">负载</div>
          <div class="v small">{{ loadText(detail) }}</div>
          <div class="k">最近心跳</div><div class="v mono small">{{ fmtDT(detail.lastSeenAt) }}</div>
          <div class="k">任务统计</div>
          <div class="v small">共 {{ detail.taskTotal || 0 }} 条 / 成功 {{ detail.taskSuccess || 0 }} / 失败 {{ detail.taskFailed || 0 }}</div>
        </div>
      </div>
    </div>

    <!-- 任务结果弹窗 -->
    <div class="modal-mask" v-if="result" @click.self="result = null">
      <div class="modal" style="max-width:820px">
        <div class="modal-head">
          <span>任务结果 · {{ result.id }}</span>
          <button class="btn xs" @click="result = null">关闭</button>
        </div>
        <div class="kv">
          <div class="k">状态</div>
          <div class="v"><span class="badge" :class="taskClass(result.status)">{{ TASK_STATUS[result.status] || result.status }}</span></div>
          <div class="k">摘要</div><div class="v small">{{ result.summary || '-' }}</div>
          <div class="k">错误</div><div class="v small" style="color:var(--red)">{{ result.error || '-' }}</div>
          <div class="k">发现数</div><div class="v small">{{ result.findingNum || 0 }}</div>
          <div class="k">耗时</div><div class="v small mono">{{ result.durationMs ? (result.durationMs / 1000).toFixed(1) + 's' : '-' }}</div>
        </div>
        <div class="card-title" style="margin-top:12px">结果明细</div>
        <pre class="code-block" style="max-height:420px; overflow:auto">{{ result.result || '(无明细)' }}</pre>
      </div>
    </div>

    <!-- 探针下载弹窗 -->
    <Modal v-if="showDownload" title="下载探针 (yugsight-agent)" width="760px" @close="showDownload = false">
      <div class="alert info">
        探针是被扫描机器上的独立程序: <b>零入站端口</b>(只向中心端发起一条出站 TCP)、
        无 Web 界面、不需管理员权限, 节点会在数秒内自动上线。
      </div>

      <div class="kv" style="margin-bottom:14px">
        <div class="k">中心端地址</div>
        <div class="v mono">{{ dlCenterAddr || '(未启用中心端监听, 启用后此处显示实际地址)' }}</div>
        <div class="k">节点密钥</div>
        <div class="v mono">{{ dlToken || '(未设置, 内网测试模式不校验密钥)' }}</div>
        <div class="k">协议版本</div>
        <div class="v mono">v{{ dlProtocol }} <span class="muted small">(需与中心端一致)</span></div>
        <div class="k">安装包目录</div>
        <div class="v mono small">{{ dlDir || '-' }}</div>
      </div>

      <div class="table-wrap" v-if="dlList.length">
        <table class="table">
          <thead><tr><th>平台</th><th>架构</th><th>文件</th><th>大小</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="p in dlList" :key="p.os + '/' + p.arch + '/' + p.file">
              <td class="small">{{ p.label }}</td>
              <td class="mono small">{{ p.os ? p.os + '/' + p.arch : '-' }}</td>
              <td class="mono small" :title="p.file">{{ p.file }}</td>
              <td class="small muted">{{ fmtSize(p.size) }}</td>
              <td>
                <button class="btn xs" v-if="p.os" @click="downloadAgent(p)">下载</button>
                <span class="muted small" v-else title="未识别的文件名: 用探针启动命令参数直接指定即可">仅列出</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="empty-hint" v-else>
        <b>尚未分发探针安装包</b>
        <p class="muted small">先把各平台 agent 放入上方的「安装包目录」, 再重新打开本弹窗。</p>
      </div>

      <div class="card-title" style="margin-top:14px">使用方式 <span class="sub">Windows 双击即装即用 · Linux/macOS 命令行启动</span></div>
      <div class="alert info" style="margin:0 0 10px">
        <b>Windows</b>: 下载后<b>双击运行</b> —— 自动安装到 <span class="mono">C:\YugsightAgent</span> 并注册开机自启,
        按弹窗提示填写中心端地址即可上线(连不上中心端时也会自动弹窗让你改地址)。
        卸载: 运行该目录下的<b>卸载探针.exe</b>。
      </div>
      <pre class="code-block" v-for="p in cmdList" :key="'cmd-' + p.os + p.arch">{{ cmdFor(p) }}</pre>
      <div class="toolbar" style="margin-top:10px" v-if="cmdList.length">
        <button class="btn sm" @click="copy(cmdsText())">复制启动命令</button>
        <button class="btn sm" @click="openGuide">部署指引</button>
        <button class="btn sm primary" @click="openInstall">可视化安装页</button>
      </div>

      <template #footer>
        <button class="btn sm" @click="showDownload = false">关闭</button>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import Empty from '../components/Empty.vue'
import Modal from '../components/Modal.vue'
import { v2 } from '../api/http'
import { fmtDT } from '../utils'

const TASK_KIND = { port: '端口扫描', ip: 'IP 存活', web: 'Web 漏洞', host: '主机扫描' }
const TASK_STATUS = { pending: '待下发', sent: '已下发', running: '执行中', success: '成功', failed: '失败' }
const OS_NAME = { windows: 'Windows', linux: 'Linux', darwin: 'macOS' }
// 调度节点类型(scheduler.Node.Kind): 中心本地节点 ID 为空串, 展示名单独兜底
const NODE_KIND = { local: '中心本地', probe: '探针' }

const status = ref(null)
const online = ref([])
const total = ref(0)
const loading = ref(false)
const onlyOnline = ref(false)
const detail = ref(null)
const result = ref(null)
const showAssign = ref(false)
const assigning = ref(false)
const assignErr = ref('')
const assignMsg = ref('')
const assign = reactive({ probeId: '', type: 'port', target: '', ports: '' })
const enabling = ref(false)
const enableMsg = ref('')

const tasks = ref([])
const taskTotal = ref(0)
const taskLoading = ref(false)
const taskProbeId = ref('')
const taskStatus = ref('')

// centerAgentVer 中心端当前对外提供的 agent 版本(来自 /probe/status)。
//
// 用来把"探针版本"与"中心端版本"做对比展示。中心端是版本权威来源: 探针版本不等于
// 它时, 探针下次注册会自动更新(中心端在注册应答里下发更新指令), 页面只需如实标注。
const centerAgentVer = computed(() => (status.value && status.value.agentVersion) || '')

// verState 判断单个探针的版本状态: 'diff'(需更新) / 'same'(一致) / 'unknown'(无法判断)。
// 拿不到任一版本号时返回 unknown —— 不猜, 避免把"信息缺失"显示成"版本不一致"。
function verState(p) {
  const center = centerAgentVer.value
  if (!center || !p || !p.version) return 'unknown'
  return p.version === center ? 'same' : 'diff'
}

let timer = null

const centerText = computed(() => {
  if (!status.value) return '-'
  if (!status.value.centerEnabled) return '未启用'
  return status.value.center ? '运行中' : '启动失败'
})
const roleText = computed(() => {
  if (!status.value) return '-'
  const c = status.value.centerEnabled, p = status.value.clientEnabled
  if (c && p) return '中心+探针'
  if (c) return '中心端'
  if (p) return '探针端'
  return '单机'
})
const displayList = computed(() => (onlyOnline.value ? online.value.filter(p => p.online) : online.value))
const onlineProbes = computed(() => online.value.filter(p => p.online))
const assignReady = computed(() => !!(status.value && status.value.center && onlineProbes.value.length))
const myInfo = computed(() => (status.value && status.value.clientInfo) || {})
const assignTargetLabel = computed(() => ({ ip: '网段 CIDR', port: '目标 IP', web: '目标 URL', host: '目标 IP' }[assign.type] || '目标'))
const assignTargetPh = computed(() => ({ ip: '如 192.168.1.0/24', port: '如 192.168.1.10', web: '如 192.168.1.10', host: '如 192.168.1.10' }[assign.type] || ''))

function capList(p) {
  return (p.capabilities || '').split(',').map(s => s.trim()).filter(Boolean)
}
function osText(p) {
  const n = nodeOf(p)
  const os = OS_NAME[n.os] || n.os || '-'
  return n.arch ? os + '/' + n.arch : os
}
// nodeOf 节点信息(注册时上报的原始快照, 字段见 probe.NodeInfo)
function nodeOf(p) {
  return (p && p.nodeInfo) || {}
}
function nicText(p) {
  const nics = nodeOf(p).netIfaces || []
  if (!nics.length) return (p && p.addr) || '-'
  return nics.map(n => n.name + ' ' + n.ip + (n.mac ? ' (' + n.mac + ')' : '')).join(' | ')
}
function loadText(p) {
  const ld = p && p.load
  if (!ld) return '未上报'
  return 'CPU ' + Number(ld.cpuPercent || 0).toFixed(1) + '% · 内存 ' + Number(ld.memPercent || 0).toFixed(1) +
    '% · 执行中任务 ' + (ld.tasksRunning || 0) + (ld.currentTask ? ' (' + ld.currentTask + ')' : '')
}
// mb 字节 -> MB(节点信息里内存/磁盘均为字节)
function mb(v) { return Math.round(Number(v || 0) / 1048576) }
function gb(v) { return Math.round(Number(v || 0) / 1073741824) }
function taskClass(s) {
  return { pending: 'st-pending', sent: 'st-running', running: 'st-running', success: 'st-success', failed: 'st-failed' }[s] || ''
}

// 一键开启探针中心端: 后端写 settings.json 的 probe 节(保留已有 listen/token),
// 重启后生效 —— 替代"手工编辑 JSON 再重启"的老路径(功能审计 P0-5)。
async function enableProbe() {
  enabling.value = true
  enableMsg.value = ''
  try {
    const d = await v2('/probe/enable', { method: 'POST' })
    enableMsg.value = (d && d.msg) || '已写入配置'
    if (d && d.restartRequired) {
      if (confirm('探针配置已写入 settings.json。\n\n重启服务后生效: 确定现在停止服务吗?(点"否"可稍后手动重启)')) {
        try {
          await fetch('/api/quit', { method: 'POST' })
        } catch (e) { /* 服务停止瞬间连接中断属正常 */ }
      }
    }
  } catch (e) {
    enableMsg.value = '开启失败: ' + (e.message || e)
  } finally {
    enabling.value = false
  }
}

async function load() {
  loading.value = true
  try {
    const [st, ls] = await Promise.all([v2('/probe/status'), v2('/probe/list')])
    status.value = st
    online.value = ls.list || []
    total.value = ls.total || 0
    // 节点密钥仅供"下载探针"弹窗生成部署命令; 取不到就退回占位符(不报错)
    probeToken.value = (st && st.centerCfg && st.centerCfg.token) || ''
    // 详情弹窗数据实时刷新
    if (detail.value) {
      const cur = online.value.find(x => x.id === detail.value.id)
      if (cur) detail.value = cur
    }
  } catch (e) {
    status.value = null
  } finally { loading.value = false }
  await loadTasks()
  await loadSchedNodes() // 节点负载随心跳变化, 与探针状态同频刷新
}

async function loadTasks() {
  taskLoading.value = true
  try {
    const p = new URLSearchParams({ page: '1', size: '50' })
    if (taskProbeId.value) p.set('probeId', taskProbeId.value)
    if (taskStatus.value) p.set('status', taskStatus.value)
    const d = await v2('/probe/tasks?' + p.toString())
    tasks.value = d.list || []
    taskTotal.value = d.total || 0
  } catch (e) { tasks.value = [] } finally { taskLoading.value = false }
}

function openDetail(p) { detail.value = p }
function openResult(t) { result.value = t }

function quickAssign(p) {
  assign.probeId = p.id
  showAssign.value = true
  assignErr.value = ''
  assignMsg.value = ''
}

async function doAssign() {
  assignErr.value = ''
  assignMsg.value = ''
  if (!assign.probeId) { assignErr.value = '请选择目标探针'; return }
  if (!assign.target) { assignErr.value = '目标不能为空'; return }
  assigning.value = true
  try {
    const d = await v2('/probe/assign', {
      method: 'POST',
      body: { probeId: assign.probeId, type: assign.type, target: assign.target, ports: assign.ports },
    })
    assignMsg.value = '已下发任务 ' + d.taskId + ' 到 ' + d.probeId
    assign.target = ''
    await loadTasks()
  } catch (e) { assignErr.value = e.message } finally { assigning.value = false }
}

async function cancelTask(t) {
  if (!confirm('确认取消任务 ' + t.id + ' ?')) return
  try {
    await v2('/probe/cancel', { method: 'POST', body: { probeId: t.probeNode, taskId: t.id } })
    await loadTasks()
  } catch (e) { alert(e.message) }
}

async function del(p) {
  if (!confirm('确认移除探针登记 ' + p.id + ' ?(不影响探针进程)')) return
  try { await v2('/probe/' + encodeURIComponent(p.id), { method: 'DELETE' }); await load() }
  catch (e) { alert(e.message) }
}

// ===== 探针下载(agent 分发) =====

const showDownload = ref(false)
const dlList = ref([])
const dlDir = ref('')
const dlCenterAddr = ref('')
const dlToken = ref('')
const dlProtocol = ref(1)
// cmdList 需要命令行启动的平台(Windows 是双击自安装, 不需要命令)
const cmdList = computed(() => dlList.value.filter(x => x.os && x.os !== 'windows'))

async function openDownload() {
  showDownload.value = true
  try {
    const d = await v2('/probe/agent/list')
    dlList.value = d.list || []
    dlDir.value = d.dir || ''
    dlCenterAddr.value = d.centerAddr || ''
    dlProtocol.value = d.protocol || 1
  } catch (e) {
    dlList.value = []
  }
  // 密钥只在中心端启用时才有意义(未启用时 probeCfg 为空, 不误报"无密钥")
  dlToken.value = (status.value && status.value.centerEnabled) ? (probeToken.value || '') : ''
}

// agent 启动命令(Linux/macOS): 中心端地址与密钥取自后端(地址已按 listen 推导为
// 可连的局域网 IP), 缺失时保留占位符, 让用户明确知道要替换什么, 而不是给出一条
// 跑不通的命令。Windows 走双击自安装, 不需要命令。
function cmdFor(p) {
  const addr = dlCenterAddr.value || '<中心端IP>:8600'
  const token = dlToken.value || '<节点密钥>'
  return './' + (p.file || 'yugsight-agent').replace(/\.exe$/, '') + ' -center ' + addr + ' -token ' + token
}

function cmdsText() {
  return cmdList.value.map(cmdFor).join('\n')
}

// 下载走浏览器原生下载: 服务端已设置 Content-Disposition, 且走会话 cookie 鉴权
// (不在 URL 带 token —— 密钥会进浏览器历史/代理日志)。
function downloadAgent(p) {
  window.open('/api/v2/probe/agent/download?os=' + p.os + '&arch=' + p.arch, '_blank')
}

function openGuide() {
  window.open('/api/v2/probe/agent/guide', '_blank')
}

// 可视化安装页: 服务端渲染的 HTML(含中心端地址与节点密钥的现成命令)。
// 走 requireAuth + 会话 cookie, 因此不能把链接随便外发给未登录的人 —— 页面里
// 带密钥。文案已在上方说明用途, 这里不再二次弹窗打断。
function openInstall() {
  window.open('/api/v2/probe/agent/install', '_blank')
}

async function copy(s) {
  try {
    await navigator.clipboard.writeText(s)
    alert('已复制到剪贴板')
  } catch (e) { alert('复制失败, 请手动选择文本复制') }
}

function fmtSize(v) {
  const n = Number(v || 0)
  if (!n) return '-'
  if (n < 1024) return n + ' B'
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'
  return (n / 1048576).toFixed(2) + ' MB'
}

// probeToken 中心端节点密钥(从 /probe/status 的 centerCfg 取, 见 load()).
const probeToken = ref('')

// ===== 调度节点负载(只读视图, 来自 /api/v2/scheduler/nodes) =====
const schedNodes = ref([])
const schedCapacity = ref(0)
// 调度总开关取自 /scheduler/status。必须如实标注"未启用": 未启用时节点表仍会
// 返回一个"可接纳"的中心本地节点, 只看节点会让人误以为排队派发已经在工作。
const schedEnabled = ref(false)
const schedOn = computed(() => schedEnabled.value)

function capListOf(s) {
  return (s || '').split(',').map(x => x.trim()).filter(Boolean)
}
// 负载未上报时显示 '-' 而不是 0%: 与"上报了 0%"是两回事, 混同会掩盖采集故障
function pct(v) {
  return v === null || v === undefined ? '-' : Number(v).toFixed(1) + '%'
}

async function loadSchedNodes() {
  try {
    const [nd, st] = await Promise.all([v2('/scheduler/nodes'), v2('/scheduler/status')])
    schedNodes.value = nd.nodes || []
    schedCapacity.value = nd.capacity || 0
    schedEnabled.value = !!(st && st.enabled)
  } catch (e) {
    schedNodes.value = []
    schedCapacity.value = 0
  }
}

onMounted(() => {
  load() // 内部已带 loadSchedNodes, 与探针状态同频刷新
  timer = setInterval(load, 5000) // 探针状态面板自动刷新
})
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
/* 同 Console.vue: 卡片标题栏的 .spacer 需要 flex:1 才能把右侧状态推到边 */
.card-title .spacer { flex: 1; }
</style>

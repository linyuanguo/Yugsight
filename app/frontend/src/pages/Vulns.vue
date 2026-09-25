<template>
  <div>
    <PageHeader title="漏洞管理" desc="全部漏洞记录"></PageHeader>

    <div class="card">
      <div class="toolbar">
        <select class="select" v-model="f.severity">
          <option value="">全部等级</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
          <option value="info">信息</option>
        </select>
        <!-- 两态口径: 开放(含历史 new/duplicate) / 已修复; 重复命中见"最后命中"列 -->
        <select class="select" v-model="f.status">
          <option value="">全部状态</option>
          <option value="open">开放</option>
          <option value="fixed">已修复</option>
        </select>
        <input class="input mono" v-model.trim="f.cve" placeholder="CVE 编号" @keyup.enter="reload">
        <input class="input mono" v-model.trim="f.ip" placeholder="资产 IP" @keyup.enter="reload">
        <input class="input" v-model.trim="f.title" placeholder="标题关键字" @keyup.enter="reload">
        <button class="btn sm" @click="reload">查询</button>
        <!-- 旧按钮名叫"清空", 与下面的"清空全部漏洞"混在一起被当成"清库没反应" -->
        <button class="btn sm" @click="resetF" title="清空筛选条件并回到第 1 页">重置筛选</button>
        <div class="spacer"></div>
        <span class="muted small">共 {{ total }} 条</span>
        <!-- 阶段 5 联动: 选中漏洞 -> 渗透工作台做验证渗透(仅管理员)。
             operator/auditor 不给入口: 渗透是攻击性能力, 权限边界比本页写操作更严 -->
        <span class="chip warn" v-if="selCount">已选 {{ selCount }} 条</span>
        <button class="btn sm primary" v-if="admin && selCount" @click="sendToPenta"
                title="把选中的漏洞作为已知漏洞导入渗透工作台执行验证(全程审计)">发送到渗透工作台</button>
        <button class="btn sm danger" v-if="canWrite" :disabled="total === 0" title="删除本库全部漏洞记录(资产/任务/白名单不受影响, 操作记审计)"
                @click="openClear">清空全部漏洞</button>
      </div>

      <!-- 发送失败留在当前页, 提示必须可见(跳转成功则整页切走, 用不到) -->
      <div class="err-line" v-if="sendMsg" style="margin-bottom:8px; color:var(--danger,#e5484d)">{{ sendMsg }}</div>

      <div class="table-wrap" v-if="list.length">
        <table class="table">
          <thead>
            <tr>
              <th style="width:36px"><input type="checkbox" :checked="allChecked" @change="toggleAll"></th>
              <th>等级</th><th>标题</th><th>CVE</th><th>资产</th><th>端口</th>
              <th>置信度</th><th>状态</th><th>来源</th><th>发现时间</th><th>最后命中</th><th style="width:96px">渗透验证</th>
            </tr>
          </thead>
          <tbody>
            <tr class="clickable" v-for="v in list" :key="v.id" @click="$router.push('/vulns/' + v.id)">
              <!-- @click.stop: 复选框不能触发整行的详情跳转 -->
              <td @click.stop><input type="checkbox" v-model="sel[v.id]"></td>
              <td><SevTag :sev="v.severity" /></td>
              <td>
                <b style="font-size:12.5px">{{ v.title }}</b>
                <span class="badge" v-if="v.falsePositive" style="color:var(--muted); border-style:dashed; margin-left:6px" :title="v.fpNote || '人工标记误报'">误报</span>
              </td>
              <td class="mono small">{{ v.cve || '-' }}</td>
              <td class="mono small">{{ v.assetIp }}</td>
              <td class="mono small">{{ v.port || '-' }}</td>
              <td class="mono small">{{ v.confidence != null ? v.confidence : '-' }}</td>
              <td>
                <StatusTag :status="vulnStatus(v.status)" />
                <span class="muted small" v-if="v.lastSeenAt && v.foundAt && v.lastSeenAt !== v.foundAt"
                      :title="'重复命中, 最近一次: ' + fmtDT(v.lastSeenAt)">· 重</span>
              </td>
              <td class="small muted">{{ v.source || '-' }}</td>
              <td class="muted small mono">{{ fmtDT(v.foundAt) }}</td>
              <td class="muted small mono" :title="v.lastSeenAt && v.lastSeenAt !== v.foundAt ? '重复命中' : ''">{{ fmtDT(v.lastSeenAt) }}</td>
              <td>
                <span class="badge" v-if="v.pentaResult" :style="expStyle(v.pentaResult)"
                      :title="'渗透任务 ' + (v.pentaTaskId || '-') + ' 已回传'">{{ expName(v.pentaResult) }}</span>
                <span class="muted small" v-else>未验证</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else :text="hasFilter ? '无匹配漏洞' : '暂无漏洞记录(扫描结果经回传通道写入本库)'" />

      <div class="pager" v-if="total > page * size">
        <span>第 {{ page }} 页</span>
        <div class="spacer"></div>
        <button class="btn xs" :disabled="page <= 1" @click="page--; load()">上一页</button>
        <button class="btn xs" :disabled="page * size >= total" @click="page++; load()">下一页</button>
      </div>
    </div>

    <!-- 清空全部漏洞: 不可逆, 要求输入确认词(与"删一条"的 confirm 区分开) -->
    <Modal v-if="showClear" title="清空全部漏洞" width="460px" @close="closeClear">
      <div class="alert warn" style="margin-bottom:12px">
        将删除本库全部 <b>{{ total }}</b> 条漏洞记录, 不可恢复。
        资产台账、扫描任务、白名单与误报规则都不受影响; 本次操作会写入审计日志。
      </div>
      <div class="field">
        <label class="label">请输入"清空"以确认</label>
        <input class="input" v-model.trim="clearWord" placeholder="清空" @keyup.enter="doClear">
      </div>
      <div class="login-err" style="text-align:left">{{ clearErr }}</div>
      <template #footer>
        <button class="btn" @click="closeClear">取消</button>
        <button class="btn danger" :disabled="clearWord !== '清空' || clearing" @click="doClear">确认清空</button>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import SevTag from '../components/SevTag.vue'
import StatusTag from '../components/StatusTag.vue'
import Modal from '../components/Modal.vue'
import Empty from '../components/Empty.vue'
import { v2, api } from '../api/http'
import { fmtDT, vulnStatus } from '../utils'
import { isAdmin } from '../auth'

const router = useRouter()
// admin 必须 computed 跟随 auth.js 的响应式角色: 整页刷新时本组件可能在
// whoami 返回前挂载, 快照式 ref(isAdmin()) 会永远拿到 false(阶段 4 已踩过)
const admin = computed(() => isAdmin())
// 多选 -> 「发送到渗透工作台」(阶段 5 联动入口)
const sel = reactive({})
const sendMsg = ref('')
const selCount = computed(() => Object.values(sel).filter(Boolean).length)
const allChecked = computed(() => list.value.length > 0 && list.value.every((v) => sel[v.id]))
function toggleAll(e) {
  const on = e.target.checked
  for (const v of list.value) sel[v.id] = on
}
// 渗透验证结论文案与配色(与渗透工作台同口径, 便于用户跨页对齐认知)
function expName(s) {
  return { exploitable: '可利用', partial: '部分利用', not_exploitable: '不可利用' }[s] || s || '-'
}
function expStyle(s) {
  if (s === 'exploitable') return { color: '#fff', background: 'var(--danger,#e5484d)', borderColor: 'transparent' }
  if (s === 'partial') return { color: '#fff', background: 'var(--warning,#f0b429)', borderColor: 'transparent' }
  return { color: 'var(--muted,#8b93a7)' }
}
async function sendToPenta() {
  const ids = Object.keys(sel).filter((k) => sel[k])
  if (!ids.length) return
  try {
    const d = await v2('/penta/tasks/import', { method: 'POST', body: { vulnIds: ids } })
    sendMsg.value = ''
    for (const k of Object.keys(sel)) sel[k] = false
    // 跳转后再提示: 目标页面会自动带上这批任务, 提示只是补一句"已导入"
    router.push('/penta')
    if (d && (d.skipped || d.missing)) {
      sendMsg.value = `已导入 ${d.created} 条，跳过旧任务 ${d.skipped} 条，不存在 ${d.missing} 条`
    }
  } catch (e) {
    sendMsg.value = '发送到渗透工作台失败: ' + e.message
  }
}

const list = ref([])
const total = ref(0)
const page = ref(1)
const size = 20
const f = reactive({ severity: '', status: '', cve: '', ip: '', title: '' })
// canWrite: admin/operator 才显示"清空全部漏洞"(auditor 是只读角色);
// 真正边界在后端 adminOrOperator 中间件, 这里只是不给只读角色一个必然 403 的按钮
const canWrite = ref(false)

const hasFilter = computed(() => !!(f.severity || f.status || f.cve || f.ip || f.title))

const showClear = ref(false)
const clearWord = ref('')
const clearErr = ref('')
const clearing = ref(false)

async function load() {
  const p = new URLSearchParams({ page: String(page.value), size: String(size) })
  for (const k of ['severity', 'status', 'cve', 'ip', 'title']) {
    if (f[k]) p.set(k, f[k])
  }
  const d = await v2('/vulns?' + p.toString())
  list.value = d.list || []
  total.value = d.total || 0
}

function reload() { page.value = 1; load().catch(e => alert(e.message)) }
function resetF() {
  Object.assign(f, { severity: '', status: '', cve: '', ip: '', title: '' })
  reload()
}

function openClear() {
  clearWord.value = ''
  clearErr.value = ''
  showClear.value = true
}
function closeClear() { showClear.value = false }

async function doClear() {
  if (clearWord.value !== '清空' || clearing.value) return
  clearing.value = true
  clearErr.value = ''
  try {
    const d = await v2('/vulns', { method: 'DELETE' })
    showClear.value = false
    page.value = 1
    await load()
    alert('已清空 ' + ((d && d.deleted != null) ? d.deleted : 0) + ' 条漏洞记录')
  } catch (e) {
    clearErr.value = e.message
  } finally { clearing.value = false }
}

async function loadRole() {
  try {
    const me = await api('/api/whoami')
    canWrite.value = me.role === 'admin' || me.role === 'operator'
  } catch (e) {
    canWrite.value = false // 取不到角色就不显示写入口
  }
}

onMounted(loadRole)
load().catch(e => alert(e.message))
</script>

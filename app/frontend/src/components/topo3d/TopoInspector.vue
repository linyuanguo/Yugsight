<template>
  <!-- 右侧属性面板(2026-09-29 新拓扑架构): 选中节点/链路后由页面从右侧平滑滑出。
       三区分块: 基础信息(名称/类型/IP/网段/绑定资产) + 状态信息(安全状态/在线/存活时长/风险/最近告警)
       + 操作区(启用监控/删除)。右上角手动收起; 点画布空白由页面收起(emit close 同口径)。
       双模式边界: 浏览=只读(输入/下拉/勾选全部禁用), 告警列表点击定位仍可用。 -->
  <div class="ti" :class="{ ro: mode === 'browse' }">
    <div class="ti-bar">
      <span class="ti-title">{{ multiItems && multiItems.length >= 2 ? t('topo.multiList', { n: multiItems.length }) : (selKind === 'link' ? t('topo.linkProps') : (selKind === 'box' ? t('topo.boxProps') : (selObj ? t('topo.nodeProps') : t('topo.noObj')))) }}</span>
      <button type="button" class="ti-close" :title="t('topo.collapse')" @click="emit('close')">›</button>
    </div>

    <div class="ti-scroll">
      <!-- ===== 多选清单(2026-09-30 用户要求: 框选多个时显示全部设备/框清单, 而非单个设备属性) ===== -->
      <template v-if="multiItems && multiItems.length >= 2">
        <div class="ti-sec">
          <div class="ti-h">{{ t('topo.selectedN', { n: multiItems.length }) }}</div>
          <p class="ti-note">{{ t('topo.multiNote') }}</p>
          <div v-for="it in multiItems" :key="it.kind + it.id" class="ti-mitem">
            <i :class="it.kind === 'box' ? 'mi-box' : 'mi-dot'"
               :style="it.kind === 'box' ? {} : { background: statusColor(it.status) }"></i>
            <span class="mi-name">{{ it.name }}</span>
            <em>{{ it.sub }}</em>
          </div>
        </div>
      </template>

      <!-- ===== 节点属性 ===== -->
      <template v-else-if="selObj && selKind === 'node'">
        <div class="ti-sec">
          <div class="ti-h">{{ t('topo.basic') }}</div>
          <label><span>{{ t('topo.name') }}</span><input :value="selObj.name" @input="set('name', $event.target.value)" /></label>
          <label><span>{{ t('topo.devType') }}</span>
            <select :value="selObj.type" @change="set('type', $event.target.value)">
              <option v-for="ot in TYPE_OPTIONS" :key="ot.v" :value="ot.v">{{ t(ot.t) }}</option>
            </select>
          </label>
          <label><span>{{ t('topo.ipAddr') }}<i v-if="selObj.isMonitor">{{ t('bpro.monitorSync') }}</i></span>
            <input :disabled="selObj.isMonitor" :value="selObj.ip" @input="set('ip', $event.target.value)" /></label>
          <label><span>{{ t('topo.subnet') }}</span><i class="ti-ro-val">{{ subnetOf(selObj.ip) }}</i></label>
          <label><span>{{ t('topo.bindNode') }}</span>
            <select :value="selObj.boundAssetId || ''" @change="onBindChange($event.target.value)">
              <option value="">{{ t('topo.unbound') }}</option>
              <!-- 2026-09-30 用户要求: 候选=协议配置监控目标(纳管设备), 非扫描资产 -->
              <option v-for="d in bindDevices" :key="d.deviceId" :value="d.deviceId">{{ d.name }}（{{ d.ip || '—' }}）</option>
            </select>
          </label>
        </div>

        <div class="ti-sec">
          <div class="ti-h">{{ t('topo.statusInfo') }}</div>
          <div class="ti-kv"><span>{{ t('topo.safeStatus') }}</span><i class="ti-st" :class="'st-' + safeStatus(selObj)">{{ t(safeCn[safeStatus(selObj)]) }}</i></div>
          <div class="ti-kv"><span>{{ t('topo.onlineState') }}</span><i :class="{ bad: selObj.status === 'down' }">{{ selObj.status === 'down' ? t('rp.offline') : t('rp.online') }}</i></div>
          <div class="ti-kv"><span>{{ t('topo.uptime') }}</span><i>{{ uptimeText(selObj) }}</i></div>
          <div class="ti-kv"><span>{{ t('topo.riskLevel') }}</span><i :class="{ bad: riskLevel(selObj) >= 2 }">{{ riskText(selObj) }}</i></div>
          <div class="ti-kv"><span>{{ t('topo.lastAlert') }}</span><i class="ti-aval">{{ lastAlert ? lastAlert.content : t('topo.none') }}</i></div>
        </div>

        <div class="ti-sec">
          <div class="ti-h">{{ t('topo.ops') }}</div>
          <label class="ti-toggle"><span>{{ t('topo.enableMon') }}</span>
            <input type="checkbox" :checked="selObj.isMonitor" @change="set('isMonitor', $event.target.checked)" />
          </label>
          <button v-if="mode === 'edit'" type="button" class="ti-danger" @click="emit('delete')">{{ t('topo.delNode') }}</button>
        </div>

        <!-- 告警设置(仅编辑模式): 告警推送总开关 + 今日推送统计 + 跳完整配置。
             每节点独立阈值在「节点监控 → 通用配置 → 每节点告警阈值」(2026-09-29 阶段 A) -->
        <div v-if="mode === 'edit'" class="ti-sec">
          <div class="ti-h">{{ t('topo.alertCfg') }}</div>
          <PushStatusPanel compact :editable="mode === 'edit'" />
        </div>
      </template>

      <!-- ===== 框属性(2026-09-30 用户要求: 点击框=点击设备, 属性面板改名等) ===== -->
      <template v-else-if="selObj && selKind === 'box'">
        <div class="ti-sec">
          <div class="ti-h">{{ t('topo.basic') }}</div>
          <label><span>{{ t('topo.name') }}</span><input :value="selObj.name" @input="set('name', $event.target.value)" /></label>
          <label><span>{{ t('topo.w') }}</span><input type="number" :value="selObj.w" @change="setBoxSize('w', $event.target.value)" /></label>
          <label><span>{{ t('topo.h') }}</span><input type="number" :value="selObj.h" @change="setBoxSize('h', $event.target.value)" /></label>
          <label><span>{{ t('topo.posX') }}</span><input type="number" :value="selObj.x" @change="set('x', Math.round(Number($event.target.value) || 0))" /></label>
          <label><span>{{ t('topo.posY') }}</span><input type="number" :value="selObj.y" @change="set('y', Math.round(Number($event.target.value) || 0))" /></label>
        </div>
        <!-- 2026-09-30 用户要求: 标签文字(颜色/大小/加粗/字体, 画布上可拖拽放置) -->
        <div class="ti-sec">
          <div class="ti-h">{{ t('topo.labelText') }}</div>
          <label><span>{{ t('topo.fontColor') }}</span><input type="color" :value="selObj.fontColor || '#9fb0c8'" @input="set('fontColor', $event.target.value)" /></label>
          <label><span>{{ t('topo.fontSize') }}</span><input type="number" min="8" max="48" :value="selObj.fontSize || 15" @change="set('fontSize', Math.max(8, Math.min(48, Math.round(Number($event.target.value) || 15))))" /></label>
          <label><span>{{ t('topo.font') }}</span>
            <select :value="selObj.fontFamily || ''" @change="set('fontFamily', $event.target.value)">
              <option value="">{{ t('topo.dft') }}</option>
              <option value="Microsoft YaHei">微软雅黑</option>
              <option value="SimSun">宋体</option>
              <option value="KaiTi">楷体</option>
              <option value="DengXian">等线</option>
              <option value="Consolas, monospace">等宽</option>
            </select>
          </label>
          <label class="ti-toggle"><span>{{ t('topo.bold') }}</span>
            <input type="checkbox" :checked="!!selObj.fontBold" @change="set('fontBold', $event.target.checked)" />
          </label>
          <p class="ti-note">{{ t('topo.labelDragNote') }}</p>
        </div>
        <!-- 2026-09-30 用户要求: 框线(线型/线宽/颜色) -->
        <div class="ti-sec">
          <div class="ti-h">{{ t('topo.boxLine') }}</div>
          <label><span>{{ t('topo.lineStyle') }}</span>
            <select :value="selObj.strokeStyle || 'solid'" @change="set('strokeStyle', $event.target.value)">
              <option value="solid">{{ t('topo.solid') }}</option>
              <option value="dash">{{ t('topo.longDash') }}</option>
              <option value="short">{{ t('topo.shortDash') }}</option>
            </select>
          </label>
          <label><span>{{ t('topo.lineWidth') }}</span><input type="number" min="0.5" max="8" step="0.5" :value="selObj.strokeWidth != null ? selObj.strokeWidth : 1.2" @change="set('strokeWidth', Math.max(0.5, Math.min(8, Number($event.target.value) || 1.2)))" /></label>
          <label><span>{{ t('topo.lineColor') }}</span><input type="color" :value="selObj.strokeColor || '#3884ff'" @input="set('strokeColor', $event.target.value)" /></label>
        </div>
        <!-- 2026-09-30 用户要求: 框背景(有无颜色 + 颜色 + 透明度) -->
        <div class="ti-sec">
          <div class="ti-h">{{ t('topo.boxBg') }}</div>
          <label class="ti-toggle"><span>{{ t('topo.noBg') }}</span>
            <input type="checkbox" :checked="!!selObj.fillNone" @change="set('fillNone', $event.target.checked)" />
          </label>
          <label v-show="!selObj.fillNone"><span>{{ t('topo.bgColor') }}</span><input type="color" :value="selObj.fillColor || '#3884ff'" @input="set('fillColor', $event.target.value)" /></label>
          <label v-show="!selObj.fillNone"><span>{{ t('topo.bgOpacity') }}</span>
            <input type="range" min="0" max="1" step="0.05" :value="selObj.fillOpacity != null ? selObj.fillOpacity : 0.05" @input="set('fillOpacity', Number($event.target.value))" />
          </label>
        </div>
        <div class="ti-sec">
          <div class="ti-h">{{ t('topo.ops') }}</div>
          <p class="ti-note">{{ t('topo.boxOpsNote') }}</p>
          <button v-if="mode === 'edit'" type="button" class="ti-danger" @click="emit('delete')">{{ t('topo.delBox') }}</button>
        </div>
      </template>

      <!-- ===== 链路属性 ===== -->
      <template v-else-if="selObj && selKind === 'link'">
        <div class="ti-sec">
          <div class="ti-h">{{ t('topo.linkProps') }}</div>
          <label><span>{{ t('topo.fromNode') }}</span>
            <select :value="selObj.fromDeviceId" @change="onFromEndpoint($event.target.value)">
              <option v-for="n in nodes" :key="n.deviceId" :value="n.deviceId">{{ n.name }}</option>
            </select>
          </label>
          <label><span>{{ t('topo.toNode') }}</span>
            <select :value="selObj.toDeviceId" @change="onToEndpoint($event.target.value)">
              <option v-for="n in nodes" :key="n.deviceId" :value="n.deviceId">{{ n.name }}</option>
            </select>
          </label>
          <!-- 端口绑定(2026-10-02 排期需求 2: 链路的物理含义是"本端哪口连对端哪口",
               不是设备间抽象边; 绑定后线上显示该端口真实速率, 端点变化自动清空失效绑定) -->
          <label><span>{{ t('topo.fromPort') }}</span>
            <select :value="selObj.fromPort || ''" @change="set('fromPort', $event.target.value)">
              <option value="">{{ t('topo.unbound') }}</option>
              <option v-for="p in fromPorts" :key="p.port" :value="p.port">{{ portOptLabel(p) }}</option>
            </select>
          </label>
          <!-- 端口别名(2026-10-02 v255 用户: "别名要在该链路属性里改, 只改 x/x 左边的接口"):
               链路属性里改起始端口(线上标签 ⇄ 左边的接口)的显示名; 留空=回显原口名;
               只换名字部分, 后面的 ↑↓ 实时速率照常 15s 刷新; 随视图文档持久化。
               画布双击标签/右键菜单是同一数据的等价入口 -->
          <label v-if="selObj.fromPort"><span>{{ t('topo.fromAlias') }}</span>
            <input :value="selObj.fromAlias || ''" :placeholder="t('topo.fromAliasPh')" @change="set('fromAlias', $event.target.value.trim())" />
          </label>
          <label><span>{{ t('topo.toPort') }}</span>
            <select :value="selObj.toPort || ''" @change="set('toPort', $event.target.value)">
              <option value="">{{ t('topo.unbound') }}</option>
              <option v-for="p in toPorts" :key="p.port" :value="p.port">{{ portOptLabel(p) }}</option>
            </select>
          </label>
          <!-- 终止端口别名(2026-10-02 v258 用户: "终止端口也有别名"): 与起始端口别名
               同机制 —— 只换线上该端标签的名字部分, 留空=回显原口名, 随视图文档持久化;
               画布双击该端标签/右键菜单是同一数据(l.toAlias)的等价入口 -->
          <label v-if="selObj.toPort"><span>{{ t('topo.toAlias') }}</span>
            <input :value="selObj.toAlias || ''" :placeholder="t('topo.toAliasPh')" @change="set('toAlias', $event.target.value.trim())" />
          </label>
          <div v-if="portNote" class="ti-note">{{ portNote }}</div>
          <div v-if="boundRateText" class="ti-kv"><span>{{ t('topo.boundRate') }}</span><i>{{ boundRateText }}</i></div>
          <label><span>{{ t('topo.linkType') }}</span>
            <select :value="selObj.kind || 'primary'" @change="set('kind', $event.target.value)">
              <option value="primary">{{ t('topo.primaryLink') }}</option>
              <option value="backup">{{ t('topo.backupLink') }}</option>
            </select>
          </label>
          <label><span>{{ t('topo.bwThreshold') }}</span><input type="number" :value="selObj.bandwidth" @input="set('bandwidth', Number($event.target.value))" /></label>
          <label><span>{{ t('topo.colStatus') }}</span>
            <select :value="selObj.status" @change="set('status', $event.target.value)">
              <option value="normal">{{ t('topo.stNormal') }}</option><option value="warn">{{ t('topo.stWarnCongest') }}</option><option value="down">{{ t('topo.stDownErr') }}</option>
            </select>
          </label>
          <!-- 连通性(2026-09-29 用户口径: 画了线不算通, 中心端实测两端 IP 才算) -->
          <div class="ti-kv"><span>{{ t('topo.connectivity') }}</span><i :class="{ bad: selObj.status === 'down' && selObj.tested, pend: !selObj._real && !selObj.tested }">{{ linkTestText(selObj) }}</i></div>
          <button v-if="!selObj._real" type="button" class="ti-check" :disabled="selObj._checking" @click="emit('check', selObj)">
            {{ selObj._checking ? t('topo.testing') : (selObj.tested ? t('topo.retest') : t('topo.testConn')) }}
          </button>
          <div v-if="selObj._check" class="ti-kv ti-check-detail">
            <span>{{ t('topo.testResult') }}</span>
            <i>{{ (selObj._check.results || []).map(r => r.ip + (r.up ? ' ✓ ' + r.rttMs + 'ms' : ' ✗')).join('  ') }}</i>
          </div>
          <!-- 通断重试间隔(2026-10-02 用户要求: 红线30s重试/绿线5min复验可人工自定义,
               存链路对象随视图文档持久化; 两端在线时自动测试按此间隔发起) -->
          <label><span>{{ t('topo.retryRed') }}</span>
            <input type="number" min="5" max="3600" :value="selObj.retrySec || 30"
                   @change="setRetry('retrySec', $event.target.value)" />
          </label>
          <label><span>{{ t('topo.recheckGreen') }}</span>
            <input type="number" min="10" max="86400" :value="selObj.recheckSec || 300"
                   @change="setRetry('recheckSec', $event.target.value)" />
          </label>
          <p class="ti-note">{{ t('topo.retryNote') }}</p>
          <button v-if="mode === 'edit'" type="button" class="ti-danger" @click="emit('delete')">{{ t('topo.delLink') }}</button>
        </div>
      </template>

      <div v-else class="ti-none">{{ t('topo.clickToShow') }}</div>

      <!-- 告警列表(底部, 点击定位到对应节点) -->
      <div class="ti-sec grow">
        <div class="ti-h">{{ t('topo.alertList') }} <b>{{ alerts.length }}</b></div>
        <div class="ti-alerts">
          <div v-for="a in alerts" :key="a.k + a.id" class="ti-alert" @click="emit('locate', a.deviceId)">
            <i :style="{ background: a.color }"></i>
            <span class="ti-a-t">{{ a.text }}</span>
            <span class="ti-a-l">{{ a.lv }}</span>
          </div>
          <div v-if="!alerts.length" class="ti-none">{{ t('topo.noAlerts') }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { TYPE_OPTIONS, TYPES, safeStatus, SAFE_CN } from './topoModel.js'
import { t } from '../../i18n'
import { fetchNodePorts, rateShort } from './topoPorts.js'   // 端口清单共享取数(与端口详情抽屉同源)
import PushStatusPanel from './PushStatusPanel.vue'   // 告警设置(仅编辑模式渲染, 见模板)

const props = defineProps({
  selObj: { type: Object, default: null },
  selKind: { type: String, default: '' },
  nodes: { type: Array, default: () => [] },
  links: { type: Array, default: () => [] },
  devices: { type: Array, default: () => [] },   // dashData 设备台账(绑定候选只取其中 isMonitor 纳管设备)
  lastAlert: { type: Object, default: null },     // 选中节点最近一条告警(页面按 deviceId 取)
  mode: { type: String, default: 'browse' },
  // 框选多选清单(≥2 项时面板显示清单视图): [{kind:'node'|'box', id, name, sub, status}]
  multiItems: { type: Array, default: null },
})

// 绑定节点候选(2026-09-30 用户要求): 只列协议配置里的监控目标 ——
// 探针(P_)/SNMP 网络监控目标(M_)/采集任务(C_, 主机 ssh·winrm·snmp 等), 扫描资产(A_)不列
const bindDevices = computed(() => (props.devices || []).filter(d => d.isMonitor))
const emit = defineEmits(['update', 'delete', 'locate', 'close', 'check'])

const safeCn = SAFE_CN
function set(k, v) { emit('update', { k, v }) }
// 框尺寸: 钳制与场景拖拽/拉角同口径(120~1100 × 60~640)
function setBoxSize(k, raw) {
  const v = Math.round(Number(raw) || 0)
  const lim = k === 'w' ? [120, 1100] : [60, 640]
  emit('update', { k, v: Math.max(lim[0], Math.min(lim[1], v)) })
}
// 多选清单里节点状态点颜色(与画布安全色同口径: 绿正常/黄告警/红异常/灰离线)
function statusColor(st) {
  return st === 'normal' ? '#34d399' : st === 'warn' ? '#fbbf24' : st === 'error' ? '#f87171' : '#94a3b8'
}
// 连通性文案(2026-09-29 用户口径): 后端真实链路=API 数据; 手动链路必须测试后才算通
function linkTestText(l) {
  if (l._real) return t('topo.realLink')
  if (!l.tested) return t('topo.untested')
  const t = l.checkedAt ? ' ' + new Date(l.checkedAt).toLocaleTimeString() : ''
  return (l.status === 'down' ? t('topo.notConnected') : t('topo.connected')) + t
}
// 所属网段: 取前 3 段按 /24 展示(拓扑粒度不到子网, 用 /24 作展示口径; 无 IP 显 —)
function subnetOf(ip) {
  const p = String(ip || '').split('.')
  if (p.length < 3) return ip || '—'
  return p.slice(0, 3).join('.') + '.0/24'
}
// 存活时长: 客户端会话内观测口径 —— 节点从"最近一次转为在线"起的时长; 离线或无记录显 —
// (后端无每节点首次在线时间字段, 用会话内追踪, 不伪造跨重启的绝对存活时长)
function uptimeText(n) {
  if (n.status === 'down' || !n._onlineSince) return '—'
  const sec = Math.max(0, Math.floor((Date.now() - n._onlineSince) / 1000))
  if (sec < 60) return t('topo.durSec', { n: sec })
  if (sec < 3600) return t('topo.durMin', { n: Math.floor(sec / 60) })
  return t('topo.durHour', { n: Math.floor(sec / 3600) })
}
function riskLevel(n) {
  const s = safeStatus(n)
  return s === 'red' ? 2 : s === 'yellow' ? 1 : 0
}
function riskText(n) {
  const s = safeStatus(n)
  return s === 'gray' ? t('topo.riskNone') : s === 'green' ? t('topo.riskLow') : s === 'yellow' ? t('topo.riskMid') : t('topo.riskHigh')
}
// 更换绑定资产: 同步写 boundAssetId + boundAssetName(名字冗余存一份, 避免资产删除后显示断链)
function onBindChange(id) {
  const d = props.devices.find(x => x.deviceId === id)
  emit('update', { k: 'boundAssetId', v: id })
  emit('update', { k: 'boundAssetName', v: d ? (d.name || id) : '' })
}
// 通断重试间隔钳制: 红线重试 5~3600s, 绿线复验 10~86400s; 0/非法值忽略(保持默认)
function setRetry(k, raw) {
  const v = Math.round(Number(raw))
  if (!Number.isFinite(v)) return
  const lim = k === 'retrySec' ? [5, 3600] : [10, 86400]
  emit('update', { k, v: Math.max(lim[0], Math.min(lim[1], v)) })
}

// ===== 端口绑定(2026-10-02 排期需求 2) =====
// 选中链路时按两端节点取真实端口清单(探针 ifaces / 主机采集 nic 差分 / SNMP 接口表,
// 30s 缓存); 端点切换时旧绑定失效(端口属于旧设备) → 清空; 快速换链路的竞态用
// 序号守卫丢陈旧响应。
const fromPorts = ref([])
const toPorts = ref([])
const fromNote = ref('')
const toNote = ref('')
const fromSeq = { n: 0 }
const toSeq = { n: 0 }

function nodeOf(deviceId) {
  return (props.nodes || []).find(n => n.deviceId === deviceId) || null
}
async function loadEndPorts(deviceId, arr, noteRef, seq) {
  const my = ++seq.n
  arr.value = []
  noteRef.value = ''
  if (!deviceId) return
  const n = nodeOf(deviceId)
  if (!n) { noteRef.value = t('topo.endNotInView'); return }
  const d = await fetchNodePorts(n, props.devices)
  if (seq.n !== my) return   // 已换到另一条链路: 丢弃陈旧响应
  arr.value = d.ports || []
  if (!arr.value.length) noteRef.value = d.note || ''
}
// 换端点=用户动作: 旧绑定端口属于旧设备, 失效清空。
// 【2026-10-02 修 bug】此前清空逻辑放在"端点值变化"的 watch 里, 而 watch 在"选中链路
//  变化"时同样触发(点空白/别的设备收面板, 再点回这条线: old 从 null 变回设备 ID,
//  old!==undefined 守卫放行)→ 端点根本没动, 绑定却被静默清掉, 线上网口标签消失
//  (用户报"网口显示了, 再点一下线就没了")。清空只发生在用户真的改起点/终点下拉;
//  watch 只负责按新端点加载端口清单。
function onFromEndpoint(v) {
  emit('update', { k: 'fromPort', v: '' })
  emit('update', { k: 'fromDeviceId', v })
}
function onToEndpoint(v) {
  emit('update', { k: 'toPort', v: '' })
  emit('update', { k: 'toDeviceId', v })
}
watch(() => (props.selKind === 'link' && props.selObj) ? props.selObj.fromDeviceId : null,
  (id) => { loadEndPorts(id, fromPorts, fromNote, fromSeq) }, { immediate: true })
watch(() => (props.selKind === 'link' && props.selObj) ? props.selObj.toDeviceId : null,
  (id) => { loadEndPorts(id, toPorts, toNote, toSeq) }, { immediate: true })

function portOptLabel(p) {
  const total = (p.rxBps || 0) + (p.txBps || 0)
  return p.port + (p.up ? '' : ' (down)') + (total > 0 ? ' · ' + rateShort(total) + '/s' : '')
}
const portNote = computed(() => [fromNote.value, toNote.value].filter(Boolean).join('  |  '))
// 绑定端口的真实速率(只读展示; 无数据不显示 —— 不编造)
const boundRateText = computed(() => {
  if (props.selKind !== 'link' || !props.selObj) return ''
  const parts = []
  const fa = fromPorts.value.find(p => p.port === props.selObj.fromPort)
  const ta = toPorts.value.find(p => p.port === props.selObj.toPort)
  if (fa) parts.push(t('topo.sideSrc', { port: fa.port, tx: rateShort(fa.txBps), rx: rateShort(fa.rxBps) }))
  if (ta) parts.push(t('topo.sideDst', { port: ta.port, tx: rateShort(ta.txBps), rx: rateShort(ta.rxBps) }))
  return parts.join('   ')
})

// 告警列表: 从本地 nodes/links 的异常态派生(与画布高亮同源), 点击 emit locate 定位
const alerts = computed(() => {
  const out = []
  for (const n of props.nodes) {
    if (n.status === 'normal') continue
    const s = safeStatus(n)
    out.push({
      k: 'n', id: n.nodeId, deviceId: n.deviceId, text: n.name + ' ' + (n.ip || ''),
      lv: n.status === 'down' ? t('topo.alOffline') : n.status === 'error' ? t('topo.alError') : t('topo.alWarn'),
      color: s === 'red' ? '#f87171' : s === 'yellow' ? '#fbbf24' : '#94a3b8',
    })
  }
  for (const l of props.links) {
    if (l.status === 'normal') continue
    const a = props.nodes.find(x => x.deviceId === l.fromDeviceId)
    const b = props.nodes.find(x => x.deviceId === l.toDeviceId)
    out.push({ k: 'l', id: l.linkId, deviceId: l.fromDeviceId, text: (a ? a.name : '?') + ' ↔ ' + (b ? b.name : '?'), lv: l.status === 'down' ? t('topo.alBreak') : t('topo.alCongest'), color: l.status === 'down' ? '#f87171' : '#fbbf24' })
  }
  return out
})
</script>

<style scoped>
.ti { height: 100%; display: flex; flex-direction: column; box-sizing: border-box; overflow: hidden; }
/* 顶部标题栏 + 手动收起(浏览/编辑都可用, 是查看动作非变更) */
.ti-bar {
  display: flex; align-items: center; justify-content: space-between; flex: 0 0 auto;
  padding: 8px 10px 6px 14px; border-bottom: 1px solid rgba(255, 255, 255, .08);
}
.ti-title { font-size: 13px; color: #eaf1fb; }
.ti-close {
  width: 22px; height: 22px; border-radius: 5px; cursor: pointer; font-size: 15px; line-height: 1;
  color: #9fb0c8; background: rgba(255, 255, 255, .06); border: 1px solid rgba(255, 255, 255, .12);
}
.ti-close:hover { color: #fff; background: rgba(56, 132, 255, .3); }
.ti-scroll { flex: 1; min-height: 0; overflow-y: auto; display: flex; flex-direction: column; gap: 10px; padding: 10px 12px; }
.ti-sec { border: 1px solid rgba(255, 255, 255, .07); border-radius: 8px; padding: 8px 10px; display: flex; flex-direction: column; gap: 6px; }
.ti-sec.grow { flex: 1; }
.ti-h { font-size: 12.5px; color: #eaf1fb; display: flex; justify-content: space-between; }
.ti-h b { color: #fbbf24; }
.ti label { display: flex; align-items: center; gap: 8px; font-size: 11.5px; color: #8295b0; }
.ti label span { width: 68px; flex: 0 0 auto; display: flex; align-items: center; gap: 4px; }
.ti label i { font-style: normal; font-size: 9px; color: #38bdf8; border: 1px solid rgba(56, 189, 248, .35); border-radius: 3px; padding: 0 3px; }
.ti-ro-val { flex: 1; font-style: normal; font-size: 11.5px; color: #dbe6f5; }
/* 状态信息键值对(比输入框更轻, 纯展示) */
.ti-kv { display: flex; align-items: center; justify-content: space-between; font-size: 11.5px; color: #8295b0; padding: 2px 0; }
.ti-kv i { font-style: normal; color: #dbe6f5; font-variant-numeric: tabular-nums; }
.ti-kv i.bad { color: #f87171; }
.ti-kv .ti-aval { max-width: 130px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ti-st { font-size: 10px; border-radius: 4px; padding: 1px 6px; }
.ti-st.st-green { color: #34d399; background: rgba(52, 211, 153, .14); }
.ti-st.st-yellow { color: #fbbf24; background: rgba(251, 191, 36, .14); }
.ti-st.st-red { color: #f87171; background: rgba(248, 113, 113, .16); }
.ti-st.st-gray { color: #94a3b8; background: rgba(148, 163, 184, .14); }
/* 表单控件统一深色科技风(沿用既有口径): 重写原生背景/边框, 自定义下拉箭头, 聚焦发光 */
.ti input, .ti select {
  flex: 1; min-width: 0; font-size: 11.5px; padding: 3px 6px; border-radius: 5px;
  color: #e0e6f0; background: #162032; border: 1px solid #2a3f5f;
  transition: border-color .15s, box-shadow .15s;
}
.ti input:focus, .ti select:focus {
  outline: none; border-color: #3b82f6;
  box-shadow: 0 0 0 2px rgba(59, 130, 246, .28), 0 0 6px rgba(59, 130, 246, .22);
}
.ti select {
  appearance: none; -webkit-appearance: none; -moz-appearance: none;
  padding-right: 22px; cursor: pointer;
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'><path d='M1 1l4 4 4-4' fill='none' stroke='%238295b0' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'/></svg>");
  background-repeat: no-repeat; background-position: right 8px center;
}
.ti option { background: #162032; color: #e0e6f0; padding: 4px 6px; }
.ti option:hover, .ti option:checked { background: #1e2d45; color: #fff; }
.ti input:disabled, .ti select:disabled { color: #64748b; background: #121b2b; border-color: #22304a; opacity: 1; cursor: default; }
/* 启用监控开关 */
.ti-toggle input[type=checkbox] { flex: 0 0 auto; width: 34px; height: 18px; padding: 0; border-radius: 9px; cursor: pointer;
  background: #22304a; border: 1px solid #2a3f5f; position: relative; appearance: none; -webkit-appearance: none; transition: background .15s; }
.ti-toggle input[type=checkbox]::after {
  content: ''; position: absolute; top: 1px; left: 1px; width: 14px; height: 14px; border-radius: 50%;
  background: #64748b; transition: transform .15s, background .15s;
}
.ti-toggle input[type=checkbox]:checked { background: rgba(52, 211, 153, .35); border-color: #34d399; }
.ti-toggle input[type=checkbox]:checked::after { transform: translateX(16px); background: #34d399; }
/* 浏览模式只读: 全部输入/下拉/勾选禁用(标题栏收起按钮、告警列表定位不受影响) */
.ti.ro input, .ti.ro select { pointer-events: none; opacity: .55; cursor: default; }
.ti-danger { margin-top: 4px; font-size: 11.5px; padding: 4px 10px; border-radius: 6px; cursor: pointer; color: #f87171; background: rgba(248, 113, 113, .14); border: 1px solid rgba(248, 113, 113, .4); }
/* 连通性测试按钮 + 未测提示色(2026-09-29) */
.ti-check { margin-top: 4px; font-size: 11.5px; padding: 4px 10px; border-radius: 6px; cursor: pointer; color: #38bdf8; background: rgba(56, 189, 248, .12); border: 1px solid rgba(56, 189, 248, .45); }
.ti-check:hover:not(:disabled) { background: rgba(56, 189, 248, .28); color: #fff; }
.ti-check:disabled { opacity: .55; cursor: default; }
.ti-kv i.pend { color: #94a3b8; }
.ti-check-detail { border-top: 1px dashed rgba(255, 255, 255, .1); padding-top: 4px; }
.ti-check-detail i { color: #8fe3b0; font-size: 11px; }
.ti-none { font-size: 11.5px; color: #475569; padding: 4px 0; }
.ti-note { font-size: 11px; color: #64748b; line-height: 1.6; }
/* 多选清单行: 状态点/框形标 + 名称 + 副信息(IP/尺寸) */
.ti-mitem { display: flex; align-items: center; gap: 7px; font-size: 11.5px; color: #cdd6e4; padding: 3px 6px; border-radius: 5px; }
.ti-mitem:hover { background: rgba(56, 132, 255, .1); }
.ti-mitem i { width: 9px; height: 9px; flex: 0 0 auto; }
.ti-mitem .mi-dot { border-radius: 50%; box-shadow: 0 0 5px currentColor; }
.ti-mitem .mi-box { border: 1.5px solid #3884ff; border-radius: 2px; }
.ti-mitem .mi-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ti-mitem em { font-style: normal; color: #64748b; font-size: 10.5px; flex: 0 0 auto; }
.ti-alerts { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 4px; }
.ti-alert { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: #cdd6e4; padding: 4px 6px; border-radius: 5px; cursor: pointer; }
.ti-alert:hover { background: rgba(56, 132, 255, .12); }
.ti-alert i { width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto; box-shadow: 0 0 6px currentColor; }
.ti-a-t { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ti-a-l { color: #94a3b8; font-size: 10.5px; }
</style>

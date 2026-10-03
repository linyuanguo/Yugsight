<!--
  TopoBindDialog.vue 绑定节点弹窗(2026-09-29 借鉴 Zabbix"元素绑定主机"流程;
  2026-09-30 用户要求: 绑定候选=协议配置里的监控目标, 不是扫描发现的资产)。

  设备库拖到画布生成节点后弹出: 选一台"纳管设备"绑定到该节点,
  或"跳过"保持未纳管(灰色, 不参与告警)。

  口径:
  - 候选 = dashData 设备台账中 isMonitor=true 的纳管设备:
    探针(P_) / SNMP 网络监控目标(M_, 如 172.16.199.1) /
    采集任务(C_, 主机侧 winrm·ssh·snmp + 网络侧 icmp·netconf·restconf),
    15s 轮询与拓扑状态同步同源; 扫描发现的资产(A_, isMonitor=false)不入候选;
  - 已在画布的设备(deviceId 被其它节点占用)禁选 —— 一机一节点,
    重复绑会让"设备树定位"与节点状态同步(按 deviceId 匹配)全部错乱;
  - 同业务组(网络设备/业务服务)标"推荐", 降低选错概率。
-->
<template>
  <div v-if="open" class="tbd-mask" @click.self="emit('close')">
    <div class="tbd">
      <div class="tbd-h">
        <span>绑定节点 · <b>{{ node.name }}</b></span>
        <button type="button" @click="emit('close')">×</button>
      </div>
      <input v-model="kw" class="tbd-search" placeholder="搜索名称 / IP(留空看全部)" @keyup.esc="emit('close')" />
      <div class="tbd-list">
        <div v-for="d in list" :key="d.deviceId" class="tbd-item"
             :class="{ off: usedByOther(d) }"
             :title="usedByOther(d) ? '该设备已在画布(一机一节点)' : (d.ip || '')"
             @click="!usedByOther(d) && emit('bind', d)">
          <i class="tbd-dot" :style="{ background: dotColor(d) }"></i>
          <span class="tbd-name">{{ d.name }}</span>
          <em class="tbd-ip">{{ d.ip || '—' }}</em>
          <span v-if="usedByOther(d)" class="tbd-tag off-tag">已在画布</span>
          <span v-else-if="isRecommended(d)" class="tbd-tag rec-tag">推荐</span>
        </div>
        <div v-if="!list.length" class="tbd-none">无匹配的纳管设备。绑定候选=「节点监控 → 协议配置」的监控目标(探针 / 主机侧采集 SSH·WinRM·SNMP / 网络侧采集 / SNMP 网络监控目标), 请先添加对应任务或目标。</div>
      </div>
      <div class="tbd-foot">
        <span class="tbd-hint">绑定后节点随 15s 轮询同步实时状态; 跳过 = 未纳管(灰色, 不参与告警)</span>
        <button type="button" class="tbd-skip" @click="emit('skip')">跳过(未纳管)</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { bizGroup } from './topoModel.js'

const props = defineProps({
  open: { type: Boolean, default: false },
  node: { type: Object, default: null },        // 刚生成的节点
  devices: { type: Array, default: () => [] },  // dashData 设备台账(内部只取 isMonitor 纳管设备)
  usedIds: { type: Array, default: () => [] },  // 画布已占用的 deviceId(含本节点)
})
const emit = defineEmits(['bind', 'skip', 'close'])

const kw = ref('')
// 2026-09-30 用户要求: 绑定候选只取纳管设备(isMonitor=true: 探针/SNMP 监控目标/采集任务),
// 扫描发现的资产(A_, isMonitor=false)不参与绑定
const list = computed(() => {
  const k = kw.value.trim().toLowerCase()
  const arr = (props.devices || []).filter(d => d.isMonitor)
  if (!k) return arr
  return arr.filter(d => (d.name || '').toLowerCase().includes(k) || (d.ip || '').includes(k) || (d.ips || []).some(i => i.includes(k)))
})
function usedByOther(d) {
  return (props.usedIds || []).includes(d.deviceId)
}
// 同业务组 = 推荐(网络设备↔网络设备, 业务服务↔业务服务)
function isRecommended(d) {
  if (!props.node || !d.type) return false
  const deviceGroup = d.type === 'coresw' ? 'network' : 'service'
  return bizGroup(props.node.type) === deviceGroup
}
function dotColor(d) {
  return d.status === 'down' ? '#94a3b8' : (d.status === 'error' ? '#f87171' : (d.status === 'warn' ? '#fbbf24' : '#34d399'))
}
</script>

<style scoped>
.tbd-mask { position: fixed; inset: 0; z-index: 9000; display: flex; align-items: center; justify-content: center; background: rgba(4, 8, 16, .6); }
.tbd { width: 460px; max-width: 92%; max-height: 76vh; display: flex; flex-direction: column; background: rgba(12, 20, 36, .98); border: 1px solid rgba(56, 132, 255, .4); border-radius: 10px; box-shadow: 0 16px 44px rgba(0, 0, 0, .6); }
.tbd-h { display: flex; align-items: center; justify-content: space-between; padding: 12px 14px 8px; font-size: 13.5px; color: #eaf1fb; }
.tbd-h b { color: #38bdf8; font-weight: 600; }
.tbd-h button { background: none; border: none; color: #8295b0; font-size: 18px; cursor: pointer; }
.tbd-search { margin: 0 14px 8px; font-size: 12px; padding: 6px 10px; border-radius: 6px; color: #eaf1fb; background: rgba(255, 255, 255, .06); border: 1px solid rgba(56, 132, 255, .3); }
.tbd-search:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 2px rgba(59, 130, 246, .25); }
.tbd-list { flex: 1; min-height: 120px; overflow-y: auto; padding: 0 8px; display: flex; flex-direction: column; gap: 3px; }
.tbd-item { display: flex; align-items: center; gap: 8px; padding: 6px 8px; border-radius: 6px; cursor: pointer; font-size: 12px; color: #cdd6e4; }
.tbd-item:hover { background: rgba(56, 132, 255, .16); }
.tbd-item.off { opacity: .45; cursor: not-allowed; }
.tbd-dot { width: 8px; height: 8px; border-radius: 50%; flex: 0 0 auto; box-shadow: 0 0 6px currentColor; }
.tbd-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tbd-ip { font-style: normal; font-size: 11px; color: #64748b; font-family: var(--mono, monospace); }
.tbd-tag { flex: 0 0 auto; font-size: 10px; border-radius: 4px; padding: 1px 6px; }
.tbd-tag.rec-tag { color: #38bdf8; background: rgba(56, 189, 248, .14); border: 1px solid rgba(56, 189, 248, .35); }
.tbd-tag.off-tag { color: #64748b; background: rgba(100, 116, 139, .12); border: 1px solid rgba(100, 116, 139, .3); }
.tbd-none { padding: 16px 10px; font-size: 11.5px; color: #475569; line-height: 1.6; }
.tbd-foot { display: flex; align-items: center; gap: 10px; padding: 10px 14px; border-top: 1px solid rgba(255, 255, 255, .08); }
.tbd-hint { flex: 1; font-size: 10.5px; color: #64748b; line-height: 1.4; }
.tbd-skip { flex: 0 0 auto; font-size: 12px; padding: 5px 14px; border-radius: 6px; cursor: pointer; color: #cdd6e4; background: rgba(56, 132, 255, .16); border: 1px solid rgba(56, 132, 255, .4); }
.tbd-skip:hover { background: rgba(56, 132, 255, .32); }
</style>

<template>
  <!-- 节点指标卡(2026-09-28): 复用通用 3D 卡片外壳, 展示设备名称/IP/CPU/内存/网络上下行/状态。
       数据口径: 纳管设备(dashData 设备表里存在)的 CPU/内存/状态直接取 15s 轮询的实时值,
       不再用卡片里的静态字段 —— 否则会出现"卡片显示 20% 而实际已经红了"。
       非纳管(自定义标注)设备回退到卡片自身字段。
       (与旧拓扑的 topoFocus/topoActive 双向联动已随旧拓扑模块整体删除) -->
  <div class="nc" :class="['st-' + status, mode]">
    <template v-if="side === 'front'">
      <div class="nc-head">
        <span class="nc-ico" :class="'k-' + card.kind">{{ kindGlyph }}</span>
        <div class="nc-name"><b>{{ name }}</b><small>{{ ip || '—' }}</small></div>
        <span class="nc-badge">{{ statusText }}</span>
      </div>
      <div class="nc-metrics">
        <div class="nc-bar"><i>CPU</i><span class="nc-track"><b :style="{ width: cpu + '%', background: nodeColor(cpu) }"></b></span><em>{{ cpu }}%</em></div>
        <div class="nc-bar"><i>内存</i><span class="nc-track"><b :style="{ width: mem + '%', background: nodeColor(mem) }"></b></span><em>{{ mem }}%</em></div>
      </div>
      <div class="nc-net">
        <span>↑ {{ fmt(card.netUpBps) }}</span>
        <span>↓ {{ fmt(card.netDownBps) }}</span>
        <i v-if="managed" class="nc-mon" title="纳管设备: 指标由监控接口同步">监控同步</i>
      </div>
    </template>
    <template v-else>
      <div class="nc-back">
        <div>deviceId：{{ card.deviceId || '—' }}</div>
        <div>MAC：{{ mac || '—' }}</div>
        <div>层级：{{ layerText }}</div>
        <div>类型：{{ kindText }}</div>
        <div>纳管：{{ managed ? '是(监控同步)' : '否(本地字段)' }}</div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useShared, deviceById } from './dashData.js'

const props = defineProps({
  card: { type: Object, required: true },
  compact: { type: Boolean, default: false },
  side: { type: String, default: 'front' },
  mode: { type: String, default: 'browse' },
})

const S = useShared()

const dev = computed(() => {
  void S.devUpdatedAt // 依赖设备列表刷新拍, 保证实时跟随轮询
  return props.card.deviceId ? deviceById(props.card.deviceId) : null
})
const managed = computed(() => !!dev.value)
// 纳管取实时值, 未纳管回落卡片自身字段
const cpu = computed(() => (dev.value ? dev.value.cpu : (props.card.cpu || 0)))
const mem = computed(() => (dev.value ? dev.value.memory : (props.card.mem || 0)))
const status = computed(() => (dev.value ? dev.value.status : (props.card.status || 'normal')))
const ip = computed(() => ((dev.value && dev.value.ip) || props.card.ip || ''))
const mac = computed(() => ((dev.value && dev.value.mac) || props.card.mac || ''))
const name = computed(() => props.card.name || (dev.value && dev.value.name) || '设备')

const STATUS = { normal: '正常', warn: '告警', error: '异常', down: '断开' }
const statusText = computed(() => STATUS[status.value] || status.value)
const layerText = { core: '核心层', agg: '汇聚层', access: '接入层' }[props.card.layer] || props.card.layer
const kindText = { router: '路由器', switch: '交换机', server: '服务器', terminal: '终端' }[props.card.kind] || props.card.kind
const kindGlyph = { router: '⇄', switch: '▦', server: '▤', terminal: '▭' }[props.card.kind] || '▣'

// 负载→色(绿→黄→红), 与拓扑节点同一映射口径
function nodeColor(v) {
  const load = Math.max(0, Math.min(100, v)) / 100
  return `hsl(${Math.round(140 * (1 - load))} 80% 55%)`
}
function fmt(bps) {
  bps = bps || 0
  if (bps >= 1e9) return (bps / 1e9).toFixed(1) + ' Gb/s'
  if (bps >= 1e6) return (bps / 1e6).toFixed(1) + ' Mb/s'
  if (bps >= 1e3) return Math.round(bps / 1e3) + ' Kb/s'
  return bps + ' b/s'
}
</script>

<style scoped>
.nc { height: 100%; box-sizing: border-box; padding: 14px 16px; display: flex; flex-direction: column; gap: 12px; }
.nc-head { display: flex; align-items: center; gap: 12px; }
.nc-ico {
  width: 34px; height: 34px; border-radius: 8px; flex: 0 0 auto;
  display: flex; align-items: center; justify-content: center; font-size: 16px; font-weight: 700; color: #06121f;
  background: linear-gradient(145deg, #e8eefc, #b9c6e0);
  box-shadow: 0 6px 12px rgba(0, 0, 0, .5), inset 0 2px 3px rgba(255, 255, 255, .6), inset 0 -3px 6px rgba(0, 0, 0, .3);
}
.nc-name { flex: 1; min-width: 0; }
.nc-name b { display: block; font-size: 15px; color: #eaf1fb; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.nc-name small { font-size: 12px; color: #8295b0; }
.nc-badge { flex: 0 0 auto; font-size: 11px; padding: 3px 9px; border-radius: 999px; color: #06121f; font-weight: 700; }
.st-normal .nc-badge { background: #34d399; }
.st-warn .nc-badge { background: #fbbf24; }
.st-error .nc-badge { background: #f87171; }
.st-down .nc-badge { background: #94a3b8; }
.nc-metrics { display: flex; flex-direction: column; gap: 8px; }
.nc-bar { display: flex; align-items: center; gap: 8px; font-size: 12px; color: #9fb0c8; }
.nc-bar i { width: 32px; font-style: normal; }
.nc-track { flex: 1; height: 8px; border-radius: 999px; background: rgba(255, 255, 255, .08); overflow: hidden; }
.nc-track b { display: block; height: 100%; border-radius: 999px; transition: width .3s; }
.nc-bar em { width: 38px; text-align: right; font-style: normal; color: #cdd6e4; }
.nc-net { display: flex; align-items: center; gap: 16px; font-size: 12px; color: #7dd3fc; }
.nc-net span:last-of-type { color: #fcd34d; }
.nc-mon { margin-left: auto; font-style: normal; font-size: 10px; color: #38bdf8; border: 1px solid rgba(56, 189, 248, .35); border-radius: 3px; padding: 1px 5px; }
.nc-back { display: flex; flex-direction: column; gap: 8px; font-size: 13px; color: #b9c6db; padding: 6px; }
</style>

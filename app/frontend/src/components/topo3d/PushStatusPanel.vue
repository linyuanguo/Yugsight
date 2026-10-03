<!--
  PushStatusPanel.vue 告警推送轻量入口(2026-09-28)。

  分层边界(任务口径「大屏开关 + 节点管理」):
    - 大屏侧(本组件)只给三样: 推送总开关 / 今日推送概览 / 「完整配置」跳转;
    - 完整的目标管理、规则配置、测试推送、推送日志全部在
      「节点监控 → 告警日志管理 → 推送配置」(路由 /nodemonitor?view=alerts&tab=push)。

  两种形态:
    compact=true  → 大屏拓扑卡内嵌的一行 chip: 浏览模式只读展示, 点击整条跳转完整配置
                    (浏览模式允许"查看 + 跳转", 不允许编辑 —— 开关只在属性面板里改);
    compact=false → 大屏属性面板「告警设置」分组块: 编辑模式下开关可操作 + 概览 + 跳转。

  数据: GET /api/node/push/stat 30s 轮询(轻量只读端点); 开关 PUT /api/node/push/switch。
  失败降级: 接口不可用时保留上次快照并置灰提示, 不弹错(大屏常驻组件不能因推送接口抖动闪烁)。
-->
<template>
  <div v-if="compact" class="ps ps-compact" :class="{ on: enabled === true }"
       title="点击跳转「节点监控 → 告警日志管理 → 推送配置」"
       @pointerdown.stop @click.stop="gotoFull">
    <i class="ps-dot" :class="enabled === true ? 'ok' : enabled === false ? 'off' : 'wait'"></i>
    <span class="ps-t">告警推送{{ enabled === true ? '已开启' : enabled === false ? '已关闭' : '…' }}</span>
    <span class="ps-stat">今日 {{ todayPushed }} 条 · 失败 {{ todayFailed }}</span>
    <span class="ps-go">完整配置 ›</span>
  </div>

  <div v-else class="ps ps-block">
    <div class="ps-row">
      <span class="ps-l">推送总开关</span>
      <button type="button" class="ps-switch" :class="{ on: enabled === true, busy }"
              :disabled="!editable || busy || enabled === null"
              :title="editable ? (enabled ? '点击关闭' : '点击开启') : '仅编辑模式可操作'"
              @click="toggle">
        <i class="ps-knob"></i>
      </button>
      <span class="ps-state" :class="{ busy }">
        {{ enabled === null ? '加载中…' : enabled ? '已开启' : '已关闭' }}
      </span>
    </div>
    <div class="ps-row">
      <span class="ps-l">今日推送</span>
      <span class="ps-stat2">
        <b class="ok">{{ todayPushed }}</b> 条
        <b class="bad" v-if="todayFailed > 0">{{ todayFailed }}</b>
        <span class="ps-fail-l">条失败</span>
      </span>
    </div>
    <div class="ps-row">
      <span class="ps-l">完整配置</span>
      <button type="button" class="ps-btn" @click="gotoFull">节点监控 → 告警推送 ›</button>
    </div>
    <div v-if="err" class="ps-err">{{ err }}</div>
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import { fetchPushStat, setPushSwitch } from '../../api/nodepush'
import { toast } from '../../toast'

const props = defineProps({
  compact: { type: Boolean, default: false },
  // 开关是否可操作(属性面板只在编辑模式渲染本组件, 这里再做一层显式守卫:
  // 浏览模式任何入口挂载本组件都不允许改开关)
  editable: { type: Boolean, default: true },
})

const router = useRouter()

const enabled = ref(null)      // null = 加载中
const todayPushed = ref(0)
const todayFailed = ref(0)
const err = ref('')
const busy = ref(false)
let timer = null

async function load(silent = false) {
  try {
    const d = await fetchPushStat()
    enabled.value = !!d.enabled
    todayPushed.value = Number(d.todayPushed) || 0
    todayFailed.value = Number(d.todayFailed) || 0
    err.value = ''
  } catch (e) {
    // 保留上次快照; 无快照时(首拉失败)给一行降级提示, 不弹 toast(轮询场景会刷)
    if (enabled.value === null && !silent) err.value = '推送状态获取失败: ' + (e.message || '')
  }
}

async function toggle() {
  if (busy.value || enabled.value === null) return
  busy.value = true
  const next = !enabled.value
  try {
    await setPushSwitch(next)
    enabled.value = next
    toast('告警推送总开关已' + (next ? '开启' : '关闭'), 'ok')
    load(true)   // 回读确认(后端是唯一事实来源)
  } catch (e) {
    toast('开关切换失败: ' + (e.message || ''), 'err')
  } finally {
    busy.value = false
  }
}

// 「完整配置」跳转: 节点监控 → 告警日志管理 → 推送配置 tab
function gotoFull() {
  router.push({ path: '/nodemonitor', query: { view: 'alerts', tab: 'push' } })
}

onMounted(() => {
  load()
  timer = setInterval(() => load(true), 30000)
})
onBeforeUnmount(() => {
  if (timer) { clearInterval(timer); timer = null }
})
</script>

<style scoped>
/* ===== compact: 大屏拓扑卡内嵌 chip(单行, 点击整条跳转) ===== */
.ps-compact {
  display: flex; align-items: center; gap: 6px;
  font-size: 10.5px; color: #9fb0c8; cursor: pointer; user-select: none;
  padding: 2px 8px; border-radius: 999px;
  background: rgba(255, 255, 255, .05); border: 1px solid rgba(255, 255, 255, .12);
}
.ps-compact:hover { background: rgba(56, 132, 255, .16); border-color: rgba(56, 132, 255, .45); color: #dbe6f5; }
.ps-dot { width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto; }
.ps-dot.ok { background: #34d399; box-shadow: 0 0 6px #34d399; }
.ps-dot.off { background: #64748b; }
.ps-dot.wait { background: #fbbf24; box-shadow: 0 0 6px #fbbf24; animation: psBlink 1s ease-in-out infinite; }
@keyframes psBlink { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
.ps-t { color: #cdd6e4; }
.ps-stat { color: #8295b0; }
.ps-go { margin-left: auto; color: #38bdf8; }
.ps-compact:hover .ps-go { text-decoration: underline; }

/* ===== block: 属性面板「告警设置」分组 ===== */
.ps-block { display: flex; flex-direction: column; gap: 8px; }
.ps-row { display: flex; align-items: center; gap: 8px; }
.ps-l { width: 64px; flex: 0 0 auto; font-size: 11.5px; color: #8295b0; }
.ps-state { font-size: 11.5px; color: #9fb0c8; }
.ps-state.busy { color: #fbbf24; }
.ps-stat2 { font-size: 11.5px; color: #8295b0; }
.ps-stat2 b { font-size: 13px; margin: 0 2px; }
.ps-stat2 b.ok { color: #34d399; }
.ps-stat2 b.bad { color: #f87171; }
.ps-fail-l { margin-left: 2px; }
/* 开关(滑块样式, 与深色主题一致) */
.ps-switch {
  position: relative; width: 34px; height: 18px; border-radius: 999px; flex: 0 0 auto;
  background: #22304a; border: 1px solid #33465f; cursor: pointer; padding: 0;
  transition: background .18s, border-color .18s;
}
.ps-switch.on { background: rgba(52, 211, 153, .35); border-color: #34d399; }
.ps-switch:disabled { opacity: .45; cursor: default; }
.ps-knob {
  position: absolute; top: 2px; left: 2px; width: 12px; height: 12px; border-radius: 50%;
  background: #8295b0; transition: transform .18s, background .18s;
}
.ps-switch.on .ps-knob { transform: translateX(16px); background: #34d399; box-shadow: 0 0 6px rgba(52, 211, 153, .8); }
.ps-btn {
  flex: 1; min-width: 0; font-size: 11.5px; padding: 4px 8px; border-radius: 6px; cursor: pointer;
  color: #38bdf8; background: rgba(56, 189, 248, .12); border: 1px solid rgba(56, 189, 248, .4);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.ps-btn:hover { background: rgba(56, 189, 248, .26); color: #fff; }
.ps-err { font-size: 10.5px; color: #fbbf24; }
</style>

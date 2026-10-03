<template>
  <!-- 左侧设备树: 按层级 / 按类型两种分组, 点击定位并选中; 编辑模式提供导入与批量操作。 -->
  <div class="tt">
    <div class="tt-head">
      <span>设备树</span>
      <div class="tt-group">
        <button type="button" :class="{ on: group === 'layer' }" @click="group = 'layer'">层级</button>
        <button type="button" :class="{ on: group === 'type' }" @click="group = 'type'">类型</button>
      </div>
    </div>
    <input v-model="kw" class="tt-search" placeholder="过滤名称 / IP" />
    <div class="tt-body">
      <!-- 设备库(借鉴 Zabbix 元素库, 仅编辑模式): 拖类型字形到画布 → 生成节点 → 弹资产绑定 -->
      <div v-if="mode === 'edit'" class="tt-grp tt-library">
        <div class="tt-grp-h tt-library-h">
          <span>设备库</span><b>拖到画布生成</b>
        </div>
        <div class="tt-lib-list">
          <template v-for="g in libSections" :key="g.key">
            <!-- 组头可折叠(2026-10-02 用户要求: 网络设备/业务服务 都可以折叠显示) -->
            <div class="tt-lib-grp" :class="{ closed: libCollapsed[g.key] }" @click="toggleLib(g.key)">
              <i class="tt-lib-caret">▸</i><span>{{ t(g.label) }}</span><b>{{ g.items.length }}</b>
            </div>
            <div v-show="!libCollapsed[g.key]" class="tt-lib-items">
              <div v-for="t in g.items" :key="t.v" class="tt-lib-item" draggable="true"
                   :title="'拖到画布, 或点 + 直接添加「' + t.t + '」'" @dragstart="onLibDragStart($event, t.v)">
                <i class="tt-glyph">{{ t.glyph }}</i><span>{{ t.t }}</span>
                <!-- 一键添加(2026-09-29): 点 + 直接落到画布中心 → 同样弹资产绑定; 拖拽保留 -->
                <button type="button" class="tt-lib-add" title="直接添加到画布" @click.stop="emit('quick-add', t.v)">＋</button>
              </div>
            </div>
          </template>
        </div>
      </div>
      <div v-for="g in groups" :key="g.k" class="tt-grp">
        <div class="tt-grp-h" @click="toggle(g.k)">
          <span><i v-if="g.glyph" class="tt-glyph">{{ g.glyph }}</i>{{ g.t }}</span><b>{{ g.items.length }}</b>
          <button v-if="mode === 'edit' && g.items.length" type="button" class="tt-mini" @click.stop="emit('batch-hide', g.items)">隐藏</button>
        </div>
        <div v-if="!collapsed[g.k]" class="tt-list">
          <div v-for="n in g.items" :key="n.nodeId" class="tt-item" :class="{ on: selNode === n.nodeId }"
               @click="pick(n)">
            <i class="tt-dot" :style="{ background: STATUS_COLOR[n.status] || '#94a3b8' }"></i>
            <span class="tt-name" :title="n.name">{{ n.name }}</span>
            <span class="tt-ip">{{ n.ip || '—' }}</span>
          </div>
          <div v-if="!g.items.length" class="tt-none">无</div>
        </div>
      </div>
    </div>
    <!-- 2026-09-30 用户要求: 底部"导入设备/重新布局"两按钮移除
         (空视图首次打开的自动导入在页面 bootstrap 里做; 重排摆位用视图"删除重建"或逐节点拖拽) -->
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { typeText, typeGlyph, bizGroup, STATUS_COLOR, TYPE_GROUPS, TYPES, TOPO_TYPE_MIME } from './topoModel.js'
import { t } from '../../i18n'

const props = defineProps({
  nodes: { type: Array, default: () => [] },
  mode: { type: String, default: 'browse' },
  selNode: { type: String, default: '' },
  // 用户自定义分层盒(2026-09-29): "层级"分组标题跟随层名(改名/增删实时同步)
  bands: { type: Array, default: () => [] },
})
// 2026-09-30 用户要求: 'import'/'relayout'(底部两按钮)移除
const emit = defineEmits(['pick', 'batch-hide', 'quick-add'])

const group = ref('layer')
const kw = ref('')
const collapsed = ref({})

const filtered = computed(() => {
  const k = kw.value.trim().toLowerCase()
  if (!k) return props.nodes
  return props.nodes.filter(n => (n.name || '').toLowerCase().includes(k) || (n.ip || '').includes(k))
})
const groups = computed(() => {
  const map = new Map()
  const bandName = (idx) => {
    const b = (props.bands || [])[idx - 1]
    return (b && b.name) ? b.name : ({ 1: '核心层', 2: '汇聚层', 3: '接入层' }[idx] || '接入层')
  }
  for (const n of filtered.value) {
    if (group.value === 'layer') {
      const key = String(n.layer || 3)
      const title = bandName(Number(key))
      if (!map.has(key)) map.set(key, { k: key, t: title, items: [] })
      map.get(key).items.push(n)
    } else {
      // 按类型: 网络设备在前 / 业务服务在后, 带字形(差异化图标)
      const key = n.type || 'server'
      if (!map.has(key)) map.set(key, { k: 'type_' + key, t: typeText(key), glyph: typeGlyph(key), biz: bizGroup(key), items: [] })
      map.get(key).items.push(n)
    }
  }
  const arr = Array.from(map.values())
  if (group.value === 'type') arr.sort((a, b) => (a.biz === 'network' ? 0 : 1) - (b.biz === 'network' ? 0 : 1))
  return arr
})
function toggle(k) { collapsed.value[k] = !collapsed.value[k] }
function pick(n) { emit('pick', n) }

// ===== 设备库(编辑模式): 类型分组平铺, HTML5 原生拖拽到画布 =====
// 与"添加设备"菜单同一事实来源(TYPES), 多一个 group 分组头。
const LIB_DRAG_MIME = 'text/topo-type'
const libSections = computed(() => TYPE_GROUPS.map(g => ({
  key: g.key, label: g.label,
  items: Object.keys(TYPES).filter(v => TYPES[v].group === g.key)
    .map(v => ({ v, t: typeText(v), glyph: typeGlyph(v) })),
})))
function onLibDragStart(e, type) {
  e.dataTransfer.setData(LIB_DRAG_MIME, type)
  e.dataTransfer.effectAllowed = 'copy'
}
// 设备库组折叠(2026-10-02 用户要求: 网络设备/业务服务 都可以折叠显示)
const libCollapsed = ref({})
function toggleLib(k) { libCollapsed.value[k] = !libCollapsed.value[k] }
</script>

<style scoped>
.tt { height: 100%; display: flex; flex-direction: column; gap: 8px; padding: 10px 12px; box-sizing: border-box; }
.tt-head { display: flex; align-items: center; justify-content: space-between; font-size: 13px; color: #eaf1fb; }
.tt-group { display: flex; gap: 4px; }
.tt-group button { font-size: 11px; padding: 2px 8px; border-radius: 5px; cursor: pointer; color: #9fb0c8; background: rgba(255, 255, 255, .05); border: 1px solid rgba(255, 255, 255, .1); }
.tt-group button.on { color: #fff; background: rgba(56, 132, 255, .3); border-color: rgba(56, 132, 255, .5); }
.tt-search { width: 100%; box-sizing: border-box; font-size: 12px; padding: 5px 8px; border-radius: 6px; color: #eaf1fb; background: rgba(255, 255, 255, .06); border: 1px solid rgba(56, 132, 255, .28); }
.tt-body { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 6px; }
.tt-grp { border: 1px solid rgba(255, 255, 255, .07); border-radius: 7px; overflow: hidden; }
.tt-grp-h { display: flex; align-items: center; gap: 6px; padding: 5px 8px; font-size: 12px; color: #cdd6e4; background: rgba(255, 255, 255, .04); cursor: pointer; }
.tt-grp-h b { color: #64748b; font-weight: 600; }
.tt-glyph { font-style: normal; margin-right: 4px; color: #8fb0e8; }
.tt-mini { margin-left: auto; font-size: 10px; padding: 1px 6px; border-radius: 4px; color: #f87171; background: rgba(248, 113, 113, .12); border: 1px solid rgba(248, 113, 113, .3); cursor: pointer; }
.tt-list { display: flex; flex-direction: column; }
.tt-item { display: flex; align-items: center; gap: 6px; padding: 4px 10px; font-size: 11.5px; color: #b9c6db; cursor: pointer; }
.tt-item:hover { background: rgba(56, 132, 255, .12); }
.tt-item.on { background: rgba(251, 191, 36, .16); color: #fde68a; }
.tt-dot { width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto; box-shadow: 0 0 6px currentColor; }
.tt-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tt-ip { color: #64748b; font-size: 10.5px; }
.tt-none { padding: 4px 10px; font-size: 11px; color: #475569; }
/* 设备库(拖拽源): 整组高亮区分于"当前画布设备", 条目带拖拽手型 */
.tt-library { border-color: rgba(56, 189, 248, .35); }
.tt-library-h { background: rgba(56, 189, 248, .08); }
.tt-library-h b { color: #38bdf8; font-weight: 500; }
.tt-lib-list { display: flex; flex-direction: column; }
.tt-lib-grp { padding: 3px 10px 2px; font-size: 10px; color: #475569; letter-spacing: 1px; display: flex; align-items: center; gap: 5px; cursor: pointer; user-select: none; }
.tt-lib-grp:hover { color: #8295b0; background: rgba(255, 255, 255, .04); }
.tt-lib-grp b { margin-left: auto; font-weight: 600; }
.tt-lib-caret { font-style: normal; font-size: 9px; color: #64748b; transform: rotate(90deg); transition: transform .15s ease; }
.tt-lib-grp.closed .tt-lib-caret { transform: none; }
.tt-lib-items { display: flex; flex-direction: column; }
.tt-lib-item {
  display: flex; align-items: center; gap: 7px; padding: 4px 10px; font-size: 11.5px;
  color: #b9c6db; cursor: grab; user-select: none;
}
.tt-lib-item:hover { background: rgba(56, 189, 248, .14); color: #eaf1fb; }
.tt-lib-item:active { cursor: grabbing; }
.tt-lib-add {
  margin-left: auto; width: 18px; height: 18px; border-radius: 4px; flex: 0 0 auto;
  font-size: 12px; line-height: 1; cursor: pointer; color: #38bdf8;
  background: rgba(56, 189, 248, .1); border: 1px solid rgba(56, 189, 248, .35);
}
.tt-lib-add:hover { background: rgba(56, 189, 248, .3); color: #fff; }
</style>

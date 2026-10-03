<!--
  PushRuleConfig.vue 推送规则配置(2026-09-28, 告警日志管理 → 推送配置下半区)。

  字段: 告警级别过滤(三级复选, 默认全选) / 告警延迟(秒, 默认 30) /
        推送时段(全天|工作时段 09:00-18:00|自定义) / 免打扰时段(开关+时间, 可跨天) /
        推送目标关联(多选, 支持全选/反选, 来自 pushStore 实时列表)。
  后端对接(2026-09-28): 持久化改走 GET/PUT /api/node/push/rules(api/nodepush.js),
  localStorage 已移除; 加载失败保留上次成功加载的配置(快照), 保存失败保持脏状态。
  脏状态: 表单与"最近一次后端成功加载/保存"快照的 JSON 比对(经 normalizeRules
  固定键序, 后端返回键序不同也不会产生假脏), 通过 emit('dirty') 上抛给父页
  (父页负责"未保存切换页面"的拦截提示 + beforeunload)。
-->
<template>
  <div class="card">
    <div class="card-title">
      推送规则配置
      <span class="chip" v-if="dirty" style="color:var(--yellow);border-color:rgba(250,204,21,.5);background:rgba(250,204,21,.08)">
        ● 有未保存修改
      </span>
      <div class="spacer"></div>
      <button class="btn xs" @click="restoreSaved">恢复已保存</button>
    </div>

    <div class="rule-grid">
      <!-- 告警级别过滤 -->
      <div class="field rule-f">
        <label class="label">告警级别过滤</label>
        <div class="rule-checks">
          <label class="checkbox" v-for="l in LEVELS" :key="l.key">
            <input type="checkbox" v-model="form.levels" :value="l.key" />
            <span class="badge" :class="l.cls">{{ l.label }}</span>
          </label>
        </div>
        <div class="muted small">只推送勾选级别的告警; 全部取消 = 不推送任何告警。</div>
      </div>

      <!-- 告警延迟 -->
      <div class="field rule-f">
        <label class="label">告警延迟(秒, 默认 30)</label>
        <div class="form-row" style="margin-bottom:0">
          <input class="input rule-num" type="number" min="0" max="3600" v-model.number="form.delaySec" />
          <span class="muted small" style="align-self:center">触发后等待 N 秒再推送, 用于聚合同类告警</span>
        </div>
        <div class="form-err" v-if="err.delaySec">{{ err.delaySec }}</div>
      </div>

      <!-- 推送时段 -->
      <div class="field rule-f">
        <label class="label">推送时段</label>
        <div class="rule-radios">
          <label class="checkbox">
            <input type="radio" value="all" v-model="form.window" /> 全天推送
          </label>
          <label class="checkbox">
            <input type="radio" value="work" v-model="form.window" /> 工作时段({{ form.workStart }}-{{ form.workEnd }})
          </label>
          <label class="checkbox">
            <input type="radio" value="custom" v-model="form.window" /> 自定义时段
          </label>
        </div>
        <div class="form-row" v-if="form.window === 'custom'">
          <div class="field" style="margin:0">
            <label class="label">开始</label>
            <input class="input" type="time" v-model="form.customStart" />
          </div>
          <div class="field" style="margin:0">
            <label class="label">结束</label>
            <input class="input" type="time" v-model="form.customEnd" />
          </div>
        </div>
        <div class="muted small" v-if="form.window === 'custom'">支持跨天(如 22:00-08:00 表示 22 点起至次日 8 点)。</div>
        <div class="form-err" v-if="err.window">{{ err.window }}</div>
      </div>

      <!-- 免打扰时段 -->
      <div class="field rule-f">
        <label class="label">免打扰时段</label>
        <label class="checkbox" style="margin-bottom:8px">
          <input type="checkbox" v-model="form.dnd" /> 开启免打扰
        </label>
        <div class="form-row" v-if="form.dnd">
          <div class="field" style="margin:0">
            <label class="label">开始</label>
            <input class="input" type="time" v-model="form.dndStart" />
          </div>
          <div class="field" style="margin:0">
            <label class="label">结束</label>
            <input class="input" type="time" v-model="form.dndEnd" />
          </div>
        </div>
        <div class="muted small" v-if="form.dnd">时段内不推送, 到时段外后补发(支持跨天)。</div>
        <div class="form-err" v-if="err.dnd">{{ err.dnd }}</div>
      </div>

      <!-- 推送目标关联 -->
      <div class="field rule-f" style="margin-bottom:0">
        <label class="label">
          推送目标关联
          <span class="muted" style="font-weight:400">已选 {{ form.targetIds.length }} / {{ pushStore.targets.length }}</span>
        </label>
        <div class="rule-target-head" v-if="pushStore.targets.length">
          <button class="btn xs" @click="selectAll">全选</button>
          <button class="btn xs" @click="invertSelection">反选</button>
        </div>
        <div class="rule-targets" v-if="pushStore.targets.length">
          <label class="checkbox t-item" v-for="t in pushStore.targets" :key="t.id">
            <input type="checkbox" v-model="form.targetIds" :value="t.id" />
            <span>{{ t.name }}</span>
            <span class="muted small">({{ typeLabel(t.type) }})</span>
            <span class="chip t-chip" :class="t.enabled ? 'on' : 'off'">{{ t.enabled ? '启用' : '停用' }}</span>
          </label>
        </div>
        <div class="muted small" v-else>暂无推送目标, 请先在上方「推送目标管理」中添加(未关联目标将不推送)。</div>
      </div>
    </div>

    <div class="form-actions rule-foot">
      <span class="muted small" v-if="dirty">有未保存修改, 请记得点击「保存配置」</span>
      <div class="spacer"></div>
      <button class="btn" @click="restoreSaved">恢复已保存</button>
      <button class="btn primary" :disabled="saving" @click="save">{{ saving ? '保存中…' : '保存配置' }}</button>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { toast } from '../../toast'
import {
  LEVELS, typeLabel,
  pushStore,
  normalizeRules
} from '../../utils/nodepush'
// 接口层: 规则 GET/PUT(字段映射见 api/nodepush.js 头部)
import { fetchRules, saveRules } from '../../api/nodepush'

const emit = defineEmits(['dirty', 'saved', 'change'])

// ===== 表单(初始=默认值; onMounted 拉后端配置覆盖) =====
const form = reactive(normalizeRules(null))
// 已保存快照 = 最近一次从后端成功加载/保存的配置; 表单 JSON 与快照不一致即为脏
const savedSnapshot = ref(JSON.stringify(form))
const dirty = computed(() => JSON.stringify(form) !== savedSnapshot.value)
watch(dirty, (d) => emit('dirty', d), { immediate: true })

// 加载失败保留当前(上次成功)配置, 只提示
async function load() {
  try {
    const r = normalizeRules(await fetchRules())   // GET /api/node/push/rules
    Object.assign(form, r)
    savedSnapshot.value = JSON.stringify(r)
  } catch (e) {
    toast('加载推送规则失败(保留当前配置): ' + e.message, 'err')
  }
}
onMounted(load)

// 目标列表来自共享 store(PushTargetList 增删后此处自动更新)
// 注意: 已选 id 里可能残留被删目标的 id, 渲染与计数以 targets 实际成员为准
const validTargetIds = computed(() =>
  form.targetIds.filter(id => pushStore.targets.some(t => t.id === id))
)

function selectAll() {
  form.targetIds = pushStore.targets.map(t => t.id)
}
function invertSelection() {
  form.targetIds = pushStore.targets
    .map(t => t.id)
    .filter(id => !form.targetIds.includes(id))
}

// ===== 校验(时间范围合法性 / 延迟范围) =====
const err = reactive({ delaySec: '', window: '', dnd: '' })

function validRange(start, end) {
  if (!start || !end) return '请完整填写时段的开始与结束时间'
  if (start === end) return '开始与结束时间不能相同'
  return ''
}

function validate() {
  err.delaySec = ''; err.window = ''; err.dnd = ''
  let ok = true
  if (!Number.isFinite(form.delaySec) || form.delaySec < 0 || form.delaySec > 3600) {
    err.delaySec = '延迟需在 0 - 3600 秒之间'
    ok = false
  }
  if (form.window === 'custom') {
    err.window = validRange(form.customStart, form.customEnd)
    if (err.window) ok = false
  }
  if (form.dnd) {
    err.dnd = validRange(form.dndStart, form.dndEnd)
    if (err.dnd) ok = false
  }
  return ok
}

// ===== 保存(后端 PUT, 失败保持脏状态可重试) =====
const saving = ref(false)
async function save() {
  if (!validate()) return
  saving.value = true
  const payload = {
    ...form,
    // 只持久化实际存在的有效目标 id(删目标后残留 id 不入库)
    targetIds: validTargetIds.value
  }
  try {
    await saveRules(payload)   // PUT /api/node/push/rules
    savedSnapshot.value = JSON.stringify(payload)
    saving.value = false
    emit('change')
    emit('saved')
    const note = !payload.levels.length ? '(当前未勾选任何级别, 实际不会推送)' : ''
    toast('推送规则已保存到后端' + note, note ? 'info' : 'ok')
  } catch (e) {
    saving.value = false
    toast('保存失败(修改仍保留在表单中): ' + e.message, 'err')
  }
}

// 恢复 = 重新拉取后端当前保存的配置(后端是唯一事实来源)
async function restoreSaved() {
  try {
    const r = normalizeRules(await fetchRules())
    Object.assign(form, r)
    savedSnapshot.value = JSON.stringify(r)
    toast('已恢复为后端当前保存的配置', 'info')
  } catch (e) {
    toast('恢复失败: ' + e.message, 'err')
  }
}

defineExpose({ dirty, save })
</script>

<style scoped>
.rule-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px 22px; }
.rule-f { margin-bottom: 0; }
@media (max-width: 1000px) { .rule-grid { grid-template-columns: 1fr; } }
.rule-checks { display: flex; gap: 14px; flex-wrap: wrap; }
.rule-radios { display: flex; flex-direction: column; gap: 7px; }
.rule-num { max-width: 130px; }
.form-err { color: var(--red); font-size: 12px; margin-top: 5px; }
.rule-target-head { display: flex; gap: 8px; margin-bottom: 8px; }
.rule-targets { display: flex; flex-direction: column; gap: 7px; max-height: 220px; overflow-y: auto; }
.t-item {
  border: 1px solid var(--border); border-radius: 8px;
  padding: 7px 10px; background: var(--panel2);
}
.t-item:hover { border-color: var(--border2); }
.t-chip { margin-left: auto; }
.rule-foot { align-items: center; }
</style>

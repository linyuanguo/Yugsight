<!--
  PushTargetList.vue 推送目标管理(2026-09-28, 告警日志管理 → 推送配置上半区)。

  后端对接(2026-09-28): 目标增删改查全部走 /api/node/push/target(s) 接口
  (api/nodepush.js), localStorage 本地存储已移除。加载失败时保留上次成功加载
  的列表(pushStore 只被成功响应覆盖)并 toast 提示。
  「测试」按钮: 前端触发 POST /api/node/push/test {targetId}, 后端真实发送一条
  测试告警并回执 {success, message}, 结果弹窗展示(成功绿/失败红+原因), 10s 超时。
  删除走二次确认弹窗(并级联清理推送规则中的关联);
  Webhook 列表中间脱敏, hover 看完整地址。
-->
<template>
  <div class="card">
    <div class="card-title">
      {{ t('pt.title') }}
      <span class="sub">{{ loading ? t('push.loading') : t('pt.cnt', { n: pushStore.targets.length }) }}</span>
      <div class="spacer"></div>
      <button class="btn primary xs" @click="openAdd">＋ {{ t('pt.add') }}</button>
    </div>

    <div v-if="!pushStore.targets.length" class="empty">
      <div class="big">＋</div>
      {{ t('pt.empty') }}
    </div>

    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th style="width:46px">{{ t('pt.cNo') }}</th>
            <th>{{ t('pt.cName') }}</th>
            <th>{{ t('pt.cType') }}</th>
            <th>Webhook</th>
            <th>{{ t('pt.cEnabled') }}</th>
            <th class="a-r" style="width:158px">{{ t('pt.cOp') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(tg, i) in pushStore.targets" :key="tg.id">
            <td class="muted mono">{{ i + 1 }}</td>
            <td>
              <div>{{ tg.name }}</div>
              <div class="muted small" v-if="tg.note">{{ tg.note }}</div>
            </td>
            <td><span class="badge">{{ t(typeLabel(tg.type)) }}</span></td>
            <td class="mono small" :title="tg.webhook">{{ maskWebhook(tg.webhook) }}</td>
            <td><span class="chip" :class="tg.enabled ? 'on' : 'off'">{{ tg.enabled ? t('pt.on') : t('pt.off') }}</span></td>
            <td class="a-r">
              <div class="row-actions">
                <button class="btn xs" @click="openEdit(tg)">{{ t('common.edit') }}</button>
                <button class="btn xs" :disabled="testingId === tg.id" @click="testTarget(tg)">
                  {{ testingId === tg.id ? t('pt.sending') : t('pt.test') }}
                </button>
                <button class="btn xs danger" @click="askDelete(tg)">{{ t('common.del') }}</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 新增/编辑弹窗 -->
    <Modal v-if="showModal" :title="editingId ? t('pt.editTitle') : t('pt.addTitle')" @close="closeModal">
      <div class="field">
        <label class="label">{{ t('pt.name') }} <span class="req">*</span></label>
        <input class="input" v-model="form.name" maxlength="20" :placeholder="t('pt.namePh')" />
        <div class="form-err" v-if="err.name">{{ err.name }}</div>
        <div class="muted small form-meta">{{ form.name.length }}/20</div>
      </div>
      <div class="field">
        <label class="label">{{ t('pt.type') }}</label>
        <select class="input" v-model="form.type">
          <option v-for="tp in PUSH_TYPES" :key="tp.key" :value="tp.key">{{ t(tp.label) }}</option>
        </select>
        <div class="muted small">{{ t('pt.typeNote') }}</div>
      </div>
      <div class="field">
        <label class="label">Webhook <span class="req">*</span></label>
        <input class="input mono" v-model="form.webhook"
               placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." />
        <div class="form-err" v-if="err.webhook">{{ err.webhook }}</div>
      </div>
      <div class="field">
        <label class="label">{{ t('pt.note') }}</label>
        <input class="input" v-model="form.note" :placeholder="t('pt.notePh')" />
      </div>
      <div class="field">
        <label class="label">{{ t('pt.enable') }}</label>
        <label class="checkbox">
          <input type="checkbox" v-model="form.enabled" />
          {{ t('pt.enableHint') }}
        </label>
      </div>
      <div class="form-actions">
        <button class="btn" @click="closeModal">{{ t('common.cancel') }}</button>
        <button class="btn primary" :disabled="saving" @click="save">{{ saving ? t('pt.saving') : t('common.save') }}</button>
      </div>
    </Modal>

    <!-- 删除二次确认弹窗 -->
    <Modal v-if="delTarget" :title="t('pt.delTitle')" width="420px" @close="delTarget = null">
      <p style="font-size:13.5px">{{ t('pt.delConfirm', { name: delTarget.name }) }}</p>
      <p class="muted small" style="margin-top:8px">{{ t('pt.delNote') }}</p>
      <div class="form-actions">
        <button class="btn" :disabled="deling" @click="delTarget = null">{{ t('common.cancel') }}</button>
        <button class="btn primary" :disabled="deling" @click="doDelete">{{ deling ? t('pt.deleting') : t('pt.doDel') }}</button>
      </div>
    </Modal>

    <!-- 测试推送结果弹窗: 成功绿色 / 失败红色+原因(后端真实发送回执) -->
    <Modal v-if="testResult" :title="t('pt.testTitle')" width="440px" @close="testResult = null">
      <div v-if="testResult.success" class="test-res ok">
        <div class="test-icon">✓</div>
        <div>
          <div class="test-title">{{ t('pt.testOk') }}</div>
          <div class="muted small">{{ t('pt.testOkHint', { name: testResult.name }) }}</div>
          <div class="muted small" v-if="testResult.message">{{ testResult.message }}</div>
        </div>
      </div>
      <div v-else class="test-res fail">
        <div class="test-icon">✕</div>
        <div>
          <div class="test-title">{{ t('pt.testFail') }}</div>
          <div class="test-reason">{{ testResult.message || t('pt.testUnknown') }}</div>
        </div>
      </div>
      <div class="form-actions">
        <div class="spacer"></div>
        <button class="btn primary" @click="testResult = null">{{ t('common.ok') }}</button>
      </div>
    </Modal>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import Modal from '../Modal.vue'
import { toast } from '../../toast'
import {
  pushStore,
  PUSH_TYPES, typeLabel, maskWebhook, isWebhookURL
} from '../../utils/nodepush'
// 接口层: 目标 CRUD + 测试推送 + 级联清理规则(见 api/nodepush.js 头部字段映射)
import {
  fetchTargets, createTarget, updateTarget, deleteTarget,
  fetchRules, saveRules, testPush
} from '../../api/nodepush'
import { t } from '../../i18n'

const emit = defineEmits(['change'])

// ===== 列表加载(成功才覆盖 pushStore → 网络异常时保留上次成功加载的配置) =====
const loading = ref(false)
async function load() {
  loading.value = true
  try {
    pushStore.targets = await fetchTargets()   // GET /api/node/push/targets
  } catch (e) {
    toast(t('pt.loadFail', { err: e.message }), 'err')
  } finally {
    loading.value = false
  }
}
onMounted(load)

// ===== 新增/编辑 =====
const showModal = ref(false)
const editingId = ref('')
const saving = ref(false)
const err = reactive({ name: '', webhook: '' })
const emptyForm = () => ({
  name: '', type: 'wecom', webhook: '', note: '', enabled: true
})
const form = reactive(emptyForm())

function openAdd() {
  editingId.value = ''
  Object.assign(form, emptyForm())
  err.name = ''; err.webhook = ''
  showModal.value = true
}
function openEdit(t) {
  editingId.value = t.id
  Object.assign(form, { name: t.name, type: t.type, webhook: t.webhook, note: t.note || '', enabled: !!t.enabled })
  err.name = ''; err.webhook = ''
  showModal.value = true
}
function closeModal() { showModal.value = false }

function save() {
  // 必填 + 格式校验(名称必填 ≤20 字符, Webhook 必须合法 http/https URL)
  const e = {}
  const name = form.name.trim()
  if (!name) e.name = t('pt.nameReq')
  else if (name.length > 20) e.name = t('pt.nameLen')
  if (!isWebhookURL(form.webhook.trim())) e.webhook = t('pt.webhookReq')
  err.name = e.name || ''; err.webhook = e.webhook || ''
  if (e.name || e.webhook) return

  saving.value = true
  // 字段映射: 表单 {name, type, webhook, note, enabled} → 接口 Target 同名字段
  const data = { name, type: form.type, webhook: form.webhook.trim(), note: form.note.trim(), enabled: form.enabled }
  const finish = () => {
    saving.value = false
    closeModal()
    emit('change')
    load()   // 重载拿后端生成的 id / createdAt(异步, 不阻塞弹窗关闭)
  }
  const fail = (e) => {
    saving.value = false
    toast(t('pt.saveFail', { err: e.message }), 'err')
  }
  if (editingId.value) {
    // PUT /api/node/push/target/{id}
    updateTarget(editingId.value, data).then(finish).catch(fail)
  } else {
    // POST /api/node/push/target
    createTarget(data).then(finish).catch(fail)
  }
}

// ===== 测试推送(前端触发, 后端真实发送并回执) =====
const testingId = ref('')
const testResult = ref(null)   // { name, success, message }
async function testTarget(tg) {
  if (!tg.enabled) {
    toast(t('pt.disabledHint', { name: tg.name }), 'info')
    return
  }
  testingId.value = tg.id
  try {
    // POST /api/node/push/test {targetId}; 10s 超时在 testPush 内处理,
    // 恒返回 {success, message}, 失败原因统一在结果弹窗红色展示
    const r = await testPush(tg.id)
    testResult.value = { name: tg.name, success: r.success, message: r.message }
  } finally {
    testingId.value = ''
  }
}

// ===== 删除(二次确认 + 级联清理规则关联) =====
const delTarget = ref(null)
const deling = ref(false)
function askDelete(tg) { delTarget.value = tg }
async function doDelete() {
  const tg = delTarget.value
  if (!tg || deling.value) return
  deling.value = true
  try {
    // DELETE /api/node/push/target/{id}
    await deleteTarget(tg.id)
    delTarget.value = null
    emit('change')
    toast(t('pt.deleted'), 'info')
    load()
    // 级联清理: 推送规则里对该目标的关联一并清除(删除弹窗已承诺此行为)。
    // 尽力而为: 失败只提示不阻断 —— 残留 id 无害(规则页按实际目标过滤展示,
    // 下次保存规则时 payload 只含有效 id, 自然清除)。
    try {
      const r = await fetchRules()
      if ((r.targetIds || []).includes(tg.id)) {
        await saveRules({ ...r, targetIds: r.targetIds.filter(id => id !== tg.id) })
      }
    } catch (e) {
      toast(t('pt.delCleanFail'), 'info')
    }
  } catch (e) {
    toast(t('pt.delFail', { err: e.message }), 'err')
  } finally {
    deling.value = false
  }
}
</script>

<style scoped>
.req { color: var(--red); }
.form-err { color: var(--red); font-size: 12px; margin-top: 4px; }
.form-meta { margin-top: 3px; text-align: right; }

/* 测试推送结果弹窗(成功绿 / 失败红+原因) */
.test-res { display: flex; gap: 12px; align-items: flex-start; }
.test-icon {
  flex: none; width: 34px; height: 34px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 17px; font-weight: 700;
}
.test-res.ok .test-icon { background: rgba(34,197,94,.15); color: var(--green); }
.test-res.fail .test-icon { background: rgba(239,68,68,.15); color: var(--red); }
.test-title { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
.test-res.ok .test-title { color: var(--green); }
.test-res.fail .test-title { color: var(--red); }
.test-reason {
  color: var(--red); font-size: 12.5px; background: rgba(239,68,68,.08);
  border: 1px solid rgba(239,68,68,.25); border-radius: 6px;
  padding: 6px 8px; word-break: break-all;
}
</style>

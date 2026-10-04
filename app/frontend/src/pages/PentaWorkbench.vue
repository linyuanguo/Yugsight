<template>
  <div>
    <PageHeader :title="t('pw.title')" :desc="t('pw.desc')">
      <span class="chip" :class="st.enabled ? 'on' : 'off'">{{ st.enabled ? t('pw.on') : t('pw.off') }}</span>
      <span class="chip">{{ t('pw.tplCount', { b: st.builtinCount || 0, c: st.customCount || 0, n: total }) }}</span>
      <button class="btn sm" @click="refreshAll"><span class="spinner" v-if="loading"></span> {{ t('common.refresh') }}</button>
    </PageHeader>

    <!-- 安全声明: 常驻不可关闭。攻击性能力的边界写在最显眼处, 而不是埋在文档里 -->
    <div class="card" style="border-left:3px solid var(--danger,#e5484d); margin-bottom:12px">
      <div class="card-title">{{ t('pw.statementTitle') }}</div>
      <p class="muted small" style="margin:0; line-height:1.7">{{ st.statement || statementFallback }}</p>
    </div>

    <div class="tabs">
      <div class="tab" :class="{ active: tab === 'task' }" @click="tab = 'task'">{{ t('pw.tabTask') }}</div>
      <div class="tab" :class="{ active: tab === 'run' }" @click="switchTab('run')">{{ t('pw.tabRun') }}</div>
      <div class="tab" :class="{ active: tab === 'result' }" @click="switchTab('result')">{{ t('pw.tabResult') }}</div>
      <div class="tab" :class="{ active: tab === 'audit' }" @click="switchTab('audit')">
        {{ t('pw.tabAudit') }}
        <span class="muted small" v-if="paTotal > 0">{{ t('pw.itemsN', { n: paTotal }) }}</span>
      </div>
    </div>

    <!-- ==================== Tab1 渗透任务管理 ==================== -->
    <div v-if="tab === 'task'">
      <div class="card">
        <div class="card-title">
          {{ t('pw.taskList') }}
          <span class="sub">{{ t('pw.taskListSub') }}</span>
          <div class="spacer"></div>
          <button class="btn sm primary" @click="showNew = !showNew">{{ showNew ? t('pw.collapseNew') : t('pw.newTask') }}</button>
          <button class="btn sm" @click="openImport">{{ t('pw.importVuln') }}</button>
        </div>

        <div class="form-row" style="margin-bottom:10px">
          <!-- 2026-10-02 用户口径: 筛选选项基于当前数据里存在的 —— 状态/风险等级选项
               由后端按全量任务聚合回带(statuses/risks), 无数据的选项不出现 -->
          <div class="field" style="max-width:150px">
            <label class="label">{{ t('pw.status') }}</label>
            <select class="input" v-model="filt.status">
              <option value="">{{ t('common.all') }}</option>
              <option v-for="s in pentaStatusOpts" :key="s.id" :value="s.id">{{ statusName(s.id) }} ({{ s.count }})</option>
            </select>
          </div>
          <div class="field" style="max-width:150px">
            <label class="label">{{ t('pw.risk') }}</label>
            <select class="input" v-model="filt.risk">
              <option value="">{{ t('common.all') }}</option>
              <option v-for="s in pentaRiskOpts" :key="s.id" :value="s.id">{{ riskName(s.id) }} ({{ s.count }})</option>
            </select>
          </div>
          <div class="field" style="max-width:220px">
            <label class="label">{{ t('pw.target') }}</label>
            <input class="input mono" v-model.trim="filt.target" :placeholder="phTarget">
          </div>
          <div class="spacer"></div>
          <button class="btn sm" @click="loadTasks">{{ t('common.query') }}</button>
          <button class="btn sm" @click="resetFilter">{{ t('common.reset') }}</button>
        </div>

        <!-- 新建任务(折叠区) -->
        <div v-if="showNew" class="panel-dashed">
          <div class="form-row" style="flex-wrap:wrap; align-items:flex-end; gap:10px">
            <div class="field" style="max-width:180px">
              <label class="label">{{ t('pw.fTarget') }}</label>
              <input class="input mono" v-model.trim="nf.target" placeholder="10.0.0.5">
            </div>
            <div class="field" style="max-width:110px">
              <label class="label">{{ t('pw.fPort') }}</label>
              <input class="input mono" type="number" v-model.number="nf.port" placeholder="6379">
            </div>
            <div class="field" style="max-width:130px">
              <label class="label">{{ t('pw.fProtocol') }}</label>
              <select class="input" v-model="nf.protocol">
                <option value="tcp">tcp</option>
                <option value="http">http</option>
                <option value="https">https</option>
                <option value="redis">redis</option>
              </select>
            </div>
            <div class="field" style="max-width:170px">
              <label class="label">{{ t('pw.fCve') }}</label>
              <input class="input mono" v-model.trim="nf.cve" placeholder="CVE-2022-0543">
            </div>
            <div class="field" style="max-width:220px">
              <label class="label">{{ t('pw.fTitle') }}</label>
              <input class="input" v-model.trim="nf.title" :placeholder="t('pw.phTitle')">
            </div>
            <div class="field" style="max-width:210px">
              <label class="label">{{ t('pw.fTpl') }}</label>
              <select class="input" v-model="nf.templateId">
                <option value="">{{ t('pw.tplUnset') }}</option>
                <option v-for="tp in allTemplates" :key="tp.id" :value="tp.id">{{ tp.name }}（{{ tp.id }}）</option>
              </select>
            </div>
            <!-- 2026-09-25 命名扫描: 关联扫描任务名(可选)。控制台"下一步渗透"会
                 预填它; 手动建任务时填了, 报告中心"按任务名生成报告"能带上该任务 -->
            <div class="field" style="max-width:190px">
              <label class="label">{{ t('pw.fJob') }}</label>
              <input class="input" v-model.trim="nf.job" :placeholder="t('pw.phJob')">
            </div>
            <div class="field" style="max-width:150px">
              <label class="label">{{ t('pw.fSeverity') }}</label>
              <select class="input" v-model="nf.severity">
                <option value="">{{ t('pw.unrated') }}</option>
                <option value="critical">{{ t('sev.critical') }}</option>
                <option value="high">{{ t('sev.high') }}</option>
                <option value="medium">{{ t('sev.medium') }}</option>
                <option value="low">{{ t('sev.low') }}</option>
              </select>
            </div>
            <div class="spacer"></div>
            <button class="btn primary" :disabled="!nf.target" @click="createTask">{{ t('pw.createTask') }}</button>
          </div>
        </div>

        <!-- 批量操作条: 选中才出现, 避免"无选中时按钮可点但什么都不做" -->
        <div class="form-row" v-if="selCount" style="margin:10px 0 8px">
          <span class="chip warn">{{ t('pw.selN', { n: selCount }) }}</span>
          <button class="btn sm danger" @click="batchDelete">{{ t('pw.batchDel') }}</button>
          <button class="btn sm" @click="exportTasks">{{ t('pw.batchExport') }}</button>
          <button class="btn sm" @click="clearSel">{{ t('pw.clearSel') }}</button>
        </div>

        <div class="table-wrap" v-if="tasks.length">
          <table class="table">
            <thead>
              <tr>
                <th style="width:36px"><input type="checkbox" :checked="allChecked" @change="toggleAll"></th>
                <th>{{ t('pw.cTask') }}</th><th style="width:150px">{{ t('pw.cTarget') }}</th>
                <th style="width:150px">CVE</th><th style="width:80px">{{ t('pw.cRisk') }}</th>
                <th style="width:80px">{{ t('pw.cStatus') }}</th><th style="width:90px">{{ t('pw.cConclusion') }}</th>
                <th style="width:150px">{{ t('pw.cLastRun') }}</th><th style="width:180px">{{ t('pw.cOps') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="tk in tasks" :key="tk.id">
                <td><input type="checkbox" v-model="checked[tk.id]"></td>
                <td>
                  <div>{{ tk.title || t('pw.defaultTitle') }}</div>
                  <div class="muted small mono">{{ tk.id }}</div>
                </td>
                <td class="mono">{{ tk.target }}<span class="muted">:{{ tk.port || '-' }}</span></td>
                <td class="mono small">{{ tk.cve || '-' }}</td>
                <td><SevTag :sev="tk.riskLevel || 'info'" /></td>
                <td><span class="badge">{{ statusName(tk.status) }}</span></td>
                <td>
                  <span v-if="tk.exploitability" class="badge" :style="expStyle(tk.exploitability)">{{ expName(tk.exploitability) }}</span>
                  <span v-else class="muted small">{{ t('pw.unverified') }}</span>
                </td>
                <td class="mono small muted">{{ tk.finishedAt ? fmtDT(tk.finishedAt) : '-' }}</td>
                <td>
                  <button class="btn xs" @click="gotoRun(tk)">{{ t('pw.runBtn') }}</button>
                  <button class="btn xs" @click="gotoResult(tk)">{{ t('pw.resultBtn') }}</button>
                  <button class="btn xs danger" @click="delTask(tk)">{{ t('common.del') }}</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="tasksLoaded ? t('pw.emptyTasks') : t('common.loading')" />
        <div class="err-line" style="color:var(--danger,#e5484d)">{{ listErr }}</div>
      </div>
    </div>

    <!-- ==================== Tab2 渗透执行控制台 ==================== -->
    <div v-if="tab === 'run'">
      <div class="penta-grid">
        <div>
          <div class="card">
            <div class="card-title">{{ t('pw.pickTask') }}<span class="sub">{{ t('pw.pickTaskSub') }}</span></div>
            <select class="input mono" v-model="runTaskId">
              <option value="">{{ t('pw.phPickTask') }}</option>
              <option v-for="t in tasks" :key="t.id" :value="t.id">
                {{ t.target }}:{{ t.port || '-' }} · {{ t.title || t.cve || t.id }}
              </option>
            </select>
            <div v-if="curTask" class="kv-list" style="margin-top:10px">
              <div><span class="k">{{ t('pw.target') }}</span><span class="v mono">{{ curTask.target }}:{{ curTask.port || '-' }}（{{ curTask.protocol || 'tcp' }}）</span></div>
              <div><span class="k">{{ t('pw.kvObject') }}</span><span class="v">{{ curTask.title || '-' }}</span></div>
              <div><span class="k">CVE</span><span class="v mono">{{ curTask.cve || '-' }}</span></div>
              <div><span class="k">{{ t('pw.kvSource') }}</span><span class="v">{{ curTask.source === 'vuln' ? t('pw.srcVuln') : t('pw.srcManual') }}</span></div>
            </div>
          </div>

          <!-- EXP 模板库 -->
          <div class="card">
            <div class="card-title">
              {{ t('pw.tplLib') }}
              <span class="sub">{{ t('pw.tplLibCount', { b: (tpls.builtin || []).length, c: (tpls.custom || []).length }) }}</span>
              <div class="spacer"></div>
              <button class="btn xs" @click="showTplImport = true">{{ t('pw.importTpl') }}</button>
            </div>
            <div class="form-row" style="margin-bottom:8px">
              <input class="input" v-model.trim="tplQ" :placeholder="t('pw.phTplSearch')">
              <div class="spacer"></div>
              <select class="input" style="max-width:140px" v-model="tplTag">
                <option value="">{{ t('pw.allTags') }}</option>
                <option v-for="g in (tpls.tags || [])" :key="g" :value="g">{{ g }}</option>
              </select>
            </div>
            <div class="tpl-list">
              <div
                class="tpl-item" v-for="tp in filteredTpls" :key="tp.id"
                :class="{ active: runTplId === tp.id }" @click="pickTpl(tp)"
              >
                <div class="tpl-head">
                  <b>{{ tp.name }}</b>
                  <span class="badge blue mono">{{ tp.id }}</span>
                  <span class="badge" v-if="tp.builtIn">{{ t('pw.builtin') }}</span>
                  <span class="badge warn" v-else>{{ t('pw.custom') }}</span>
                </div>
                <div class="muted small" v-if="tp.desc">{{ tp.desc }}</div>
                <div class="tpl-meta">
                  <span class="badge blue mono" v-if="tp.cve">{{ tp.cve }}</span>
                  <span class="badge" v-for="g in (tp.tags || [])" :key="g">{{ g }}</span>
                  <span class="muted small">{{ t('pw.stepsN', { n: (tp.steps || []).length }) }}</span>
                </div>
                <!-- 选中后展开"即将执行什么": 执行前必须让用户看见具体动作, 不是黑盒点按钮 -->
                <div v-if="runTplId === tp.id && (tp.steps || []).length" class="tpl-steps">
                  <div class="mono small" v-for="(s, i) in tp.steps" :key="i">
                    {{ i + 1 }}. [{{ s.type }}] {{ s.name }}{{ s.path ? ' ' + s.path : '' }}{{ s.service ? ' ' + s.service : '' }}
                  </div>
                  <div class="muted small" v-if="tp.note">{{ t('pw.note', { x: tp.note }) }}</div>
                </div>
              </div>
              <Empty v-if="!filteredTpls.length" :text="t('pw.emptyTpls')" />
            </div>
          </div>
        </div>

        <div>
          <div class="card">
            <div class="card-title">{{ t('pw.runParams') }}</div>
            <div v-if="wpStep" class="form-row" style="flex-wrap:wrap; gap:10px">
              <div class="field" style="max-width:130px">
                <label class="label">{{ t('pw.fService') }}</label>
                <input class="input mono" disabled :value="wpStep.service || '-'">
              </div>
              <div class="field" style="max-width:150px">
                <label class="label">{{ t('pw.fUser') }}</label>
                <input class="input mono" v-model.trim="wpUser" placeholder="admin">
              </div>
              <div class="field" style="max-width:100%">
                <label class="label">{{ t('pw.fPasswords') }}</label>
                <textarea class="input mono" rows="3" v-model="wpPasswords"></textarea>
              </div>
            </div>
            <div v-else class="muted small" style="margin-bottom:8px">
              {{ t('pw.noWpStep') }}
            </div>

            <!-- 逐次授权确认: 不写进 localStorage, 刷新即失效 —— 攻击动作不能"一次勾选永久有效" -->
            <label class="ack-line" :class="{ on: ack }">
              <input type="checkbox" v-model="ack">
              <span>{{ t('pw.ackText') }}</span>
            </label>

            <div class="form-row">
              <div class="spacer"></div>
              <button class="btn danger" :disabled="running || !runTaskId || !runTplId" @click="execTask">
                {{ running ? t('pw.running') : t('pw.execVerify') }}
              </button>
            </div>
            <div class="err-line" style="color:var(--danger,#e5484d)">{{ runErr }}</div>
          </div>

          <div class="card">
            <div class="card-title">
              {{ t('pw.liveLog') }}
              <span class="chip warn" v-if="running">{{ t('pw.chipRunning') }}</span>
              <span class="chip" :class="outcome && outcome.ok ? 'on' : 'warn'" v-else-if="outcome">
                {{ outcome.ok ? t('pw.done') : t('pw.noConclusion') }}
              </span>
              <div class="spacer"></div>
              <!-- 2026-09-25 起移除"复制日志"按钮: 内网 IP(http 非安全上下文)下
                   navigator.clipboard 恒被浏览器拒绝, 按钮点了只会报错;
                   日志区文本可直接选中复制 -->
            </div>
            <div v-if="outcome" class="result-brief">
              <div class="muted small">{{ outcome.summary || '-' }}</div>
              <div class="step-list" v-if="(outcome.steps || []).length">
                <div class="step-row" v-for="(s, i) in outcome.steps" :key="i">
                  <span class="badge" :class="s.hit ? 'badge-ok' : ''">{{ s.name }}</span>
                  <span class="muted small mono">{{ s.type }}</span>
                  <span class="badge" :class="s.hit ? 'badge-ok' : ''">{{ s.hit ? t('pw.hit') : t('pw.miss') }}</span>
                  <span class="mono small muted">{{ s.durationMs }}ms</span>
                  <div class="small" v-if="s.hit && s.risk" style="width:100%; color:var(--warn,#d97706)">{{ s.risk }}</div>
                </div>
              </div>
            </div>
            <pre class="penta-console" ref="consoleEl">{{ logText }}</pre>
          </div>
        </div>
      </div>
    </div>

    <!-- ==================== Tab3 渗透结果管理 ==================== -->
    <div v-if="tab === 'result'">
      <div class="card">
        <div class="card-title">
          {{ t('pw.tabResult') }}
          <span class="sub">{{ t('pw.resultSub') }}</span>
          <div class="spacer"></div>
          <span class="chip">{{ t('pw.verifiedN', { a: verifiedCount, b: resultTasks.length }) }}</span>
        </div>

        <div class="table-wrap" v-if="resultTasks.length">
          <table class="table">
            <thead>
              <tr>
                <th>{{ t('pw.cTargetObject') }}</th><th style="width:130px">{{ t('pw.cConclusion') }}</th><th style="width:140px">{{ t('pw.cRiskAdj') }}</th>
                <th>{{ t('pw.cSummary') }}</th><th style="width:120px">{{ t('pw.cFeedback') }}</th><th style="width:170px">{{ t('pw.cOps') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="rt in resultTasks" :key="rt.id">
                <td>
                  <div>{{ rt.title || t('pw.defaultTitle') }}</div>
                  <div class="muted small mono">{{ rt.target }}:{{ rt.port || '-' }}{{ rt.cve ? ' · ' + rt.cve : '' }}</div>
                </td>
                <td>
                  <select class="input" v-model="edit[rt.id].exploitability">
                    <option value="exploitable">{{ t('pw.expExploitable') }}</option>
                    <option value="partial">{{ t('pw.expPartial') }}</option>
                    <option value="not_exploitable">{{ t('pw.expNo') }}</option>
                  </select>
                </td>
                <td>
                  <select class="input" v-model="edit[rt.id].riskLevel">
                    <option value="">{{ t('pw.keepRisk') }}</option>
                    <option value="critical">{{ t('sev.critical') }}</option>
                    <option value="high">{{ t('sev.high') }}</option>
                    <option value="medium">{{ t('sev.medium') }}</option>
                    <option value="low">{{ t('sev.low') }}</option>
                    <option value="info">{{ t('sev.info') }}</option>
                  </select>
                </td>
                <td>
                  <input class="input" v-model="edit[rt.id].summary" :placeholder="t('pw.phSummary')">
                </td>
                <td>
                  <span class="badge badge-ok" v-if="rt.feedbackAt">{{ t('pw.feedbackDone') }}</span>
                  <span class="muted small" v-else-if="!rt.vulnId">{{ t('pw.noVuln') }}</span>
                  <span class="muted small" v-else>{{ t('pw.feedbackPending') }}</span>
                  <div class="muted small mono" v-if="rt.feedbackAt">{{ fmtDT(rt.feedbackAt) }}</div>
                </td>
                <td>
                  <button class="btn xs" @click="saveResult(rt)">{{ t('common.save') }}</button>
                  <button class="btn xs primary" :disabled="!rt.vulnId" @click="feedback(rt)">{{ t('pw.feedback') }}</button>
                  <button class="btn xs" @click="toggleEvidence(rt.id)">{{ expanded[rt.id] ? t('pw.evidenceHide') : t('pw.evidence') }}</button>
                </td>
              </tr>
              <tr v-if="expanded[rt.id]">
                <td colspan="6" style="background:rgba(255,255,255,.02)">
                  <div v-if="(rt.evidence || []).length">
                    <div class="muted small" style="margin-bottom:6px">{{ t('pw.evidenceNote') }}</div>
                    <div class="ev-block" v-for="(s, i) in rt.evidence" :key="i">
                      <div class="ev-head">
                        <span class="badge" :class="s.hit ? 'badge-ok' : ''">{{ s.name }}</span>
                        <span class="muted small mono">{{ s.type }} · {{ s.durationMs }}ms · {{ s.hit ? t('pw.hit') : t('pw.miss') }}</span>
                      </div>
                      <pre class="ev-body">{{ s.evidence || '-' }}</pre>
                    </div>
                  </div>
                  <div v-else class="muted small">{{ t('pw.noEvidence') }}</div>
                  <div v-if="rt.runLog" class="ev-block" style="margin-top:8px">
                    <div class="ev-head"><span class="badge blue">{{ t('pw.runLog') }}</span></div>
                    <pre class="ev-body">{{ rt.runLog }}</pre>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="t('pw.emptyResults')" />
        <div class="err-line" style="color:var(--danger,#e5484d)">{{ resErr }}</div>
      </div>
    </div>

    <!-- ==================== Tab4 渗透审计 ==================== -->
    <!-- 独立于通用审计(授权管理→审计日志): 渗透命令全程留痕。
         清空仅 admin(整页 admin 专属), 且后端清空后写 penta.audit.clear
         痕迹(谁/何时/清了几条) —— 记录可清(分发/数据交接场景), "被清过"
         永远查得到, 与通用审计"清空留痕"口径一致。 -->
    <div v-if="tab === 'audit'">
      <div class="card">
        <div class="card-title">
          {{ t('pw.tabAudit') }}
          <span class="sub">{{ t('pw.auditSub') }}</span>
          <div class="spacer"></div>
          <span class="chip" v-if="paTotal > 0">{{ t('pw.totalItems', { n: paTotal }) }}</span>
          <button class="btn xs danger" :disabled="!paTotal" @click="openClearAudit"
                  :title="paTotal ? t('pw.clearAuditTip', { w: t('pw.clearWord') }) : t('pw.clearAuditEmpty')">{{ t('pw.clearAudit') }}</button>
        </div>

        <div class="form-row" style="flex-wrap:wrap">
          <select class="input" v-model="paFlt.action" style="width:180px">
            <option value="">{{ t('pw.allActions') }}</option>
            <option v-for="a in paActions" :key="a" :value="a">{{ a }}</option>
          </select>
          <input class="input" v-model.trim="paFlt.keyword" :placeholder="t('pw.phKeyword')" style="width:200px" />
          <input class="input" type="date" v-model="paFlt.from" style="width:140px" />
          <input class="input" type="date" v-model="paFlt.to" style="width:140px" />
          <button class="btn" @click="paApplyFilter">{{ t('pw.filter') }}</button>
          <button class="btn" @click="paResetFilter">{{ t('common.reset') }}</button>
        </div>

        <div class="table-wrap" v-if="pentaAudits.length">
          <table class="table">
            <thead>
              <tr>
                <th>{{ t('pw.cTime') }}</th><th>{{ t('common.user') }}</th><th>{{ t('pw.cAction') }}</th><th>{{ t('pw.cObject') }}</th><th>{{ t('pw.cDetail') }}</th><th>{{ t('pw.cClientIp') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="a in pentaAudits" :key="a.id">
                <td class="mono small">{{ fmtDT(a.createdAt) }}</td>
                <td class="small">{{ a.userId || '-' }}</td>
                <td class="mono small">{{ a.action }}</td>
                <td class="small" :title="a.target">{{ a.target || '-' }}</td>
                <td class="small muted" :title="a.detail">{{ a.detail || '-' }}</td>
                <td class="mono small">{{ a.clientIp || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="t('pw.emptyAudit')" />

        <!-- 分页 -->
        <div class="form-row" v-if="paTotal > PA_SIZE" style="justify-content:flex-end">
          <button class="btn xs" :disabled="paPage <= 1" @click="paGotoPage(paPage - 1)">{{ t('al.prev') }}</button>
          <span class="muted small">{{ paPage }} / {{ paTotalPages }}</span>
          <button class="btn xs" :disabled="paPage >= paTotalPages" @click="paGotoPage(paPage + 1)">{{ t('al.next') }}</button>
        </div>
      </div>
    </div>

    <!-- 从漏扫管控导入 -->
    <Modal v-if="showImport" :title="t('pw.importTitle')" width="860px" @close="showImport = false">
      <div class="form-row" style="margin-bottom:8px">
        <input class="input" v-model.trim="vulnQ" :placeholder="t('pw.phVulnFilter')">
        <div class="spacer"></div>
        <span class="chip">{{ t('pw.selN', { n: Object.values(vulnSel).filter(Boolean).length }) }}</span>
      </div>
      <div class="table-wrap" style="max-height:420px; overflow:auto">
        <table class="table">
          <thead>
            <tr><th style="width:36px"></th><th>{{ t('pw.cVuln') }}</th><th style="width:130px">{{ t('pw.cAsset') }}</th><th style="width:70px">{{ t('pw.cPort') }}</th><th style="width:80px">{{ t('pw.cSev') }}</th><th style="width:90px">{{ t('pw.cVerified') }}</th></tr>
          </thead>
          <tbody>
            <tr v-for="v in filteredVulns" :key="v.id">
              <td><input type="checkbox" v-model="vulnSel[v.id]"></td>
              <td>
                <div>{{ v.title }}</div>
                <div class="muted small mono">{{ v.cve || v.id }}</div>
              </td>
              <td class="mono">{{ v.assetIp }}</td>
              <td class="mono">{{ v.port || '-' }}</td>
              <td><SevTag :sev="v.severity" /></td>
              <td>
                <span v-if="v.pentaResult" class="badge" :style="expStyle(v.pentaResult)">{{ expName(v.pentaResult) }}</span>
                <span v-else class="muted small">{{ t('pw.unverified') }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <template #footer>
        <div class="spacer"></div>
        <button class="btn sm" @click="showImport = false">{{ t('common.cancel') }}</button>
        <button class="btn sm primary" :disabled="importing" @click="doImport">
          {{ importing ? t('pw.importing') : t('pw.importBtn') }}
        </button>
      </template>
    </Modal>

    <!-- 导入自定义 EXP -->
    <Modal v-if="showTplImport" :title="t('pw.tplImportTitle')" width="720px" @close="showTplImport = false">
      <p class="muted small" style="margin-top:0">
        {{ t('pw.tplImportNote') }}
      </p>
      <textarea class="input mono" rows="16" spellcheck="false" v-model="tplText" :placeholder="phTpl"></textarea>
      <div class="err-line" style="color:var(--danger,#e5484d)">{{ tplErr }}</div>
      <template #footer>
        <div class="spacer"></div>
        <button class="btn sm" @click="showTplImport = false">{{ t('common.cancel') }}</button>
        <button class="btn sm primary" :disabled="!tplText.trim()" @click="doImportTpl">{{ t('pw.import') }}</button>
      </template>
    </Modal>

    <!-- 清空渗透审计: 输入"清空"确认(与"清空全部漏洞"同口径)。
         清空后列表只剩后端写的 penta.audit.clear 痕迹(清空动作本身可审计) -->
    <Modal v-if="showClearAudit" :title="t('pw.clearAuditTitle')" width="480px" @close="showClearAudit = false">
      <p class="muted small" style="margin:0 0 12px">
        {{ t('pw.clearAuditNote1') }}
        <b class="mono">penta.audit.clear</b> {{ t('pw.clearAuditNote2') }}
      </p>
      <div class="field">
        <label class="lbl">{{ t('pw.clearWordPre') }} <b>{{ t('pw.clearWord') }}</b> {{ t('pw.clearWordPost') }}</label>
        <input class="input" v-model.trim="clearAuditWord" :placeholder="t('pw.clearWord')" />
      </div>
      <template #footer>
        <div class="spacer"></div>
        <button class="btn sm" @click="showClearAudit = false">{{ t('common.cancel') }}</button>
        <button class="btn sm danger" :disabled="clearAuditWord !== t('pw.clearWord') || clearAuditBusy" @click="doClearAudit">
          {{ clearAuditBusy ? t('pw.clearing') : t('pw.clearWord') }}
        </button>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import Empty from '../components/Empty.vue'
import Modal from '../components/Modal.vue'
import SevTag from '../components/SevTag.vue'
import { v2 } from '../api/http'
import { fmtDT } from '../utils'
import { t } from '../i18n'

const route = useRoute()

// 文案常量: Vue 模板里出现字面量占位符会被当插值解析(编译报
// "Unterminated string constant"), 所有示例文本一律经 JS 常量传 :placeholder。
const phTarget = '10.0.0.5'
// 示例模板文本走 i18n: 用 computed 保证切换语言后 placeholder 跟随更新
const phTpl = computed(() => [
  'id: my-check',
  'name: ' + t('pw.tplExName'),
  'cve: CVE-2025-0001',
  'tags: [http, custom]',
  'desc: ' + t('pw.tplExDesc'),
  'steps:',
  '  - name: ' + t('pw.tplExStep1'),
  '    type: http',
  '    path: /admin/login',
  '    expectStatus: 200',
  '    expectBody: "login|password"',
  '  - name: ' + t('pw.tplExStep2'),
  '    type: tcp',
  '    send: "PING\\r\\n"',
  '    expect: "\\\\+PONG"'
].join('\n'))

// 服务名 -> 中文(弱口令检测页深链过来时用于生成任务标题)
const serviceNames = { redis: 'Redis', mysql: 'MySQL', ftp: 'FTP', telnet: 'Telnet', ssh: 'SSH', vnc: 'VNC', rdp: 'RDP', smb: 'SMB' }

// statementFallback 后端未返回声明文案时的兜底(与后端 pentaStatement 同口径, 走 i18n)。
const statementFallback = computed(() => t('pw.statementFallback'))

const tab = ref('task')
const loading = ref(false)
const st = ref({})
const tasks = ref([])
const total = ref(0)
const tasksLoaded = ref(false)
const listErr = ref('')
const resErr = ref('')
const runErr = ref('')
const showNew = ref(false)
const filt = reactive({ status: '', risk: '', target: '' })
const checked = reactive({})
// job: 关联的扫描任务名(2026-09-25 命名扫描: 控制台"下一步渗透"批量建任务时
// 带上, 报告中心"按任务名生成报告"的渗透章节按它过滤; 空 = 独立渗透任务)
const nf = reactive({ target: '', port: 0, protocol: 'tcp', cve: '', title: '', templateId: '', severity: '', job: '' })

const tpls = ref({})
const tplTag = ref('')
const tplQ = ref('')
const runTaskId = ref('')
const runTplId = ref('')
const ack = ref(false)
const wpUser = ref('')
const wpPasswords = ref('')
const running = ref(false)
const lines = ref([])
const outcome = ref(null)
const consoleEl = ref(null)

const resultTasks = ref([])
const edit = reactive({})
const expanded = reactive({})

const showImport = ref(false)
const vulns = ref([])
const vulnQ = ref('')
const vulnSel = reactive({})
const importing = ref(false)

const showTplImport = ref(false)
const tplText = ref('')
const tplErr = ref('')

let sseAbort = null

const allTemplates = computed(() => [...(tpls.value.builtin || []), ...(tpls.value.custom || [])])
const curTask = computed(() => tasks.value.find((t) => t.id === runTaskId.value) || null)
const curTpl = computed(() => allTemplates.value.find((t) => t.id === runTplId.value) || null)
// 弱口令步骤: 有才展示账号/口令输入, 避免对所有模板都摆一堆用不上的输入框
const wpStep = computed(() => ((curTpl.value && curTpl.value.steps) || []).find((s) => s.type === 'weakpass') || null)
const allChecked = computed(() => tasks.value.length > 0 && tasks.value.every((t) => checked[t.id]))
const selCount = computed(() => Object.values(checked).filter(Boolean).length)
const logText = computed(() => lines.value.join('\n') || t('pw.logEmpty'))
const verifiedCount = computed(() => resultTasks.value.filter((t) => t.exploitability).length)

// ===== 渗透审计(独立表 penta_audit) =====
// 与通用审计(授权管理页)分离: 渗透命令的合规留痕不进"可清空"的池子。
// 清空入口仅 admin(整页 admin 专属, 后端 adminOnly 双保险), 后端清空后
// 写 penta.audit.clear 痕迹 —— 清空动作本身可审计, 不是无痕擦除。
const PA_SIZE = 50
const pentaAudits = ref([])
const paTotal = ref(0)
const paPage = ref(1)
const paFlt = ref({ action: '', keyword: '', from: '', to: '' })
const paActions = ref([]) // 动作下拉(全记录 distinct, 首次切入取一次)
const paTotalPages = computed(() => Math.max(1, Math.ceil(paTotal.value / PA_SIZE)))

async function loadPentaAudit() {
  const q = new URLSearchParams()
  q.set('page', String(paPage.value))
  q.set('size', String(PA_SIZE))
  if (paFlt.value.action) q.set('action', paFlt.value.action)
  if (paFlt.value.keyword) q.set('keyword', paFlt.value.keyword)
  if (paFlt.value.from) q.set('from', paFlt.value.from)
  if (paFlt.value.to) q.set('to', paFlt.value.to)
  try {
    const r = await v2('/penta/audit?' + q.toString())
    pentaAudits.value = r.list || []
    paTotal.value = r.total || 0
  } catch (e) {
    listErr.value = e.message
  }
}

function loadPentaAuditActions() {
  // 动作下拉: 全记录 distinct(一次取完, 与通用审计页同口径)
  v2('/penta/audit?size=5000')
    .then((r) => {
      const s = new Set((r.list || []).map((a) => a.action))
      paActions.value = Array.from(s).sort()
    })
    .catch(() => { /* 下拉可空, 不影响主体 */ })
}

function paApplyFilter() { paPage.value = 1; loadPentaAudit() }
function paResetFilter() {
  paFlt.value = { action: '', keyword: '', from: '', to: '' }
  paPage.value = 1
  loadPentaAudit()
}
function paGotoPage(p) { paPage.value = p; loadPentaAudit() }

// 清空渗透审计: 输入"清空"二次确认(与"清空全部漏洞"同口径); 清完列表只剩
// 后端写的那条 penta.audit.clear 痕迹(清空动作本身留痕)
const showClearAudit = ref(false)
const clearAuditWord = ref('')
const clearAuditBusy = ref(false)
function openClearAudit() {
  clearAuditWord.value = ''
  showClearAudit.value = true
}
async function doClearAudit() {
  if (clearAuditWord.value !== t('pw.clearWord')) return
  clearAuditBusy.value = true
  try {
    const d = await v2('/penta/audit', { method: 'DELETE' })
    showClearAudit.value = false
    paFlt.value = { action: '', keyword: '', from: '', to: '' }
    paPage.value = 1
    await loadPentaAudit()
    loadPentaAuditActions()
    alert(t('pw.auditCleared', { n: (d && d.deleted) || 0 }))
  } catch (e) {
    alert(e.message)
  } finally {
    clearAuditBusy.value = false
  }
}

const filteredTpls = computed(() => {
  const q = tplQ.value.trim().toLowerCase()
  return allTemplates.value.filter((t) => {
    if (tplTag.value && !(t.tags || []).some((g) => String(g).toLowerCase() === tplTag.value.toLowerCase())) return false
    if (!q) return true
    return [t.name, t.id, t.cve, t.desc].some((v) => String(v || '').toLowerCase().includes(q))
  })
})

const filteredVulns = computed(() => {
  const q = vulnQ.value.trim().toLowerCase()
  if (!q) return vulns.value
  return vulns.value.filter((v) => [v.title, v.cve, v.assetIp, v.id].some((x) => String(x || '').toLowerCase().includes(q)))
})

// ===== 通用判别 =====
// 状态/利用结论键值化: 返回词条经 t() 解析(未知值原样显示)
function statusName(s) {
  const k = { pending: 'pw.stPending', running: 'pw.stRunning', done: 'pw.stDone', failed: 'pw.stFailed' }[s]
  return k ? t(k) : (s || t('pw.stPending'))
}
function expName(e) {
  const k = { exploitable: 'pw.expExploitable', partial: 'pw.expPartial', not_exploitable: 'pw.expNo' }[e]
  return k ? t(k) : (e || '-')
}
// 利用结论按颜色区分: 红=确认可利用(需立即处置), 橙=部分利用, 灰=不可利用
function expStyle(e) {
  if (e === 'exploitable') return { color: '#fff', background: 'var(--danger,#e5484d)', borderColor: 'transparent' }
  if (e === 'partial') return { color: '#fff', background: 'var(--warning,#f0b429)', borderColor: 'transparent' }
  return { color: 'var(--muted,#8b93a7)' }
}

// ===== 数据加载 =====
async function loadStatus() {
  try { st.value = await v2('/penta/status') } catch (e) { st.value = { enabled: false } }
}

// 2026-10-02: 状态/风险等级筛选选项 = 后端全量聚合回带(只含真实存在的值)
const RISK_CN = { critical: 'sev.critical', high: 'sev.high', medium: 'sev.medium', low: 'sev.low', info: 'sev.info' }
function riskName(id) { return RISK_CN[id] ? t(RISK_CN[id]) : id }
const pentaStatusOpts = ref([])
const pentaRiskOpts = ref([])
async function loadTasks() {
  loading.value = true
  listErr.value = ''
  try {
    const q = new URLSearchParams()
    if (filt.status) q.set('status', filt.status)
    if (filt.risk) q.set('risk', filt.risk)
    if (filt.target) q.set('target', filt.target)
    q.set('size', '200')
    const d = await v2('/penta/tasks?' + q.toString())
    tasks.value = d.list || []
    total.value = d.total || tasks.value.length
    pentaStatusOpts.value = d.statuses || []
    pentaRiskOpts.value = d.risks || []
    // 已选的筛选值对应任务全删 → 选项消失, 筛选自清(防列表卡死为空)
    if (filt.status && !pentaStatusOpts.value.some(s => s.id === filt.status)) {
      filt.status = ''
      loadTasks()
    } else if (filt.risk && !pentaRiskOpts.value.some(s => s.id === filt.risk)) {
      filt.risk = ''
      loadTasks()
    }
  } catch (e) {
    listErr.value = t('pw.loadTasksFail', { err: e.message })
  } finally {
    loading.value = false
    tasksLoaded.value = true
  }
}

async function loadTemplates() {
  try { tpls.value = await v2('/penta/templates') } catch (e) { tpls.value = {} }
}

async function loadResultTasks() {
  resErr.value = ''
  try {
    const d = await v2('/penta/tasks?size=200')
    resultTasks.value = d.list || []
    // edit 用任务自身的当前值回填: 未验证且用户未手改过的行也有可编辑的初始态,
    // 否则"结论"下拉会空白导致保存时把已有结论冲掉。
    for (const t of resultTasks.value) {
      edit[t.id] = edit[t.id] || {
        exploitability: t.exploitability || 'not_exploitable',
        riskLevel: t.riskLevel || '',
        summary: t.summary || ''
      }
    }
  } catch (e) {
    resErr.value = t('pw.loadResultsFail', { err: e.message })
  }
}

async function refreshAll() {
  await Promise.all([loadStatus(), loadTasks(), loadTemplates(), loadResultTasks()])
}

function resetFilter() {
  filt.status = ''
  filt.risk = ''
  filt.target = ''
  loadTasks()
}

function switchTab(t) {
  tab.value = t
  if (t === 'run' && !allTemplates.value.length) loadTemplates()
  if (t === 'result') loadResultTasks()
  if (t === 'audit' && !pentaAudits.value.length) {
    loadPentaAudit()
    loadPentaAuditActions()
  }
}

// ===== 任务管理 =====
async function createTask() {
  listErr.value = ''
  try {
    await v2('/penta/tasks', {
      method: 'POST',
      body: {
        target: nf.target, port: nf.port || 0, protocol: nf.protocol,
        cve: nf.cve, title: nf.title, templateId: nf.templateId, severity: nf.severity,
        job: nf.job // 关联扫描任务名(可选; 报告按任务名关联)
      }
    })
    nf.target = ''
    nf.cve = ''
    nf.title = ''
    nf.templateId = ''
    nf.severity = ''
    // job 不清空: 控制台"下一步渗透"批量建任务时, 多个任务共享同一任务名,
    // 保持预填避免用户每台手填一遍
    await Promise.all([loadTasks(), loadResultTasks()])
  } catch (e) {
    listErr.value = t('pw.createFail', { err: e.message })
  }
}

async function delTask(tk) {
  if (!confirm(t('pw.delTaskConfirm', { id: tk.id, target: tk.target }))) return
  try {
    await v2('/penta/tasks/' + encodeURIComponent(tk.id), { method: 'DELETE' })
    await Promise.all([loadTasks(), loadResultTasks()])
  } catch (e) { listErr.value = t('pw.delFail', { err: e.message }) }
}

function toggleAll(e) {
  const on = e.target.checked
  for (const t of tasks.value) checked[t.id] = on
}
function clearSel() {
  for (const k of Object.keys(checked)) checked[k] = false
}

async function batchDelete() {
  const ids = Object.keys(checked).filter((k) => checked[k])
  if (!ids.length) return
  if (!confirm(t('pw.batchDelConfirm', { n: ids.length }))) return
  try {
    const d = await v2('/penta/tasks/batch', { method: 'POST', body: { ids } })
    listErr.value = ''
    clearSel()
    await Promise.all([loadTasks(), loadResultTasks()])
    if (d && d.deleted < ids.length) listErr.value = t('pw.batchDelDone', { n: d.deleted })
  } catch (e) { listErr.value = t('pw.batchDelFail', { err: e.message }) }
}

// 导出走原始 fetch 拿 blob: 服务端返回附件而非 Resp 信封, 走 v2() 会被当 JSON 解析失败
async function exportTasks() {
  const ids = Object.keys(checked).filter((k) => checked[k])
  if (!ids.length) return
  try {
    const r = await fetch('/api/v2/penta/tasks/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids })
    })
    if (!r.ok) throw new Error('HTTP ' + r.status)
    const blob = await r.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'penta_tasks_' + new Date().toISOString().slice(0, 19).replace(/[-:T]/g, '') + '.json'
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) { listErr.value = t('pw.exportFail', { err: e.message }) }
}

// ===== 从漏扫管控导入 =====
async function openImport() {
  vulnQ.value = ''
  try {
    const d = await v2('/vulns?size=200')
    vulns.value = d.list || []
  } catch (e) {
    vulns.value = []
    listErr.value = t('pw.loadVulnsFail', { err: e.message })
  }
  showImport.value = true
}

async function doImport() {
  const ids = Object.keys(vulnSel).filter((k) => vulnSel[k])
  if (!ids.length) return
  importing.value = true
  try {
    const d = await v2('/penta/tasks/import', { method: 'POST', body: { vulnIds: ids } })
    showImport.value = false
    for (const k of Object.keys(vulnSel)) vulnSel[k] = false
    await Promise.all([loadTasks(), loadResultTasks()])
    listErr.value = ''
    if (d && (d.skipped || d.missing)) {
      listErr.value = t('pw.importDone', { c: d.created, s: d.skipped, m: d.missing })
    }
  } catch (e) {
    listErr.value = t('pw.importFail', { err: e.message })
  } finally {
    importing.value = false
  }
}

// ===== 执行控制台 =====
function pickTpl(t) {
  runTplId.value = t.id
  // 切模板不保留上一份弱口令输入: 不同模板试的是不同服务的凭据, 混着填会打到错误目标
  wpUser.value = ''
  wpPasswords.value = ''
}

function gotoRun(t) {
  runTaskId.value = t.id
  runTplId.value = t.templateId || ''
  ack.value = false
  lines.value = []
  outcome.value = null
  runErr.value = ''
  switchTab('run')
}

function scrollLog() {
  nextTick(() => {
    if (consoleEl.value) consoleEl.value.scrollTop = consoleEl.value.scrollHeight
  })
}

function handleSSE(chunk) {
  // SSE 帧格式 "event: xxx\ndata: {json}\n\n"; 逐帧解析而不是整段 JSON.parse,
  // 因为流式返回体本身不是合法 JSON。
  let evt = ''
  const dataLines = []
  for (const ln of chunk.split('\n')) {
    if (ln.startsWith('event: ')) evt = ln.slice(7).trim()
    else if (ln.startsWith('data: ')) dataLines.push(ln.slice(6))
  }
  if (!dataLines.length) return
  let payload = null
  try { payload = JSON.parse(dataLines.join('\n')) } catch (e) { return }
  if (evt === 'penta.start') {
    lines.value.push(t('pw.logTask', { id: payload.taskId || '-', tpl: payload.template || '-' }))
    lines.value.push(t('pw.logTarget', { x: payload.target + ':' + (payload.port || '-') }))
  } else if (evt === 'penta.line') {
    lines.value.push(payload.line || '')
  } else if (evt === 'penta.step') {
    // 步骤事件两阶段: start = 开始探测(让用户看得见"在做什么"), done = 结论
    if (payload.phase === 'start') {
      lines.value.push(t('pw.logStepStart', { name: payload.name, type: payload.type }))
    } else {
      const tail = payload.err ? t('pw.logErr', { err: payload.err }) : ''
      lines.value.push('  <- ' + payload.name + ' ' + (payload.hit ? t('pw.hit') : t('pw.miss')) + ' (' + payload.durationMs + 'ms)' + tail)
      if (payload.output) lines.value.push(String(payload.output).split('\n').slice(0, 6).join('\n'))
    }
  } else if (evt === 'penta.done') {
    outcome.value = payload
    lines.value.push('')
    lines.value.push(t('pw.logConclusion', { r: payload.exploitability ? expName(payload.exploitability) : t('pw.noConclusionDetail') }))
    lines.value.push(t('pw.logSummary', { s: payload.summary || '-' }))
  }
  scrollLog()
}

async function execTask() {
  runErr.value = ''
  if (!runTaskId.value) { runErr.value = t('pw.errPickTask'); return }
  if (!runTplId.value) { runErr.value = t('pw.errPickTpl'); return }
  if (!ack.value) { runErr.value = t('pw.errAck'); return }
  running.value = true
  lines.value = []
  outcome.value = null
  const body = { templateId: runTplId.value, ack: true }
  if (wpStep.value) {
    const pw = wpPasswords.value.split(/[\r\n,]/).map((s) => s.trim()).filter(Boolean)
    if (wpUser.value || pw.length) body.weakpass = { user: wpUser.value, passwords: pw }
  }
  sseAbort = new AbortController()
  try {
    const r = await fetch('/api/v2/penta/tasks/' + encodeURIComponent(runTaskId.value) + '/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: sseAbort.signal
    })
    if (!r.ok) {
      const txt = await r.text()
      let msg = txt
      try { msg = (JSON.parse(txt) || {}).message || txt } catch (e) { /* 非 JSON 原样展示 */ }
      throw new Error(msg || 'HTTP ' + r.status)
    }
    const reader = r.body.getReader()
    const dec = new TextDecoder('utf-8')
    let buf = ''
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buf += dec.decode(value, { stream: true })
      let idx
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        handleSSE(buf.slice(0, idx))
        buf = buf.slice(idx + 2)
      }
    }
  } catch (e) {
    runErr.value = t('pw.execFail', { err: e.message })
  } finally {
    sseAbort = null
    running.value = false
    ack.value = false
    await Promise.all([loadTasks(), loadResultTasks()])
  }
}

// (copyLog 已移除: 非安全上下文下 clipboard API 不可用, 见模板处注释)

// ===== 结果管理 =====
function gotoResult(t) {
  switchTab('result')
  expanded[t.id] = true
}

function toggleEvidence(id) {
  expanded[id] = !expanded[id]
}

async function saveResult(t) {
  const e = edit[t.id] || {}
  try {
    await v2('/penta/tasks/' + encodeURIComponent(t.id), {
      method: 'PUT',
      body: { exploitability: e.exploitability, riskLevel: e.riskLevel, summary: e.summary }
    })
    resErr.value = ''
    await Promise.all([loadTasks(), loadResultTasks()])
  } catch (err) {
    resErr.value = t('pw.saveFail', { err: err.message })
  }
}

async function feedback(t) {
  try {
    await v2('/penta/tasks/' + encodeURIComponent(t.id) + '/feedback', { method: 'POST' })
    resErr.value = ''
    await Promise.all([loadTasks(), loadResultTasks()])
  } catch (e) {
    resErr.value = t('pw.feedbackFail', { err: e.message })
  }
}

// ===== 自定义模板导入 =====
async function doImportTpl() {
  tplErr.value = ''
  try {
    await v2('/penta/templates/import', { method: 'POST', body: { content: tplText.value } })
    showTplImport.value = false
    tplText.value = ''
    await Promise.all([loadTemplates(), loadStatus()])
  } catch (e) {
    tplErr.value = t('pw.importFail', { err: e.message })
  }
}

// 深链:
//   /penta?import=<vulnId,...>        漏洞管理页 / 详情页带过来的漏洞
//   /penta?task=<taskId>              已存在任务, 直接进执行台
//   /penta?new=host:port:service:user 弱口令检测页「验证」过来, 预填新建表单
//   /penta?job=<任务名>                2026-09-25 命名扫描: 控制台"下一步渗透"
//                                     批量建任务后跳来, 新建表单预填任务名
//   /penta?tab=result                 直接落在结果管理
function applyQuery() {
  const imp = route.query.import
  if (imp) {
    const ids = String(imp).split(',').map((s) => s.trim()).filter(Boolean)
    openImport()
    for (const id of ids) vulnSel[id] = true
  }
  if (route.query.job) nf.job = String(route.query.job).trim()
  const tk = route.query.task
  if (tk) gotoRun({ id: String(tk), target: '', templateId: '' })
  const nw = route.query.new
  if (nw) {
    const seg = String(nw).split(':')
    nf.target = seg[0] || ''
    nf.port = parseInt(seg[1], 10) || 0
    nf.protocol = 'tcp'
    nf.templateId = 'weakpass-verify'
    nf.title = t('pw.wpVerifyTitle', { x: seg[2] ? serviceNames[seg[2]] || seg[2] : nf.target })
    nf.severity = 'high'
    tab.value = 'task'
    showNew.value = true
  }
  if (route.query.tab === 'result') switchTab('result')
}

onMounted(async () => {
  await Promise.all([loadStatus(), loadTasks(), loadTemplates(), loadResultTasks()])
  applyQuery()
})
onBeforeUnmount(() => { if (sseAbort) sseAbort.abort() })
</script>

<style scoped>
.penta-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 12px; }
@media (max-width: 1180px) { .penta-grid { grid-template-columns: 1fr; } }

.tpl-list {
  display: flex; flex-direction: column; gap: 8px;
  max-height: 420px; overflow: auto; padding-right: 4px;
}
.tpl-item {
  border: 1px solid var(--border, #2b3140); border-radius: 8px;
  padding: 8px 10px; cursor: pointer; transition: border-color .15s, background .15s;
}
.tpl-item:hover { border-color: var(--accent, #4f46e5); }
.tpl-item.active { border-color: var(--accent, #4f46e5); background: rgba(79, 70, 229, .08); }
.tpl-head { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.tpl-meta { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-top: 4px; }
.tpl-steps {
  margin-top: 6px; padding-top: 6px; border-top: 1px dashed var(--border, #2b3140);
  display: flex; flex-direction: column; gap: 2px;
}

.panel-dashed {
  padding: 10px; margin-bottom: 10px; border-radius: 8px;
  border: 1px dashed var(--border, #2b3140);
}

.kv-list { display: flex; flex-direction: column; gap: 4px; font-size: 12px; }
.kv-list .k { display: inline-block; width: 52px; color: var(--muted, #8b93a7); }
.kv-list .v { color: var(--fg, #e6e9ef); }

.ack-line {
  display: flex; align-items: center; gap: 8px; margin: 10px 0;
  padding: 8px 10px; border-radius: 8px;
  border: 1px solid var(--border, #2b3140); cursor: pointer; font-size: 12px;
}
.ack-line.on { border-color: var(--danger, #e5484d); background: rgba(229, 72, 77, .08); }

.penta-console {
  margin: 0; max-height: 320px; overflow: auto;
  background: #0d1117; border: 1px solid var(--border, #2b3140); border-radius: 8px;
  padding: 10px; font-family: Consolas, Monaco, monospace; font-size: 12px;
  line-height: 1.6; color: #c9d1d9; white-space: pre-wrap; word-break: break-all;
}

.result-brief { margin-bottom: 8px; }
.step-list { display: flex; flex-direction: column; gap: 4px; margin-top: 6px; }
.step-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

.ev-block { margin-bottom: 8px; }
.ev-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.ev-body {
  margin: 0; max-height: 220px; overflow: auto;
  background: #0d1117; border: 1px solid var(--border, #2b3140); border-radius: 6px;
  padding: 8px; font-family: Consolas, Monaco, monospace; font-size: 12px;
  line-height: 1.6; color: #c9d1d9; white-space: pre-wrap; word-break: break-all;
}
</style>

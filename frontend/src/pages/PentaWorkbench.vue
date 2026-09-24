<template>
  <div>
    <PageHeader title="渗透工作台" desc="针对已知漏洞做验证渗透（扫描只发现，渗透只验证；全程审计留痕，清空操作同样留痕）">
      <span class="chip" :class="st.enabled ? 'on' : 'off'">{{ st.enabled ? '工作台已启用' : '工作台已停用' }}</span>
      <span class="chip">内置模板 {{ st.builtinCount || 0 }} · 自定义 {{ st.customCount || 0 }} · 任务 {{ total }}</span>
      <button class="btn sm" @click="refreshAll"><span class="spinner" v-if="loading"></span> 刷新</button>
    </PageHeader>

    <!-- 安全声明: 常驻不可关闭。攻击性能力的边界写在最显眼处, 而不是埋在文档里 -->
    <div class="card" style="border-left:3px solid var(--danger,#e5484d); margin-bottom:12px">
      <div class="card-title">安全声明</div>
      <p class="muted small" style="margin:0; line-height:1.7">{{ st.statement || statementFallback }}</p>
    </div>

    <div class="tabs">
      <div class="tab" :class="{ active: tab === 'task' }" @click="tab = 'task'">渗透任务管理</div>
      <div class="tab" :class="{ active: tab === 'run' }" @click="switchTab('run')">渗透执行控制台</div>
      <div class="tab" :class="{ active: tab === 'result' }" @click="switchTab('result')">渗透结果管理</div>
      <div class="tab" :class="{ active: tab === 'audit' }" @click="switchTab('audit')">
        渗透审计
        <span class="muted small" v-if="paTotal > 0">{{ paTotal }} 条</span>
      </div>
    </div>

    <!-- ==================== Tab1 渗透任务管理 ==================== -->
    <div v-if="tab === 'task'">
      <div class="card">
        <div class="card-title">
          渗透任务列表
          <span class="sub">按状态 / 风险等级 / 目标筛选</span>
          <div class="spacer"></div>
          <button class="btn sm primary" @click="showNew = !showNew">{{ showNew ? '收起新建' : '新建任务' }}</button>
          <button class="btn sm" @click="openImport">从漏扫管控导入</button>
        </div>

        <div class="form-row" style="margin-bottom:10px">
          <div class="field" style="max-width:150px">
            <label class="label">状态</label>
            <select class="input" v-model="filt.status">
              <option value="">全部</option>
              <option value="pending">待执行</option>
              <option value="running">执行中</option>
              <option value="done">完成</option>
              <option value="failed">失败</option>
            </select>
          </div>
          <div class="field" style="max-width:150px">
            <label class="label">风险等级</label>
            <select class="input" v-model="filt.risk">
              <option value="">全部</option>
              <option value="critical">严重</option>
              <option value="high">高危</option>
              <option value="medium">中危</option>
              <option value="low">低危</option>
              <option value="info">信息</option>
            </select>
          </div>
          <div class="field" style="max-width:220px">
            <label class="label">目标</label>
            <input class="input mono" v-model.trim="filt.target" :placeholder="phTarget">
          </div>
          <div class="spacer"></div>
          <button class="btn sm" @click="loadTasks">查询</button>
          <button class="btn sm" @click="resetFilter">重置</button>
        </div>

        <!-- 新建任务(折叠区) -->
        <div v-if="showNew" class="panel-dashed">
          <div class="form-row" style="flex-wrap:wrap; align-items:flex-end; gap:10px">
            <div class="field" style="max-width:180px">
              <label class="label">目标 IP / 主机</label>
              <input class="input mono" v-model.trim="nf.target" placeholder="10.0.0.5">
            </div>
            <div class="field" style="max-width:110px">
              <label class="label">端口</label>
              <input class="input mono" type="number" v-model.number="nf.port" placeholder="6379">
            </div>
            <div class="field" style="max-width:130px">
              <label class="label">协议</label>
              <select class="input" v-model="nf.protocol">
                <option value="tcp">tcp</option>
                <option value="http">http</option>
                <option value="https">https</option>
              </select>
            </div>
            <div class="field" style="max-width:170px">
              <label class="label">CVE（可选）</label>
              <input class="input mono" v-model.trim="nf.cve" placeholder="CVE-2022-0543">
            </div>
            <div class="field" style="max-width:220px">
              <label class="label">漏洞标题</label>
              <input class="input" v-model.trim="nf.title" placeholder="Redis 未授权访问">
            </div>
            <div class="field" style="max-width:210px">
              <label class="label">EXP 模板</label>
              <select class="input" v-model="nf.templateId">
                <option value="">未指定（执行时选择）</option>
                <option v-for="t in allTemplates" :key="t.id" :value="t.id">{{ t.name }}（{{ t.id }}）</option>
              </select>
            </div>
            <div class="field" style="max-width:150px">
              <label class="label">初始风险等级</label>
              <select class="input" v-model="nf.severity">
                <option value="">未定级</option>
                <option value="critical">严重</option>
                <option value="high">高危</option>
                <option value="medium">中危</option>
                <option value="low">低危</option>
              </select>
            </div>
            <div class="spacer"></div>
            <button class="btn primary" :disabled="!nf.target" @click="createTask">创建任务</button>
          </div>
        </div>

        <!-- 批量操作条: 选中才出现, 避免"无选中时按钮可点但什么都不做" -->
        <div class="form-row" v-if="selCount" style="margin:10px 0 8px">
          <span class="chip warn">已选 {{ selCount }} 条</span>
          <button class="btn sm danger" @click="batchDelete">批量删除</button>
          <button class="btn sm" @click="exportTasks">批量导出</button>
          <button class="btn sm" @click="clearSel">取消选择</button>
        </div>

        <div class="table-wrap" v-if="tasks.length">
          <table class="table">
            <thead>
              <tr>
                <th style="width:36px"><input type="checkbox" :checked="allChecked" @change="toggleAll"></th>
                <th>任务</th><th style="width:150px">目标</th>
                <th style="width:150px">CVE</th><th style="width:80px">风险</th>
                <th style="width:80px">状态</th><th style="width:90px">验证结论</th>
                <th style="width:150px">最近执行</th><th style="width:180px">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="t in tasks" :key="t.id">
                <td><input type="checkbox" v-model="checked[t.id]"></td>
                <td>
                  <div>{{ t.title || '渗透验证' }}</div>
                  <div class="muted small mono">{{ t.id }}</div>
                </td>
                <td class="mono">{{ t.target }}<span class="muted">:{{ t.port || '-' }}</span></td>
                <td class="mono small">{{ t.cve || '-' }}</td>
                <td><SevTag :sev="t.riskLevel || 'info'" /></td>
                <td><span class="badge">{{ statusName(t.status) }}</span></td>
                <td>
                  <span v-if="t.exploitability" class="badge" :style="expStyle(t.exploitability)">{{ expName(t.exploitability) }}</span>
                  <span v-else class="muted small">未验证</span>
                </td>
                <td class="mono small muted">{{ t.finishedAt ? fmtDT(t.finishedAt) : '-' }}</td>
                <td>
                  <button class="btn xs" @click="gotoRun(t)">执行</button>
                  <button class="btn xs" @click="gotoResult(t)">结果</button>
                  <button class="btn xs danger" @click="delTask(t)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="tasksLoaded ? '没有符合条件的渗透任务，可从漏扫管控导入漏洞' : '加载中…'" />
        <div class="err-line" style="color:var(--danger,#e5484d)">{{ listErr }}</div>
      </div>
    </div>

    <!-- ==================== Tab2 渗透执行控制台 ==================== -->
    <div v-if="tab === 'run'">
      <div class="penta-grid">
        <div>
          <div class="card">
            <div class="card-title">选择任务<span class="sub">仅对已登记漏洞执行验证</span></div>
            <select class="input mono" v-model="runTaskId">
              <option value="">请选择渗透任务</option>
              <option v-for="t in tasks" :key="t.id" :value="t.id">
                {{ t.target }}:{{ t.port || '-' }} · {{ t.title || t.cve || t.id }}
              </option>
            </select>
            <div v-if="curTask" class="kv-list" style="margin-top:10px">
              <div><span class="k">目标</span><span class="v mono">{{ curTask.target }}:{{ curTask.port || '-' }}（{{ curTask.protocol || 'tcp' }}）</span></div>
              <div><span class="k">对象</span><span class="v">{{ curTask.title || '-' }}</span></div>
              <div><span class="k">CVE</span><span class="v mono">{{ curTask.cve || '-' }}</span></div>
              <div><span class="k">来源</span><span class="v">{{ curTask.source === 'vuln' ? '漏扫管控导入' : '手动创建' }}</span></div>
            </div>
          </div>

          <!-- EXP 模板库 -->
          <div class="card">
            <div class="card-title">
              EXP 模板库
              <span class="sub">内置 {{ (tpls.builtin || []).length }} · 自定义 {{ (tpls.custom || []).length }}</span>
              <div class="spacer"></div>
              <button class="btn xs" @click="showTplImport = true">导入自定义</button>
            </div>
            <div class="form-row" style="margin-bottom:8px">
              <input class="input" v-model.trim="tplQ" placeholder="搜索名称 / ID / CVE">
              <div class="spacer"></div>
              <select class="input" style="max-width:140px" v-model="tplTag">
                <option value="">全部标签</option>
                <option v-for="g in (tpls.tags || [])" :key="g" :value="g">{{ g }}</option>
              </select>
            </div>
            <div class="tpl-list">
              <div
                class="tpl-item" v-for="t in filteredTpls" :key="t.id"
                :class="{ active: runTplId === t.id }" @click="pickTpl(t)"
              >
                <div class="tpl-head">
                  <b>{{ t.name }}</b>
                  <span class="badge blue mono">{{ t.id }}</span>
                  <span class="badge" v-if="t.builtIn">内置</span>
                  <span class="badge warn" v-else>自定义</span>
                </div>
                <div class="muted small" v-if="t.desc">{{ t.desc }}</div>
                <div class="tpl-meta">
                  <span class="badge blue mono" v-if="t.cve">{{ t.cve }}</span>
                  <span class="badge" v-for="g in (t.tags || [])" :key="g">{{ g }}</span>
                  <span class="muted small">{{ (t.steps || []).length }} 步</span>
                </div>
                <!-- 选中后展开"即将执行什么": 执行前必须让用户看见具体动作, 不是黑盒点按钮 -->
                <div v-if="runTplId === t.id && (t.steps || []).length" class="tpl-steps">
                  <div class="mono small" v-for="(s, i) in t.steps" :key="i">
                    {{ i + 1 }}. [{{ s.type }}] {{ s.name }}{{ s.path ? ' ' + s.path : '' }}{{ s.service ? ' ' + s.service : '' }}
                  </div>
                  <div class="muted small" v-if="t.note">说明：{{ t.note }}</div>
                </div>
              </div>
              <Empty v-if="!filteredTpls.length" text="没有匹配的 EXP 模板" />
            </div>
          </div>
        </div>

        <div>
          <div class="card">
            <div class="card-title">执行参数</div>
            <div v-if="wpStep" class="form-row" style="flex-wrap:wrap; gap:10px">
              <div class="field" style="max-width:130px">
                <label class="label">服务</label>
                <input class="input mono" disabled :value="wpStep.service || '-'">
              </div>
              <div class="field" style="max-width:150px">
                <label class="label">账号</label>
                <input class="input mono" v-model.trim="wpUser" placeholder="admin">
              </div>
              <div class="field" style="max-width:100%">
                <label class="label">候选口令（每行一个，上限 10 个；这是凭据验证场景，不是爆破）</label>
                <textarea class="input mono" rows="3" v-model="wpPasswords"></textarea>
              </div>
            </div>
            <div v-else class="muted small" style="margin-bottom:8px">
              当前模板无弱口令步骤。选择含 weakpass 步骤的模板后，可在此指定账号与候选口令执行登录验证。
            </div>

            <!-- 逐次授权确认: 不写进 localStorage, 刷新即失效 —— 攻击动作不能"一次勾选永久有效" -->
            <label class="ack-line" :class="{ on: ack }">
              <input type="checkbox" v-model="ack">
              <span>我确认已获得该目标的书面授权（每次执行均需勾选，授权态不留存）</span>
            </label>

            <div class="form-row">
              <div class="spacer"></div>
              <button class="btn danger" :disabled="running || !runTaskId || !runTplId" @click="execTask">
                {{ running ? '执行中…' : '执行验证' }}
              </button>
            </div>
            <div class="err-line" style="color:var(--danger,#e5484d)">{{ runErr }}</div>
          </div>

          <div class="card">
            <div class="card-title">
              实时执行回显
              <span class="chip warn" v-if="running">执行中</span>
              <span class="chip" :class="outcome && outcome.ok ? 'on' : 'warn'" v-else-if="outcome">
                {{ outcome.ok ? '已完成' : '未获得结论' }}
              </span>
              <div class="spacer"></div>
              <button class="btn xs" v-if="lines.length" @click="copyLog">复制日志</button>
            </div>
            <div v-if="outcome" class="result-brief">
              <div class="muted small">{{ outcome.summary || '-' }}</div>
              <div class="step-list" v-if="(outcome.steps || []).length">
                <div class="step-row" v-for="(s, i) in outcome.steps" :key="i">
                  <span class="badge" :class="s.hit ? 'badge-ok' : ''">{{ s.name }}</span>
                  <span class="muted small mono">{{ s.type }}</span>
                  <span class="badge" :class="s.hit ? 'badge-ok' : ''">{{ s.hit ? '命中' : '未命中' }}</span>
                  <span class="mono small muted">{{ s.durationMs }}ms</span>
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
          渗透结果管理
          <span class="sub">可利用性结论 · 风险定级修正 · 证据留存 · 一键回传漏扫管控</span>
          <div class="spacer"></div>
          <span class="chip">已验证 {{ verifiedCount }} / {{ resultTasks.length }}</span>
        </div>

        <div class="table-wrap" v-if="resultTasks.length">
          <table class="table">
            <thead>
              <tr>
                <th>目标 / 对象</th><th style="width:130px">验证结论</th><th style="width:140px">风险定级修正</th>
                <th>摘要（写入报告）</th><th style="width:120px">回传</th><th style="width:170px">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="t in resultTasks" :key="t.id">
                <td>
                  <div>{{ t.title || '渗透验证' }}</div>
                  <div class="muted small mono">{{ t.target }}:{{ t.port || '-' }}{{ t.cve ? ' · ' + t.cve : '' }}</div>
                </td>
                <td>
                  <select class="input" v-model="edit[t.id].exploitability">
                    <option value="exploitable">可利用</option>
                    <option value="partial">部分利用</option>
                    <option value="not_exploitable">不可利用</option>
                  </select>
                </td>
                <td>
                  <select class="input" v-model="edit[t.id].riskLevel">
                    <option value="">保持扫描定级</option>
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中危</option>
                    <option value="low">低危</option>
                    <option value="info">信息</option>
                  </select>
                </td>
                <td>
                  <input class="input" v-model="edit[t.id].summary" placeholder="验证摘要（命中现象 / 判定依据）">
                </td>
                <td>
                  <span class="badge badge-ok" v-if="t.feedbackAt">已回传</span>
                  <span class="muted small" v-else-if="!t.vulnId">无关联漏洞</span>
                  <span class="muted small" v-else>待回传</span>
                  <div class="muted small mono" v-if="t.feedbackAt">{{ fmtDT(t.feedbackAt) }}</div>
                </td>
                <td>
                  <button class="btn xs" @click="saveResult(t)">保存</button>
                  <button class="btn xs primary" :disabled="!t.vulnId" @click="feedback(t)">回传</button>
                  <button class="btn xs" @click="toggleEvidence(t.id)">{{ expanded[t.id] ? '收起证据' : '证据' }}</button>
                </td>
              </tr>
              <tr v-if="expanded[t.id]">
                <td colspan="6" style="background:rgba(255,255,255,.02)">
                  <div v-if="(t.evidence || []).length">
                    <div class="muted small" style="margin-bottom:6px">命令与响应留存（同步写入审计）：</div>
                    <div class="ev-block" v-for="(s, i) in t.evidence" :key="i">
                      <div class="ev-head">
                        <span class="badge" :class="s.hit ? 'badge-ok' : ''">{{ s.name }}</span>
                        <span class="muted small mono">{{ s.type }} · {{ s.durationMs }}ms · {{ s.hit ? '命中' : '未命中' }}</span>
                      </div>
                      <pre class="ev-body">{{ s.evidence || '-' }}</pre>
                    </div>
                  </div>
                  <div v-else class="muted small">暂无步骤证据（任务尚未执行，或执行未产出证据）</div>
                  <div v-if="t.runLog" class="ev-block" style="margin-top:8px">
                    <div class="ev-head"><span class="badge blue">执行日志</span></div>
                    <pre class="ev-body">{{ t.runLog }}</pre>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else text="暂无可管理的渗透结果（执行验证后在此修正定级并回传）" />
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
          渗透审计
          <span class="sub">创建 / 导入 / 执行 / 每步探测 / 结果保存 / 回传 全量记录 · 清空操作本身留痕（合规留痕）</span>
          <div class="spacer"></div>
          <span class="chip" v-if="paTotal > 0">共 {{ paTotal }} 条</span>
          <button class="btn xs danger" :disabled="!paTotal" @click="openClearAudit"
                  :title="paTotal ? '清空全部渗透审计(输入“清空”确认)' : '没有可清空的记录'">清空审计</button>
        </div>

        <div class="form-row" style="flex-wrap:wrap">
          <select class="input" v-model="paFlt.action" style="width:180px">
            <option value="">全部动作</option>
            <option v-for="a in paActions" :key="a" :value="a">{{ a }}</option>
          </select>
          <input class="input" v-model.trim="paFlt.keyword" placeholder="关键字（对象 / 详情）" style="width:200px" />
          <input class="input" type="date" v-model="paFlt.from" style="width:140px" />
          <input class="input" type="date" v-model="paFlt.to" style="width:140px" />
          <button class="btn" @click="paApplyFilter">筛选</button>
          <button class="btn" @click="paResetFilter">重置</button>
        </div>

        <div class="table-wrap" v-if="pentaAudits.length">
          <table class="table">
            <thead>
              <tr>
                <th>时间</th><th>用户</th><th>动作</th><th>对象</th><th>详情</th><th>来源 IP</th>
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
        <Empty v-else text="暂无渗透审计记录（执行渗透验证后自动写入）" />

        <!-- 分页 -->
        <div class="form-row" v-if="paTotal > PA_SIZE" style="justify-content:flex-end">
          <button class="btn xs" :disabled="paPage <= 1" @click="paGotoPage(paPage - 1)">上一页</button>
          <span class="muted small">{{ paPage }} / {{ paTotalPages }}</span>
          <button class="btn xs" :disabled="paPage >= paTotalPages" @click="paGotoPage(paPage + 1)">下一页</button>
        </div>
      </div>
    </div>

    <!-- 从漏扫管控导入 -->
    <Modal v-if="showImport" title="从漏扫管控导入漏洞" width="860px" @close="showImport = false">
      <div class="form-row" style="margin-bottom:8px">
        <input class="input" v-model.trim="vulnQ" placeholder="按 IP / CVE / 标题过滤漏洞">
        <div class="spacer"></div>
        <span class="chip">已选 {{ Object.values(vulnSel).filter(Boolean).length }} 条</span>
      </div>
      <div class="table-wrap" style="max-height:420px; overflow:auto">
        <table class="table">
          <thead>
            <tr><th style="width:36px"></th><th>漏洞</th><th style="width:130px">资产</th><th style="width:70px">端口</th><th style="width:80px">等级</th><th style="width:90px">已验证</th></tr>
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
                <span v-else class="muted small">未验证</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <template #footer>
        <div class="spacer"></div>
        <button class="btn sm" @click="showImport = false">取消</button>
        <button class="btn sm primary" :disabled="importing" @click="doImport">
          {{ importing ? '导入中…' : '导入到渗透工作台' }}
        </button>
      </template>
    </Modal>

    <!-- 导入自定义 EXP -->
    <Modal v-if="showTplImport" title="导入自定义 EXP 模板" width="720px" @close="showTplImport = false">
      <p class="muted small" style="margin-top:0">
        支持 YAML / JSON 文本粘贴导入。步骤类型仅允许 http / tcp / weakpass / external ——
        不允许携带任意命令，服务端会对 ID、步骤类型与口令数量做校验，不合规直接拒绝。
      </p>
      <textarea class="input mono" rows="16" spellcheck="false" v-model="tplText" :placeholder="phTpl"></textarea>
      <div class="err-line" style="color:var(--danger,#e5484d)">{{ tplErr }}</div>
      <template #footer>
        <div class="spacer"></div>
        <button class="btn sm" @click="showTplImport = false">取消</button>
        <button class="btn sm primary" :disabled="!tplText.trim()" @click="doImportTpl">导入</button>
      </template>
    </Modal>

    <!-- 清空渗透审计: 输入"清空"确认(与"清空全部漏洞"同口径)。
         清空后列表只剩后端写的 penta.audit.clear 痕迹(清空动作本身可审计) -->
    <Modal v-if="showClearAudit" title="清空渗透审计" width="480px" @close="showClearAudit = false">
      <p class="muted small" style="margin:0 0 12px">
        将删除全部渗透审计记录(仅管理员可操作)。清空后后端会保留一条
        <b class="mono">penta.audit.clear</b> 痕迹(谁、何时、清了几条), 清空动作本身可审计。
      </p>
      <div class="field">
        <label class="lbl">输入 <b>清空</b> 确认</label>
        <input class="input" v-model.trim="clearAuditWord" placeholder="清空" />
      </div>
      <template #footer>
        <div class="spacer"></div>
        <button class="btn sm" @click="showClearAudit = false">取消</button>
        <button class="btn sm danger" :disabled="clearAuditWord !== '清空' || clearAuditBusy" @click="doClearAudit">
          {{ clearAuditBusy ? '清空中…' : '清空' }}
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

const route = useRoute()

// 文案常量: Vue 模板里出现字面量占位符会被当插值解析(编译报
// "Unterminated string constant"), 所有示例文本一律经 JS 常量传 :placeholder。
const phTarget = '10.0.0.5'
const phTpl = [
  'id: my-check',
  'name: 自定义验证模板',
  'cve: CVE-2025-0001',
  'tags: [http, custom]',
  'desc: 示例: 验证管理后台是否可直接访问',
  'steps:',
  '  - name: 访问后台路径',
  '    type: http',
  '    path: /admin/login',
  '    expectStatus: 200',
  '    expectBody: "login|password"',
  '  - name: 取 Banner 判断版本',
  '    type: tcp',
  '    send: "PING\\r\\n"',
  '    expect: "\\\\+PONG"'
].join('\n')

// 服务名 -> 中文(弱口令检测页深链过来时用于生成任务标题)
const serviceNames = { redis: 'Redis', mysql: 'MySQL', ftp: 'FTP', telnet: 'Telnet', ssh: 'SSH', vnc: 'VNC', rdp: 'RDP', smb: 'SMB' }

// statementFallback 后端未返回声明文案时的兜底(与后端 pentaStatement 同口径)。
const statementFallback = '本模块仅可用于验证自己拥有或已获书面授权的目标系统。所有渗透命令全程写入审计日志，审计记录仅管理员可清空，且清空操作本身同样留痕；未经授权对他人系统实施渗透可能违反《中华人民共和国网络安全法》及相关法律法规。'

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
const nf = reactive({ target: '', port: 0, protocol: 'tcp', cve: '', title: '', templateId: '', severity: '' })

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
const logText = computed(() => lines.value.join('\n') || '执行输出将实时显示在这里…')
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
  if (clearAuditWord.value !== '清空') return
  clearAuditBusy.value = true
  try {
    const d = await v2('/penta/audit', { method: 'DELETE' })
    showClearAudit.value = false
    paFlt.value = { action: '', keyword: '', from: '', to: '' }
    paPage.value = 1
    await loadPentaAudit()
    loadPentaAuditActions()
    alert('已清空 ' + ((d && d.deleted) || 0) + ' 条记录（清空动作本身留痕 penta.audit.clear）')
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
function statusName(s) {
  return { pending: '待执行', running: '执行中', done: '完成', failed: '失败' }[s] || s || '待执行'
}
function expName(e) {
  return { exploitable: '可利用', partial: '部分利用', not_exploitable: '不可利用' }[e] || e || '-'
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
  } catch (e) {
    listErr.value = '任务列表加载失败: ' + e.message
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
    resErr.value = '渗透结果加载失败: ' + e.message
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
        cve: nf.cve, title: nf.title, templateId: nf.templateId, severity: nf.severity
      }
    })
    nf.target = ''
    nf.cve = ''
    nf.title = ''
    nf.templateId = ''
    nf.severity = ''
    await Promise.all([loadTasks(), loadResultTasks()])
  } catch (e) {
    listErr.value = '创建失败: ' + e.message
  }
}

async function delTask(t) {
  if (!confirm(`确认删除渗透任务 ${t.id}（${t.target}）？证据将一并删除，审计留痕不受影响。`)) return
  try {
    await v2('/penta/tasks/' + encodeURIComponent(t.id), { method: 'DELETE' })
    await Promise.all([loadTasks(), loadResultTasks()])
  } catch (e) { listErr.value = '删除失败: ' + e.message }
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
  if (!confirm(`确认批量删除 ${ids.length} 条渗透任务？执行中的任务会被跳过。`)) return
  try {
    const d = await v2('/penta/tasks/batch', { method: 'POST', body: { ids } })
    listErr.value = ''
    clearSel()
    await Promise.all([loadTasks(), loadResultTasks()])
    if (d && d.deleted < ids.length) listErr.value = `实际删除 ${d.deleted} 条（执行中的任务已跳过）`
  } catch (e) { listErr.value = '批量删除失败: ' + e.message }
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
  } catch (e) { listErr.value = '导出失败: ' + e.message }
}

// ===== 从漏扫管控导入 =====
async function openImport() {
  vulnQ.value = ''
  try {
    const d = await v2('/vulns?size=200')
    vulns.value = d.list || []
  } catch (e) {
    vulns.value = []
    listErr.value = '漏洞列表加载失败: ' + e.message
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
      listErr.value = `导入完成：新建 ${d.created} 条，跳过已导入 ${d.skipped} 条，不存在 ${d.missing} 条`
    }
  } catch (e) {
    listErr.value = '导入失败: ' + e.message
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
    lines.value.push('任务: ' + (payload.taskId || '-') + '  模板: ' + (payload.template || '-'))
    lines.value.push('目标: ' + payload.target + ':' + (payload.port || '-'))
  } else if (evt === 'penta.line') {
    lines.value.push(payload.line || '')
  } else if (evt === 'penta.step') {
    // 步骤事件两阶段: start = 开始探测(让用户看得见"在做什么"), done = 结论
    if (payload.phase === 'start') {
      lines.value.push('> 执行步骤 [' + payload.name + '] ' + payload.type)
    } else {
      const tail = payload.err ? '  错误: ' + payload.err : ''
      lines.value.push('  <- ' + payload.name + ' ' + (payload.hit ? '命中' : '未命中') + ' (' + payload.durationMs + 'ms)' + tail)
      if (payload.output) lines.value.push(String(payload.output).split('\n').slice(0, 6).join('\n'))
    }
  } else if (evt === 'penta.done') {
    outcome.value = payload
    lines.value.push('')
    lines.value.push('结论: ' + (payload.exploitability ? expName(payload.exploitability) : '未获得结论（目标不可达或全部步骤失败）'))
    lines.value.push('摘要: ' + (payload.summary || '-'))
  }
  scrollLog()
}

async function execTask() {
  runErr.value = ''
  if (!runTaskId.value) { runErr.value = '请先选择渗透任务'; return }
  if (!runTplId.value) { runErr.value = '请选择 EXP 模板'; return }
  if (!ack.value) { runErr.value = '请先勾选授权确认'; return }
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
    runErr.value = '执行失败: ' + e.message
  } finally {
    sseAbort = null
    running.value = false
    ack.value = false
    await Promise.all([loadTasks(), loadResultTasks()])
  }
}

async function copyLog() {
  try {
    await navigator.clipboard.writeText(logText.value)
  } catch (e) {
    runErr.value = '复制失败（浏览器限制），请手动选中日志复制'
  }
}

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
    resErr.value = '保存失败: ' + err.message
  }
}

async function feedback(t) {
  try {
    await v2('/penta/tasks/' + encodeURIComponent(t.id) + '/feedback', { method: 'POST' })
    resErr.value = ''
    await Promise.all([loadTasks(), loadResultTasks()])
  } catch (e) {
    resErr.value = '回传失败: ' + e.message
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
    tplErr.value = '导入失败: ' + e.message
  }
}

// 深链:
//   /penta?import=<vulnId,...>        漏洞管理页 / 详情页带过来的漏洞
//   /penta?task=<taskId>              已存在任务, 直接进执行台
//   /penta?new=host:port:service:user 弱口令检测页「验证」过来, 预填新建表单
//   /penta?tab=result                 直接落在结果管理
function applyQuery() {
  const imp = route.query.import
  if (imp) {
    const ids = String(imp).split(',').map((s) => s.trim()).filter(Boolean)
    openImport()
    for (const id of ids) vulnSel[id] = true
  }
  const tk = route.query.task
  if (tk) gotoRun({ id: String(tk), target: '', templateId: '' })
  const nw = route.query.new
  if (nw) {
    const seg = String(nw).split(':')
    nf.target = seg[0] || ''
    nf.port = parseInt(seg[1], 10) || 0
    nf.protocol = 'tcp'
    nf.templateId = 'weakpass-verify'
    nf.title = '弱口令验证 ' + (seg[2] ? serviceNames[seg[2]] || seg[2] : nf.target)
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

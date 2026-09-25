<template>
  <div>
    <!-- 菜单 B 方案(2026-09-22): 原「实时扫描控制台」与「扫描任务管理」合并为一页。
         提交区共用一张表单, "提交方式: 立即执行 | 排队执行"决定后端路径:
         立即 → /api/scan SSE 实时流(原控制台行为); 排队 → 同一端点 queue=true,
         调度器按并发/限速/节点派发(原任务管理行为)。后端契约零改, 纯前端合并。
         tab 状态放在 URL query 上(先例 /env?tab=rules): 刷新/书签/手工输 URL 都停在同一 tab。 -->
    <PageHeader title="扫描作业" desc="立即扫描实时看结果; 排队任务由调度器派发"></PageHeader>
    <div class="tabs">
      <div class="tab" :class="{ active: tab === 'scan' }" @click="setTab('scan')">立即扫描</div>
      <div class="tab" :class="{ active: tab === 'queue' }" @click="setTab('queue')">任务队列</div>
    </div>

    <!-- v-show 而非 v-if: 扫描进行中用户切到任务队列, unmount 会中止进行中的
         SSE 流与全局 EventSource, 本窗口结果也一并丢失。 -->
    <div v-show="tab === 'scan'">
      <!-- 扫描参数: 三种扫描(快速发现/深度主机/Web) + 提交方式(立即/排队)。
           "仅存活检查"与"自定义端口集"是快速发现的选项, 不是独立类型 ——
           它们与快速发现共用同一个统一扫描引擎, 拆开只会让用户选三遍同一件事。 -->
      <div class="card">
        <div class="form-row">
          <div class="field" style="max-width:170px">
            <label class="label">扫描类型</label>
            <select class="select" v-model="form.type" :disabled="busy">
              <option v-for="t in SCAN_TYPES" :key="t.value" :value="t.value">{{ t.label }}</option>
            </select>
          </div>
          <div class="field">
            <label class="label">{{ targetLabel }} *</label>
            <input class="input mono" v-model.trim="form.target" :placeholder="targetPh" :disabled="busy" @keyup.enter="start">
          </div>
          <div class="field" v-if="form.type === 'host'">
            <label class="label">端口(逗号分隔)</label>
            <input class="input mono" v-model.trim="form.ports" placeholder="留空用默认端口集" :disabled="busy">
          </div>
          <div class="field" v-if="form.type === 'quick'">
            <label class="label">端口集(留空用默认)</label>
            <input class="input mono" v-model.trim="form.ports" placeholder="如 80,443,3389; 留空用常用端口" :disabled="busy">
          </div>
          <!-- 存活判定仅立即模式传: 调度入队链路(enqueueScanRequest)不带 aliveMode,
               排队时选了会被静默丢弃 —— 不如隐藏, 避免用户以为生效了。 -->
          <div class="field" style="max-width:230px" v-if="form.type === 'quick' && !form.aliveOnly && form.mode === 'now'">
            <label class="label">存活判定</label>
            <select class="select" v-model="form.aliveMode" :disabled="busy">
              <option value="loose">宽松: ICMP/ARP 或端口开放</option>
              <option value="strict">严格: 仅 ICMP/ARP 应答</option>
              <option value="none">跳过存活: 纯端口扫描</option>
            </select>
          </div>
          <div class="field" style="max-width:130px">
            <label class="label">超时(ms)</label>
            <input class="input mono" type="number" v-model.number="form.timeoutMs" :disabled="busy">
          </div>
          <div class="field" style="max-width:130px">
            <label class="label">并发</label>
            <input class="input mono" type="number" v-model.number="form.concurrency" :disabled="busy">
          </div>
        </div>
        <!-- 提交方式: 立即执行(默认, 原控制台行为) / 排队执行(调度器派发, 原任务管理行为)。
             调度参数(策略/节点/优先级/重试)只在排队时有意义, 仅排队时出现。 -->
        <div class="form-row" style="align-items:flex-end">
          <div class="field">
            <label class="label">提交方式</label>
            <div style="display:flex; align-items:center; gap:16px; padding-top:2px">
              <label class="checkbox"><input type="radio" v-model="form.mode" value="now" :disabled="busy"> 立即执行(实时看结果)</label>
              <label class="checkbox"><input type="radio" v-model="form.mode" value="queue" :disabled="busy"> 排队执行(调度派发)</label>
              <span class="chip" v-if="form.mode === 'queue'" :class="schedOn ? 'on' : 'off'">{{ schedOn ? '调度已启用' : '调度未启用' }}</span>
            </div>
          </div>
        </div>
        <!-- 快速发现的两个选项: 仅存活检查(不枚举端口, 更快) / 深度主机与 Web 各自扩展项 -->
        <div class="form-row" v-if="form.type === 'quick'">
          <div class="field" style="max-width:200px">
            <label class="checkbox"><input type="checkbox" v-model="form.aliveOnly" :disabled="busy">
              仅存活检查(不枚举端口)</label>
          </div>
        </div>
        <div class="form-row" v-if="form.type === 'host'">
          <div class="field" style="max-width:280px">
            <label class="checkbox"><input type="checkbox" v-model="form.enableNuclei" :disabled="busy">
              启用 Nuclei 模板扫描</label>
          </div>
          <div class="field" v-if="form.enableNuclei">
            <label class="label">tag 白名单</label>
            <input class="input mono" v-model.trim="form.nucleiTags" placeholder="如 cisa-kev,critical(留空不限)" :disabled="busy">
          </div>
          <!-- 经典页迁移(P1-3): tag 黑名单, 命中任一标签的模板被剔除; 与白名单同走 /api/scan 的 nucleiTagsExclude 字段 -->
          <div class="field" v-if="form.enableNuclei">
            <label class="label">tag 黑名单</label>
            <input class="input mono" v-model.trim="form.nucleiTagsExclude" placeholder="如 tech,exposure(留空不限)" :disabled="busy">
          </div>
          <button class="btn xs" @click="ruleDrawerOpen = true">模板更新</button>
          <!-- 经典页迁移(P1-3): 热重载 exe 同目录 vuln/templates/ 下的外部模板, 无需重启 -->
          <button class="btn xs" @click="reloadNuclei" title="重新加载外部模板目录(vuln/templates/), 修改模板后点此立即生效">重载模板</button>
        </div>
        <!-- Web 深度爬取(c4): 默认关。开启后跟随页面链接递归扫描子路径, 覆盖广但耗时显著变长 -->
        <div class="form-row" v-if="form.type === 'web'">
          <div class="field" style="max-width:340px">
            <label class="checkbox"><input type="checkbox" v-model="form.webdeep" :disabled="busy">
              深度爬取(跟随页面链接递归扫描子路径)</label>
          </div>
        </div>
        <!-- 调度参数: 仅排队时显示(策略模板 / 执行节点 / 优先级 / 失败重试) -->
        <div class="form-row" v-if="form.mode === 'queue'">
          <div class="field" style="max-width:190px">
            <label class="label">策略模板</label>
            <select class="select" v-model="form.strategy" :disabled="busy">
              <option value="">按服务端默认策略</option>
              <option v-for="s in strategies" :key="s.id" :value="s.id">{{ s.name }} ({{ s.id }})</option>
              <option value="custom">custom(不套模板)</option>
            </select>
          </div>
          <!-- 执行节点下拉只列探针(kind=probe): 中心本地已由空值表达, 列出来会出现两个"本地" -->
          <div class="field" style="max-width:200px">
            <label class="label">执行节点</label>
            <select class="select" v-model="form.queueNode" :disabled="busy">
              <option value="">中心本地</option>
              <option value="auto">auto(自动挑最空闲探针)</option>
              <option v-for="n in probeNodes" :key="n.id" :value="n.id">{{ n.name || n.id }}</option>
            </select>
          </div>
          <div class="field" style="max-width:130px">
            <label class="label">优先级(小=先)</label>
            <input class="input mono" type="number" v-model.number="form.priority" placeholder="0" :disabled="busy">
          </div>
          <div class="field" style="max-width:150px; align-self:flex-end">
            <label class="checkbox"><input type="checkbox" v-model="form.autoRetry" :disabled="busy"> 失败自动重分配</label>
          </div>
        </div>
        <div class="form-row" style="margin-top:4px">
          <div class="spacer"></div>
          <button class="btn primary" v-if="!busy"
            :disabled="!form.target || (form.mode === 'queue' && schedOff)"
            @click="start">
            {{ form.mode === 'queue' ? '排队提交' : '启动扫描' }}
          </button>
          <button class="btn danger" v-else-if="running" @click="stop">停止扫描</button>
          <button class="btn primary" v-else disabled>提交中...</button>
        </div>
        <!-- 排队提交的反馈: 入队是瞬时的(后端 emit 完 done 就关闭流), 结果在这里展示 -->
        <div class="login-err" v-if="form.mode === 'queue' && qErr" style="text-align:left">{{ qErr }}</div>
        <div class="muted small" v-if="form.mode === 'queue' && qMsg" style="margin-top:6px">{{ qMsg }}</div>
      </div>

      <!-- Web 漏洞库规则选择 (c8): 仅列 scope=web 规则, 勾选决定本次扫描启用哪些。
           默认全勾(= 全跑, 与旧行为一致); 敏感路径/安全头/注入等基线探测不受勾选影响。
           规则加载失败时不改变面板基线, 提交时回退为"全跑"(不改变扫描能力)。
           排队提交不携带规则勾选(调度 Params 无对应字段, 选了会被静默丢弃), 故仅立即模式显示。 -->
      <div class="card" v-if="form.type === 'web' && form.mode === 'now'">
        <div class="card-title">
          漏洞规则
          <span class="sub">Web 范围 · 基线探测不受勾选影响</span>
          <div class="spacer"></div>
          <span class="chip" :class="allWebEnabled ? 'on' : 'warn'" v-if="webRules.length">
            {{ selectedWebRuleIds.length }}/{{ webRules.length }}
          </span>
          <button class="btn xs" v-if="webRules.length" :disabled="busy || allWebEnabled" @click="setAllWebRules(true)">全选</button>
          <button class="btn xs" v-if="webRules.length" :disabled="busy || selectedWebRuleIds.length === 0" @click="setAllWebRules(false)">全不选</button>
          <button class="btn xs" :disabled="webRulesLoading || busy" @click="loadWebRules">
            <span class="spinner" v-if="webRulesLoading" style="width:11px;height:11px;border-width:1.5px"></span> 刷新
          </button>
          <button class="btn xs" @click="ruleDrawerOpen = true">规则库</button>
        </div>
        <div class="muted small err-line" v-if="webRulesErr">{{ webRulesErr }}</div>
        <div class="rule-list" v-if="webRules.length">
          <div v-for="r in webRules" :key="r.id" class="rule-row" :class="{ off: !r.enabled }">
            <label class="checkbox" style="flex:none; padding-top:2px">
              <input type="checkbox" :checked="r.enabled" :disabled="busy" @change="r.enabled = $event.target.checked">
            </label>
            <SevTag :sev="r.severity" />
            <div style="flex:1; min-width:0">
              <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap">
                <b class="small">{{ r.name }}</b>
                <span class="badge">{{ r.type }}</span>
                <span class="mono small muted" :title="'匹配模式: ' + r.pattern">{{ r.pattern }}</span>
              </div>
              <div class="muted small" style="margin-top:2px" v-if="r.detail" :title="r.detail">{{ r.detail }}</div>
            </div>
          </div>
        </div>
        <div class="empty" v-else style="min-height:56px">
          <span class="spinner" v-if="webRulesLoading" style="vertical-align:middle"></span>
          {{ webRulesLoading ? '正在加载 Web 范围规则…' : '暂无 Web 范围规则' }}
        </div>
      </div>

      <div class="grid cols-3">
        <!-- 事件日志: 本窗口扫描事件 + 全局广播(空闲时) 合并在同一框。
             全局流随页面自动接入; 扫描进行中主框已逐条展示本窗口事件,
             全局广播是同一批事件的回声, 期间不再重复渲染。 -->
        <div class="card" style="grid-column: span 2">
          <div class="card-title">
            事件日志
            <span class="chip" :class="running ? 'warn' : ''" style="font-size:11px">
              <span class="spinner" v-if="running" style="width:9px;height:9px;border-width:1.5px"></span>
              {{ running ? '扫描中' : '空闲(显示全局事件)' }}
            </span>
            <div class="spacer"></div>
            <button class="btn xs" @click="logs = []">清空</button>
          </div>
          <div class="log-box" ref="logBox">
            <div v-if="!logs.length" class="lg-muted">尚无事件, 配置参数后点击"启动扫描"</div>
            <div v-for="(l, i) in logs" :key="i" class="log-line" :class="l.cls">
              <span class="log-time">{{ l.time }}</span>{{ l.text }}
            </div>
          </div>
        </div>

        <!-- 漏洞结果: 本窗口会话结果仅对立即执行有意义; 排队任务的进度在
             "任务队列" tab 的任务表里看, 这里显示空值会让人误读"无发现"。 -->
        <div class="card" v-if="form.mode === 'now'">
          <div class="card-title">
            漏洞结果 <span class="sub">{{ findings.length }} 条</span>
            <div class="spacer"></div>
            <!-- 经典页迁移(P1-3): 导出"本次会话"HTML 报告(POST /api/report, 与报告中心的 DB 报告是两套口径) -->
            <button class="btn xs" v-if="!running && (findings.length || openPorts.length)" @click="reportOpen = true">导出报告</button>
            <!-- 阶段 3: AI 研判 —— 分析最近一次扫描的原始报告(扫描结束后自动存档,
                 后端按 module=scan 取 10 分钟内最新一份; 未启用/模块关闭自动置灰) -->
            <AiAnalyzeButton v-if="!running && (findings.length || openPorts.length)" module="scan" label="AI 研判" />
          </div>
          <div v-if="!findings.length" class="empty" style="min-height:120px">扫描命中后实时显示</div>
          <div v-else style="max-height:430px; overflow-y:auto">
            <div v-for="(f, i) in findings" :key="i" style="border-bottom:1px solid var(--border); padding:9px 2px">
              <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap">
                <SevTag :sev="f.severity" />
                <b style="font-size:12.5px" :title="f.title">{{ f.title }}</b>
                <span class="badge" v-if="f.falsePositive" style="color:var(--muted); border-style:dashed" :title="f.fpNote || '人工标记误报'">误报</span>
              </div>
              <div class="muted small mono" style="margin-top:3px" v-if="f.cve || f.host">{{ [f.cve, f.host && (f.host + (f.port ? ':' + f.port : ''))].filter(Boolean).join(' ') }}</div>
              <div class="small muted" style="margin-top:3px; word-break:break-all" v-if="f.detail">{{ f.detail }}</div>
              <div class="small" style="margin-top:4px; color:var(--green)" v-if="f.fix">修复: {{ f.fix }}</div>
              <div style="margin-top:6px">
                <button class="btn xs" v-if="!f.falsePositive" @click="markFP(f)">标记误报</button>
                <span class="muted small" v-else>已标记</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 开放端口结果行(P1-6): 命中弱口令检测支持的服务(redis/mysql/ftp/telnet)时,
           行内直接给「弱口令检测」按钮把目标带到 /weakpass, 免去用户手抄 IP:端口。
           不支持的端口不给按钮 —— 点了只会得到"协议不支持", 不如没有。 -->
      <div class="card" v-if="openPorts.length && form.mode === 'now'">
        <div class="card-title">
          开放端口
          <span class="sub">{{ openPorts.length }} 条</span>
          <div class="spacer"></div>
          <button class="btn xs" @click="openPorts = []">清空</button>
        </div>
        <div class="table-wrap" style="max-height:280px; overflow-y:auto">
          <table class="table">
            <thead><tr><th>地址</th><th>服务</th><th>横幅</th><th style="width:110px">操作</th></tr></thead>
            <tbody>
              <tr v-for="p in openPorts" :key="p.key">
                <td class="mono">{{ p.ip }}:{{ p.port }}</td>
                <td><span class="badge blue">{{ p.service || '-' }}</span></td>
                <td class="small muted mono" :title="p.banner">{{ p.banner || '-' }}</td>
                <td>
                  <button class="btn xs" v-if="p.weakSvc" @click="goWeakpass(p)">弱口令检测</button>
                  <span class="muted small" v-else>-</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- 报告导出弹窗(经典页迁移 P1-3): 标题/操作员 + 生成本次会话 HTML 报告 -->
      <Modal v-if="reportOpen" title="导出本次扫描报告" width="460px" @close="reportOpen = false">
        <div class="form-row">
          <div class="field">
            <label class="label">报告标题</label>
            <input class="input" v-model.trim="reportTitle" placeholder="Yugsight 漏洞扫描报告">
          </div>
          <div class="field" style="max-width:180px">
            <label class="label">操作员(可选)</label>
            <input class="input" v-model.trim="reportOperator">
          </div>
        </div>
        <div class="muted small" style="margin-top:8px">
          导出内容: 本次会话的 {{ findings.length }} 条发现(已排除标记的误报) + {{ openPorts.length }} 条开放端口。
          默认内置模板, 可放 exe 同目录 report_template.html 自定义。
        </div>
        <template #footer>
          <button class="btn sm" @click="reportOpen = false">取消</button>
          <button class="btn sm primary" :disabled="reportBusy" @click="exportReport">
            <span class="spinner" v-if="reportBusy"></span> 生成并下载
          </button>
        </template>
      </Modal>

      <RuleDrawer :open="ruleDrawerOpen" @close="ruleDrawerOpen = false" />
    </div>

    <!-- ===== 任务队列 tab(原「扫描任务管理」页, 排队提交表单已并入上方共用表单) ===== -->
    <div v-show="tab === 'queue'">
      <!-- 调度被显式关闭的提示: 调度默认启用, 正常看不到这条; 只有手动关掉后
           才出现, 告诉用户"怎么改回来"即可 -->
      <div class="alert warn" v-if="sched && !sched.enabled">
        调度已关闭(默认启用), 设 "enabled": true 后重启恢复。
        <button class="btn xs" style="margin-left:8px" @click="copySchedOn">{{ schedCopied ? '已复制' : '一键复制' }}</button>
      </div>

      <!-- 调度任务列表 -->
      <div class="card">
        <div class="toolbar">
          <span class="muted small">调度任务</span>
          <select class="select" v-model="taskFilter" @change="taskPage=1; loadTasks()">
            <option value="">全部状态</option>
            <option value="queued">排队中</option>
            <option value="running">运行中</option>
            <option value="paused">已暂停</option>
            <option value="success">已完成</option>
            <option value="failed">已失败</option>
            <option value="cancelled">已取消</option>
          </select>
          <button class="btn sm" :disabled="taskLoading" @click="loadTasks"><span class="spinner" v-if="taskLoading"></span> 刷新</button>
          <label class="checkbox"><input type="checkbox" v-model="taskAuto"> 自动刷新(4s)</label>
          <div class="spacer"></div>
          <span class="muted small">共 {{ taskTotal }} 个 · 队列 {{ (taskData.queue || []).length }} · 槽位 {{ stats.slots || 0 }}/{{ stats.maxSlots || 0 }}</span>
        </div>

        <div class="table-wrap" v-if="tasks.length">
          <table class="table">
            <thead>
              <tr>
                <th>ID</th><th>类型</th><th>目标</th><th>策略</th><th>节点</th><th>状态</th>
                <th>优先级</th><th>进度 / 结果</th><th>耗时</th><th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="t in tasks" :key="t.id">
                <td class="mono small">{{ t.id }}</td>
                <td class="small">{{ KIND_NAME[t.kind] || t.kind }}</td>
                <td class="mono small" :title="t.target">{{ t.target }}</td>
                <td class="small">{{ t.strategy || '-' }}</td>
                <td class="small">{{ t.node || '中心本地' }}</td>
                <td><span class="badge" :class="schedClass(t.status)">{{ SCHED_STATUS[t.status] || t.status }}</span></td>
                <td class="small mono">{{ t.priority || 0 }}</td>
                <td class="small" :title="t.result || t.err || t.progress || ''">
                  {{ short(t.progress || t.result || t.err || '-') }}
                </td>
                <td class="muted small mono">{{ costText(t) }}</td>
                <td>
                  <div class="row-actions">
                    <button class="btn xs" v-if="t.status === 'queued' || t.status === 'running'" @click="act('pause', t)">暂停</button>
                    <button class="btn xs green" v-if="t.status === 'paused'" @click="act('resume', t)">恢复</button>
                    <button class="btn xs danger" v-if="t.status === 'queued' || t.status === 'running' || t.status === 'paused'" @click="act('cancel', t)">取消</button>
                    <button class="btn xs" v-if="t.status === 'failed' || t.status === 'cancelled'" @click="act('retry', t)">重试</button>
                    <button class="btn xs danger" @click="delTask(t)">删除</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty" style="min-height:120px">
          暂无调度任务
          <div style="margin-top:8px">
            <button class="btn xs" @click="goQueueForm">去"立即扫描"排队提交</button>
          </div>
        </div>

        <div class="pager" v-if="taskTotal > taskPage * taskSize">
          <span>第 {{ taskPage }} 页</span>
          <div class="spacer"></div>
          <button class="btn xs" :disabled="taskPage <= 1" @click="taskPage--; loadTasks()">上一页</button>
          <button class="btn xs" :disabled="taskPage * taskSize >= taskTotal" @click="taskPage++; loadTasks()">下一页</button>
        </div>
      </div>

      <!-- 策略模板 + 限速统计 -->
      <div class="grid cols-2">
        <div class="card">
          <div class="card-title">
            策略模板 <span class="sub">GET /api/v2/scheduler/strategies</span>
            <div class="spacer"></div>
            <button class="btn xs" @click="loadStrategies">刷新</button>
          </div>
          <div v-if="!strategies.length" class="empty" style="min-height:80px">暂无策略模板</div>
          <div v-for="s in strategies" :key="s.id" style="border-bottom:1px solid var(--border); padding:9px 2px">
            <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap">
              <b class="small">{{ s.name }}</b>
              <span class="badge mono">{{ s.id }}</span>
              <span class="badge">{{ KIND_NAME[s.kind] || s.kind }}</span>
              <span class="chip" v-if="s.priority">优先级 {{ s.priority }}</span>
            </div>
            <div class="muted small" style="margin-top:3px">{{ s.description }}</div>
            <div class="muted small mono" style="margin-top:3px">
              端口 {{ short(s.defaults && s.defaults.ports || '-', 40) }} ·
              超时 {{ (s.defaults && s.defaults.timeoutMs) || '-' }}ms ·
              并发 {{ (s.defaults && s.defaults.concurrency) || '-' }} ·
              限速 {{ (s.defaults && s.defaults.rate) || 0 }}pps
            </div>
          </div>
          <div class="muted small" style="margin-top:10px">
            端口集: 存活 <span class="mono">{{ short(strategyPorts.alive, 40) }}</span> ·
            常用 <span class="mono">{{ short(strategyPorts.common, 40) }}</span> ·
            Web <span class="mono">{{ short(strategyPorts.web, 40) }}</span>
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            限速统计 <span class="sub">GET /api/v2/scheduler/rate</span>
            <div class="spacer"></div>
            <span class="chip blue">默认 {{ rateDefault || 0 }} pps</span>
            <button class="btn xs" @click="loadRate">刷新</button>
          </div>
          <div v-if="!rateRows.length" class="empty" style="min-height:80px">暂无活动网段(任务跑起来后按源网段分桶)</div>
          <div v-for="r in rateRows" :key="r.net" class="bar-row">
            <span class="bar-label mono">{{ r.net }}</span>
            <span class="bar-track">
              <span class="bar-fill" :style="{ width: barWidth(r) + '%', background: 'var(--accent)' }"></span>
            </span>
            <span class="bar-val">{{ r.rate || 0 }}pps</span>
            <span class="badge">{{ r.source === 'rule' ? '网段规则' : '全局默认' }}</span>
            <span class="muted small mono">令牌 {{ (r.tokens || 0).toFixed(0) }}</span>
          </div>
          <div class="card-title" style="margin-top:12px">网段规则 <span class="sub">{{ rateRules.length }} 条</span></div>
          <div v-if="!rateRules.length" class="muted small">未配置专属网段速率, 全部走默认</div>
          <div v-for="(r, i) in rateRules" :key="i" class="mono small" style="padding:3px 0">
            {{ r.cidr }} → {{ r.rate > 0 ? r.rate + ' pps' : '不限速' }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, nextTick, onMounted, onBeforeUnmount, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import SevTag from '../components/SevTag.vue'
import RuleDrawer from '../components/RuleDrawer.vue'
import Modal from '../components/Modal.vue'
import AiAnalyzeButton from '../components/AiAnalyzeButton.vue'
import { api, v2 } from '../api/http'
import { SEV_NAME, copyText } from '../utils'
import { SCAN_TYPES, typeToKind, TARGET_LABEL, TARGET_PH, KIND_NAME } from '../utils/scanTypes'

const route = useRoute()
const router = useRouter()

// tab 状态放在 URL query 上(先例 /env?tab=rules): 刷新/书签/手工输 URL 都能停在
// 同一 tab。只有 'queue' 是队列 tab, 其它取值(含空)一律落"立即扫描" —— 旧书签
// /console 直接打开不受影响; /scans 由路由重定向到 /console?tab=queue。
const tab = computed(() => (route.query.tab === 'queue' ? 'queue' : 'scan'))
// replace 而非 push: 切 tab 不该往历史栈里堆记录(浏览器后退应是"离开本页", 不是"回到上一个 tab")
function setTab(t) {
  if (t === tab.value) return
  router.replace({ path: '/console', query: t === 'queue' ? { tab: 'queue' } : {} })
}
// 任务队列空态的"去提交"入口: 切回立即扫描 tab 并预选"排队执行"
function goQueueForm() {
  form.mode = 'queue'
  setTab('scan')
}

// 弱口令检测支持的端口 -> 服务名(与 weakpass 包的支持列表一致)。
// 只有这些端口的行才出现「弱口令检测」按钮: 其它端口点了只会得到"协议不支持"。
const WEAKPASS_PORT = { 6379: 'redis', 3306: 'mysql', 21: 'ftp', 23: 'telnet' }
const openPorts = ref([]) // {key, ip, port, service, banner, weakSvc}

function addOpenPort(ip, port, service, banner) {
  if (!ip || !port) return
  const key = ip + ':' + port
  if (openPorts.value.some(p => p.key === key)) return
  openPorts.value.push({
    key, ip, port: Number(port),
    service: service || '',
    banner: String(banner || '').slice(0, 90),
    weakSvc: WEAKPASS_PORT[Number(port)] || ''
  })
}

// 带上服务名是刻意的: Weakpass 页按 host:port[:service] 解析, 端口映射在那一侧也有,
// 但显式带上可避免"端口被改过却仍按默认服务试探"。
function goWeakpass(p) {
  router.push({ path: '/weakpass', query: { targets: p.ip + ':' + p.port, service: p.weakSvc } })
}

// ===== 经典页迁移(P1-3): Nuclei 外部模板热重载 =====
async function reloadNuclei() {
  try {
    const d = await api('/api/nuclei/reload', { method: 'POST' })
    addLog(`Nuclei 模板已重载: 共 ${d.total || 0} 条(内置 ${d.builtin || 0} / 外部 ${d.external || 0})`, 'lg-blue')
  } catch (e) { addLog('Nuclei 模板重载失败: ' + e.message, 'lg-orange') }
}

// ===== 经典页迁移(P1-3): 导出本次会话 HTML 报告 =====
// 与"报告中心"(基于 DB 的 v2 报告)是两套口径: 这里是"扫完立即导出本窗口结果",
// 数据就取自本页内存里的 findings/openPorts, 不依赖落库。
const reportOpen = ref(false)
const reportBusy = ref(false)
const reportTitle = ref('Yugsight 漏洞扫描报告')
const reportOperator = ref('')
let scanStartAt = 0   // 本次扫描开始时刻(报告里的 startTime/duration 口径)

function buildScanEntry() {
  // 排除已标记误报的项(与经典页 selectedScans 同口径: 白名单命中服务端已过滤, 这里只剩误报)
  const f = findings.value.filter(x => !x.falsePositive).map(x => ({
    severity: String(x.severity || 'info').toLowerCase(),
    title: x.title || '', detail: x.detail || '', fix: x.fix || '', source: x.source || ''
  }))
  const rows = openPorts.value.map(p => [p.ip + ':' + p.port, p.service || '-', p.banner || '-'])
  // 类型名统一取 scanTypes 常量(合并前这里是第四份手写文案)
  const t = SCAN_TYPES.find(x => x.value === form.type)
  const dur = scanStartAt ? Math.max(0, Math.round((Date.now() - scanStartAt) / 100) / 10) + 's' : ''
  return {
    type: form.type,
    target: form.target,
    typeName: t ? t.label : form.type,
    startTime: scanStartAt ? new Date(scanStartAt).toLocaleString('zh-CN', { hour12: false }) : '',
    duration: dur,
    summary: `发现 ${f.length} 条 · 开放端口 ${openPorts.value.length} 条`,
    rowHead: rows.length ? ['地址', '服务', '横幅'] : [],
    rows,
    findings: f
  }
}

async function exportReport() {
  reportBusy.value = true
  try {
    const r = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: reportTitle.value || 'Yugsight 漏洞扫描报告', operator: reportOperator.value, scans: [buildScanEntry()] })
    })
    if (!r.ok) {
      let msg = 'HTTP ' + r.status
      try { msg = (await r.json()).error || msg } catch (e) { /* 保留 HTTP 状态 */ }
      alert('报告生成失败: ' + msg)
      return
    }
    const blob = await r.blob()
    let name = 'yugsight_report.html'
    const m = (r.headers.get('Content-Disposition') || '').match(/filename="?([^";]+)/)
    if (m) name = m[1]
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = name
    a.click()
    URL.revokeObjectURL(a.href)
    reportOpen.value = false
    addLog('报告已导出: ' + name, 'lg-green')
  } catch (e) {
    alert('报告生成失败: ' + e.message)
  } finally { reportBusy.value = false }
}

// 共用提交表单: type/target/ports 等扫描参数两模式通用; mode 决定路径;
// strategy/queueNode/priority/autoRetry 仅排队模式使用(调度参数, 即时执行无意义)。
const form = reactive({
  type: 'quick', target: '', ports: '', timeoutMs: 1500, concurrency: 200,
  aliveMode: 'loose', aliveOnly: false, enableNuclei: false, nucleiTags: '',
  nucleiTagsExclude: '',
  webdeep: false,
  mode: 'now', strategy: '', queueNode: '', priority: 0, autoRetry: true
})
const running = ref(false) // 立即执行中(SSE 长流)
const qBusy = ref(false)   // 排队提交中(瞬时流)
const busy = computed(() => running.value || qBusy.value)
const qErr = ref('')
const qMsg = ref('')
const logs = ref([])
const findings = ref([])
const logBox = ref(null)
let controller = null
let evtSource = null

// c8: Web 漏洞库规则选择(仅 web 类型)。默认全勾 = 全跑, 与旧行为一致。
const webRules = ref([]) // {id,name,severity,type,pattern,detail,enabled}
const webRulesLoading = ref(false)
const webRulesErr = ref('')
let webRulesLoaded = false
const ruleDrawerOpen = ref(false)

const targetLabel = computed(() => TARGET_LABEL[form.type] || '目标')
const targetPh = computed(() => TARGET_PH[form.type] || '')

// ===== c8: Web 漏洞库规则选择 =====
const selectedWebRuleIds = computed(() => webRules.value.filter(r => r.enabled).map(r => r.id))
const allWebEnabled = computed(() => webRules.value.length > 0 && webRules.value.every(r => r.enabled))

async function loadWebRules() {
  webRulesLoading.value = true
  webRulesErr.value = ''
  try {
    const d = await api('/api/vuln/rules')
    // 只保留 Web 范围规则: scope 已由后端归一化为 web/host, 缺失时按 type 推导(web)
    const rules = (d.rules || []).filter(r => (r.scope || 'web') === 'web')
    webRules.value = rules.map(r => ({ ...r, enabled: true })) // 默认全勾 = 全跑
    webRulesLoaded = true
  } catch (e) {
    webRulesErr.value = '规则加载失败: ' + e.message
  } finally {
    webRulesLoading.value = false
  }
}

function setAllWebRules(enabled) {
  webRules.value.forEach(r => { r.enabled = enabled })
}

// 切到 web 类型且尚未加载时拉取一次(避免每次切换都请求)
watch(() => form.type, (t) => {
  if (t === 'web' && !webRulesLoaded) loadWebRules()
})

function nowStr() {
  return new Date().toTimeString().slice(0, 8)
}

function addLog(text, cls = 'lg-blue') {
  logs.value.push({ time: nowStr(), text, cls })
  if (logs.value.length > 800) logs.value.splice(0, logs.value.length - 800)
  nextTick(() => { if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight })
}

// 事件 -> 日志行 (与经典页 handleEvent 同口径)
function renderEvent(ev, d) {
  if (ev === 'status') {
    addLog(d.msg || '', 'lg-blue')
  } else if (ev === 'ip') {
    if (!d.alive) return
    // 三路证据如实展示: ICMP 应答 / ARP 应答 / 仅端口推断(严格模式下后者不计入存活)
    const via = d.icmp ? 'ICMP ' + (d.rttMs || 0) + 'ms'
      : d.arp ? 'ARP ' + (d.mac || '')
      : (d.inferred ? 'TCP 端口推断' : 'TCP')
    const tail = d.excludedByStrict ? '  [严格模式未计入存活]' : ''
    addLog(`存活 ${d.ip}  端口: ${(d.ports || []).join(', ') || '-'}  ${via}${tail}`,
      d.excludedByStrict ? 'lg-yellow' : 'lg-green')
    ;(d.ports || []).forEach(pt => addOpenPort(d.ip, pt, '', ''))
  } else if (ev === 'port') {
    if (d.state === 'open') {
      addLog(`开放 ${d.ip}:${d.port}  ${d.service || ''}  ${d.latencyMs != null ? d.latencyMs + 'ms' : ''}  ${d.banner || ''}`.trim(), 'lg-green')
      addOpenPort(d.ip, d.port, d.service, d.banner)
    }
  } else if (ev === 'finding') {
    findings.value.unshift({ ...d })
    const cve = d.cve ? ' [' + d.cve + ']' : ''
    const src = d.source === 'nuclei' ? ' [外部模板]' : (d.source === 'nuclei-builtin' ? ' [内置模板]' : '')
    const sev = String(d.severity || 'info').toLowerCase()
    addLog(`[${SEV_NAME[sev] || sev}] ${d.title}${cve}${src}${d.falsePositive ? ' [误报]' : ''}`, sev === 'critical' ? 'lg-critical' : (sev === 'high' ? 'lg-red' : sev === 'medium' ? 'lg-orange' : sev === 'low' ? 'lg-yellow' : 'lg-blue'))
  } else if (ev === 'ai') {
    if (d.stage === 'start') addLog('AI 分析开始', 'lg-purple')
    else if (d.delta) addEvtAI(d.delta)
    else if (d.stage === 'done') addLog('AI 分析完成', 'lg-purple')
  } else if (ev === 'hello') {
    // 原代码此处误写 addEvtLog(未定义), 被外层 try/catch 吞成"解析失败"; 统一走 addLog
    addLog(d.msg || '已接入 SSE 事件流', 'lg-muted')
  } else if (ev === 'done') {
    addLog('=== ' + (d.msg || '完成') + ' ===', 'lg-green')
  } else {
    addLog(ev + ': ' + JSON.stringify(d), 'lg-muted')
  }
}

let aiBuf = ''
function addEvtAI(delta) {
  // AI 流式: 追加到最后一行 AI 日志
  aiBuf += delta
  const last = logs.value[logs.value.length - 1]
  if (last && last.cls === 'lg-purple' && last.ai) {
    last.text += delta
  } else {
    logs.value.push({ time: nowStr(), text: delta, cls: 'lg-purple', ai: true })
  }
  if (logs.value.length > 800) logs.value.splice(0, logs.value.length - 800)
  nextTick(() => { if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight })
}

// 立即执行 payload: quick → 统一扫描引擎(unified); "仅存活检查"映射到 ip 类型(不枚举端口)
function payload() {
  const p = {
    type: typeToKind(form.type, form.aliveOnly),
    timeoutMs: form.timeoutMs || 1500,
    concurrency: form.concurrency || 200
  }
  if (form.type === 'quick') {
    p.cidr = form.target; p.ports = form.ports; p.aliveMode = form.aliveMode
  }
  if (form.type === 'host') { p.ip = form.target; p.ports = form.ports }
  if (form.type === 'web') {
    p.url = form.target
    p.webdeep = form.webdeep
    // c8: 规则选择成功加载时才下发"只跑勾选的规则"; 加载失败则不下发 ruleMode,
    // 后端回退到"全跑"(降级不改变扫描基线能力, 见 WebScan 的 ruleFilter 约定)。
    if (webRulesLoaded) {
      p.ruleMode = 'selected'
      p.selectedRules = selectedWebRuleIds.value
    }
  }
  if (form.type === 'host') {
    p.enableNuclei = !!form.enableNuclei
    p.nucleiTags = form.nucleiTags
    p.nucleiTagsExclude = form.nucleiTagsExclude
  }
  return p
}

async function start() {
  if (!form.target) return
  if (form.mode === 'queue') { submitQueued(); return }
  running.value = true
  logs.value = []
  findings.value = []
  openPorts.value = []
  aiBuf = ''
  scanStartAt = Date.now() // 报告里的开始时间/耗时口径
  const p = payload()
  addLog('启动扫描: ' + p.type + ' -> ' + form.target, 'lg-blue')

  controller = new AbortController()
  const t0 = Date.now()
  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(p),
      signal: controller.signal
    })
    if (!resp.ok) {
      addLog('服务器错误: HTTP ' + resp.status, 'lg-red')
      finish()
      return
    }
    const reader = resp.body.getReader()
    const dec = new TextDecoder()
    let buf = ''
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buf += dec.decode(value, { stream: true })
      let i
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const chunk = buf.slice(0, i)
        buf = buf.slice(i + 2)
        let ev = 'message', data = ''
        for (const line of chunk.split('\n')) {
          if (line.startsWith('event: ')) ev = line.slice(7)
          else if (line.startsWith('data: ')) data += line.slice(6)
        }
        if (data) {
          try { renderEvent(ev, JSON.parse(data)) }
          catch (e) { addLog('解析失败: ' + data, 'lg-red') }
        }
      }
    }
    addLog('用时 ' + ((Date.now() - t0) / 1000).toFixed(1) + 's', 'lg-muted')
    finish()
  } catch (e) {
    if (e.name === 'AbortError') {
      addLog('已手动停止, 用时 ' + ((Date.now() - t0) / 1000).toFixed(1) + 's', 'lg-orange')
    } else {
      addLog('请求失败: ' + e.message, 'lg-red')
    }
    finish()
  }
}

function finish() {
  running.value = false
}

function stop() {
  if (controller) controller.abort()
}

async function markFP(f) {
  const note = prompt('误报备注(可选):', '')
  if (note === null) return
  try {
    await api('/api/vuln/fps/mark', {
      method: 'POST',
      body: { assetIp: f.host || '', cve: f.cve || '', title: f.title || '', note: note || '' }
    })
    f.falsePositive = true
    f.fpNote = note
    addLog('已标记误报: ' + f.title, 'lg-orange')
  } catch (e) { alert(e.message) }
}

// ===== 全局事件流(EventSource, 页面加载即自动接入) =====
// 多窗口同步: 空闲时其它窗口的扫描事件会带 [全局] 前缀出现在事件日志里;
// 本窗口扫描进行中, 全局广播是本窗口事件的回声, 跳过不重复渲染。
function connectGlobal() {
  if (evtSource) return
  evtSource = new EventSource('/api/events')
  const names = ['hello', 'status', 'finding', 'done', 'error']
  for (const n of names) {
    evtSource.addEventListener(n, (e) => {
      if (running.value) return
      let d = {}
      try { d = JSON.parse(e.data) } catch (err) { return }
      if (n === 'finding') addLog('[全局] ' + (d.title || '') + ' ' + (d.cve || ''), 'lg-red')
      else if (n === 'status') addLog('[全局] ' + (d.msg || ''), 'lg-blue')
      else if (n === 'done') addLog('[全局] ' + (d.msg || '完成'), 'lg-green')
      else if (n === 'hello') addLog('[全局] ' + (d.msg || '已接入全局事件流'), 'lg-muted')
      else if (n === 'error') addLog('[全局] ' + (d.msg || '事件流异常'), 'lg-orange')
    })
  }
  evtSource.onerror = () => {
    if (!running.value) addLog('[全局] 事件流连接异常, 浏览器将自动重连', 'lg-orange')
  }
}

function disconnectEvt() {
  if (evtSource) { evtSource.close(); evtSource = null }
}

// ===== 任务队列(原「扫描任务管理」页的调度数据, 合并后与原页同口径) =====

// 调度任务状态比通用 STATUS_NAME 多 queued/paused 两态(见 scheduler/types.go),
// 不能复用 STATUS_NAME —— 那里没有这两个取值, 会直接把英文原文显示给用户。
const SCHED_STATUS = {
  queued: '排队中', running: '运行中', paused: '已暂停',
  success: '已完成', failed: '已失败', cancelled: '已取消'
}

const sched = ref(null)
const schedOn = computed(() => sched.value !== null && !!sched.value.enabled)
const schedOff = computed(() => sched.value !== null && !sched.value.enabled)
const stats = computed(() => (taskData.value && taskData.value.stats) || (sched.value && sched.value.stats) || {})
const taskData = ref({})
const tasks = ref([])
const taskTotal = ref(0)
const taskPage = ref(1)
const taskSize = 20
const taskLoading = ref(false)
const taskFilter = ref('')
const taskAuto = ref(true)

const strategies = ref([])
const strategyPorts = ref({})
const rateRows = ref([])
const rateRules = ref([])
const rateDefault = ref(0)
const schedNodes = ref([])
// 执行节点下拉只列探针(kind=probe): 中心本地已由空值表达, 列出来会出现两个"本地"
const probeNodes = computed(() => schedNodes.value.filter(n => n.kind === 'probe'))

// 审计 §4-5: 配置指引给一键复制而不是让用户手抄 JSON 片段
const schedSnippet = '{ "scheduler": { "enabled": true } }'
const schedCopied = ref(false)
async function copySchedOn() {
  if (await copyText(schedSnippet)) {
    schedCopied.value = true
    setTimeout(() => { schedCopied.value = false }, 2000)
  }
}

function schedClass(s) {
  return {
    queued: 'st-pending', running: 'st-running', paused: 'st-duplicate',
    success: 'st-success', failed: 'st-failed', cancelled: 'st-cancelled'
  }[s] || ''
}
function short(s, n = 46) {
  const v = String(s || '-')
  return v.length > n ? v.slice(0, n) + '…' : v
}
function costText(t) {
  const q = t.queuedMs ? (t.queuedMs / 1000).toFixed(1) + 's' : '-'
  const r = t.runMs ? (t.runMs / 1000).toFixed(1) + 's' : '-'
  return '排队 ' + q + ' / 执行 ' + r
}
// 令牌桶占用率: 桶容量 = 速率(1 秒的令牌), 故 tokens/rate 即剩余可用比例。
// 速率为 0(不限速)时无"占用"概念, 返回 0 宽度而不是 NaN。
function barWidth(r) {
  if (!r || !r.rate) return 0
  const pct = (Number(r.tokens || 0) / r.rate) * 100
  return Math.max(0, Math.min(100, pct))
}

async function loadSched() {
  try { sched.value = await v2('/scheduler/status') } catch (e) { sched.value = null }
}

async function loadTasks() {
  taskLoading.value = true
  try {
    const p = new URLSearchParams({ page: String(taskPage.value), size: String(taskSize) })
    if (taskFilter.value) p.set('status', taskFilter.value)
    const d = await v2('/scheduler/tasks?' + p.toString())
    taskData.value = d || {}
    tasks.value = d.items || []
    taskTotal.value = d.total || 0
  } catch (e) { tasks.value = []; taskTotal.value = 0 } finally { taskLoading.value = false }
}

async function loadStrategies() {
  try {
    const d = await v2('/scheduler/strategies')
    strategies.value = d.strategies || []
    strategyPorts.value = d.ports || {}
  } catch (e) { strategies.value = [] }
}

async function loadRate() {
  try {
    const d = await v2('/scheduler/rate')
    rateRows.value = d.rows || []
    rateRules.value = d.rules || []
    rateDefault.value = d.default || 0
  } catch (e) { rateRows.value = []; rateRules.value = [] }
}

async function loadNodes() {
  try {
    const d = await v2('/scheduler/nodes')
    schedNodes.value = d.nodes || []
  } catch (e) { schedNodes.value = [] }
}

// 排队提交: 走 /api/scan 的 SSE 流(与立即执行同一路径), 只取 status/done 两条事件。
// 入队是瞬时的(后端 emit 完 done 就关闭流), 不需要 AbortController 中断长扫描。
// 口径与原「扫描任务管理」页一致: quick → unified/ip; 目标字段按类型落 cidr/url/ip。
async function submitQueued() {
  qErr.value = ''
  qMsg.value = ''
  if (!form.target) { qErr.value = '目标不能为空'; return }
  qBusy.value = true
  const body = {
    type: typeToKind(form.type, form.aliveOnly),
    queue: true,
    strategy: form.strategy,
    queueNode: form.queueNode,
    priority: Number(form.priority) || 0,
    autoRetry: !!form.autoRetry
  }
  if (form.type === 'quick') body.cidr = form.target
  else if (form.type === 'web') body.url = form.target
  else body.ip = form.target
  if (form.ports.trim()) body.ports = form.ports.trim()
  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
    if (!resp.ok) { qErr.value = '服务器错误: HTTP ' + resp.status; return }
    const reader = resp.body.getReader()
    const dec = new TextDecoder()
    let buf = ''
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buf += dec.decode(value, { stream: true })
      let i
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const chunk = buf.slice(0, i)
        buf = buf.slice(i + 2)
        let ev = 'message', data = ''
        for (const ln of chunk.split('\n')) {
          if (ln.startsWith('event: ')) ev = ln.slice(7)
          else if (ln.startsWith('data: ')) data += ln.slice(6)
        }
        if (!data) continue
        let d = {}
        try { d = JSON.parse(data) } catch (e) { continue }
        if (ev === 'status') {
          qMsg.value = d.msg || ''
          if (d.taskId) qMsg.value += '  任务 ID: ' + d.taskId
        } else if (ev === 'done') {
          if (d.queued) qMsg.value = '已入队, 任务 ID: ' + (d.taskId || '-')
          else if (!d.ok) qErr.value = d.msg || '入队失败'
        }
      }
    }
    addLog(qErr.value ? '排队提交失败: ' + qErr.value : '排队提交: ' + qMsg.value, qErr.value ? 'lg-orange' : 'lg-green')
    await loadTasks()
  } catch (e) {
    qErr.value = '提交失败: ' + e.message
  } finally { qBusy.value = false }
}

async function act(kind, t) {
  try {
    await v2('/scheduler/' + kind, { method: 'POST', body: { id: t.id } })
    await loadTasks()
  } catch (e) { alert(e.message) }
}

async function delTask(t) {
  if (!confirm('确认删除调度任务 ' + t.id + ' ?')) return
  try { await v2('/scheduler/tasks/' + encodeURIComponent(t.id), { method: 'DELETE' }); await loadTasks() }
  catch (e) { alert(e.message) }
}

let timer = null
onMounted(() => {
  connectGlobal()
  // 任务队列数据: 调度状态 / 任务 / 策略 / 限速 / 节点(原任务管理页同口径)
  loadSched()
  loadTasks()
  loadStrategies()
  loadRate()
  loadNodes()
  // 轮询 4s: 调度状态是"变动中的"(排队→运行→完成), 比资产类页面需要更快刷新
  timer = setInterval(() => {
    if (!taskAuto.value) return
    loadTasks()
    loadRate()
  }, 4000)
})
onBeforeUnmount(() => {
  if (controller) controller.abort()
  disconnectEvt()
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
.err-line { color: var(--red); min-height: 14px; }
.rule-list { max-height: 300px; overflow-y: auto; margin-top: 4px; }
.rule-row {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 8px 10px; margin-top: 6px;
  border: 1px solid var(--border); border-radius: 6px;
}
.rule-row:hover { border-color: var(--accent); }
.rule-row.off { opacity: 0.5; }
/* 主题里 .spacer 的 flex:1 只定义在 .toolbar/.pager 下, 卡片标题栏用它右对齐
   操作按钮时需要补一条(不改动全局样式表, 避免波及既有页面)。 */
.card-title .spacer { flex: 1; }
</style>

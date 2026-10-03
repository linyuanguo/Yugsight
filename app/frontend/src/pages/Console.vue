<template>
  <div>
    <!-- 菜单 B 方案(2026-09-22): 原「实时扫描控制台」与「扫描任务管理」合并为一页。
         提交区共用一张表单, "提交方式: 立即执行 | 排队执行"决定后端路径:
         立即 → /api/scan SSE 实时流(原控制台行为); 排队 → 同一端点 queue=true,
         调度器按并发/限速/节点派发(原任务管理行为)。后端契约零改, 纯前端合并。
         tab 状态放在 URL query 上(先例 /env?tab=rules): 刷新/书签/手工输 URL 都停在同一 tab。 -->
    <PageHeader title="扫描作业" desc="命名扫描: 任务名 + IP/子网 快速发现 → 勾选扫出的主机 → 主机漏扫 / web 漏扫 / 弱口令 / 渗透(同一任务名); 报告中心按任务名生成报告"></PageHeader>
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
          <!-- 2026-09-25 用户口径: 命名扫描 —— 立即扫描必须先输入任务名。
               任务名是结果聚合键: 漏洞/资产/原始报告都按它打标, 报告中心按任务名
               生成报告/分类原始报告; 同一任务名可分多步扫(快速发现→漏扫→弱口令→渗透)。 -->
          <div class="field" style="max-width:230px">
            <label class="label">扫描任务名 *</label>
            <input class="input" v-model.trim="form.jobName" placeholder="报告按此名生成, 如: 办公网 9 月巡检" :disabled="busy" maxlength="64" @keyup.enter="start">
          </div>
          <div class="field">
            <label class="label">{{ targetLabel }}{{ targetRequired ? ' *' : '' }}</label>
            <input class="input mono" v-model.trim="form.target" :placeholder="targetPh" :disabled="busy" @keyup.enter="start">
          </div>
          <!-- 2026-09-27 全扫(any): 存活扫描入口升级 —— 无需预先指定目标网段,
               自动探测执行节点(本地=中心端 / 下发探针=探针)所在网络环境的全部
               网段。保留原网段输入框(上面), 按钮点击即执行全网段存活探测:
               写入 target=any(后端 ip/alive 分支识别并展开)并自动勾"仅存活检查"。 -->
          <div class="field" v-if="form.type === 'quick'" style="align-self:flex-end">
            <button class="btn sm" :disabled="busy" @click="fullScan"
                    title="无需填网段: 自动探测执行节点(中心端/探针)本机所有网段并扫描存活主机">全扫</button>
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
        <!-- 2026-09-27: 执行位置(用户口径: 主机漏扫/Web 漏扫等也要能选探针端执行)。
             探针端不是"只能用内置": 它用内置引擎 + Nuclei 模板 + 探针主机 bin/ 目录
             安装的外部引擎(nmap/zap/trivy)执行, 结果回传中心端, 与本地执行同口径落库。
             唯一例外: 快速发现的完整模式(unified 引擎)探针端没有对应实现, 不给选项,
             提示改用"仅存活检查"(ip)或主机漏扫。 -->
        <div class="form-row" style="align-items:flex-end">
          <div class="field" style="max-width:180px">
            <label class="label">执行位置</label>
            <select class="select" v-model="form.execAt" :disabled="busy || !probeAllowed">
              <option value="local">本地中心端</option>
              <option value="probe" :disabled="!probeOnline.length">下发到探针</option>
            </select>
          </div>
          <div class="field" style="max-width:200px" v-if="form.execAt === 'probe'">
            <label class="label">目标探针</label>
            <select class="select" v-model="form.execProbeNode" :disabled="busy || !probeOnline.length">
              <option value="">选择探针…</option>
              <option v-for="n in probeOnline" :key="n.id" :value="n.id">{{ n.name || n.id }}</option>
            </select>
          </div>
          <div class="field" v-if="form.execAt === 'probe' && probeOnline.length">
            <span class="muted small">由探针主机执行: 内置引擎 + Nuclei + 该主机 bin/ 目录的外部引擎(nmap/zap/trivy), 结果回传中心端。</span>
          </div>
          <div class="field" v-if="form.execAt === 'probe' && !probeOnline.length">
            <span class="muted small" style="color:var(--warn)">无在线探针(需中心端启用探针中心且探针已上线, 见探针管理页)</span>
          </div>
          <div class="field" v-if="!probeAllowed">
            <span class="muted small" title="探针端没有 unified 统一引擎(只有 ip/alive/port/web/host/sca 任务类型)">快速发现完整模式不支持探针执行 —— 勾"仅存活检查"或改用主机漏扫</span>
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
          <!-- 2026-09-27: 全扫入口说明(执行节点=本地中心端或所选调度探针) -->
          <span class="muted small">点「全扫」= 自动探测执行节点所在网络环境的全部网段做存活检查, 无需指定网段</span>
        </div>
        <div class="form-row" v-if="form.type === 'host'">
          <!-- 2026-09-26: 探测引擎多选(内置 + nmap 可同时勾选, 各引擎跑完整流程,
               结果自动合并去重; 单勾时走老单引擎语义含降级)。与"漏洞引擎"(nuclei)正交 -->
          <div class="field" style="max-width:300px">
            <label class="label">探测引擎(端口/服务)</label>
            <div style="display:flex; gap:14px; padding-top:2px">
              <label class="checkbox"><input type="checkbox" v-model="form.engHostBuiltin" :disabled="busy" @change="guardEngine('host')"> 内置(快)</label>
              <label class="checkbox"><input type="checkbox" v-model="form.engHostNmap" :disabled="busy || !engineFound.nmap" @change="guardEngine('host')"> nmap(全){{ engineFound.nmap ? '' : '(未安装,去引擎页装)' }}</label>
            </div>
            <div class="muted small" style="margin-top:3px">内置: 快速端口/服务探测; nmap: 全探测(SYN 半开+服务版本)。同时勾选 = 双引擎各跑一遍, 结果自动合并去重。</div>
          </div>
          <div class="field" style="max-width:320px">
            <label class="checkbox"><input type="checkbox" v-model="form.enableNuclei" :disabled="busy">
              漏洞引擎: Nuclei 模板扫描(与探测引擎叠加)</label>
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
          <!-- 2026-09-26: web 扫描引擎多选(内置规则 + ZAP 可同时勾选, 各引擎跑完整流程,
               结果自动合并去重; 单勾时走老单引擎语义含降级) -->
          <div class="field" style="max-width:300px">
            <label class="label">扫描引擎</label>
            <div style="display:flex; gap:14px; padding-top:2px">
              <label class="checkbox"><input type="checkbox" v-model="form.engWebBuiltin" :disabled="busy" @change="guardEngine('web')"> 内置规则(快)</label>
              <label class="checkbox"><input type="checkbox" v-model="form.engWebZap" :disabled="busy || !engineFound.zap" @change="guardEngine('web')"> ZAP(动态深扫){{ engineFound.zap ? '' : '(未安装,去引擎页装)' }}</label>
            </div>
            <div class="muted small" style="margin-top:3px">内置规则: 快速规则匹配; ZAP: 动态深扫(主动爬取+注入/CSRF)。同时勾选 = 双引擎各跑一遍, 结果自动合并去重。</div>
          </div>
          <div class="field" style="max-width:340px">
            <label class="checkbox"><input type="checkbox" v-model="form.webdeep" :disabled="busy">
              深度爬取(跟随页面链接递归扫描子路径)</label>
          </div>
        </div>
        <!-- 2026-09-26: 镜像/文件/容器扫描(trivy SCA): 目标填镜像名/路径/容器名。
             执行位置: 本地中心端(需中心端装 trivy) / 下发到探针(需探针主机装 trivy+Docker, 远程扫容器走这条) -->
        <div class="form-row" v-if="form.type === 'image'">
          <div class="field" style="max-width:180px">
            <label class="label">扫描对象</label>
            <select class="select" v-model="form.trivyKind" :disabled="busy">
              <option value="image">Docker 镜像</option>
              <option value="fs">本地文件 / 目录</option>
              <option value="container">运行中容器</option>
            </select>
          </div>
          <!-- 2026-09-27: 执行位置(本地中心/探针)已上移到公共表单区(全部类型通用) -->
          <div class="field">
            <span class="chip" :class="engineFound.trivy ? 'on' : 'off'">{{ engineFound.trivy ? '中心端 trivy 已安装(本地执行可用)' : '中心端 trivy 未安装(本地执行需去引擎页装, 或选"下发到探针")' }}</span>
          </div>
        </div>
        <!-- 2026-09-26: 引擎使用说明(用户要求"简单明了"): trivy 是唯一引擎, 说明执行位置与远程容器口径 -->
        <div class="muted small" v-if="form.type === 'image'" style="margin:2px 0 6px">
          trivy: 检测镜像/文件/容器的依赖漏洞与配置、密钥。目标可留空 = 自动识别: 本地执行扫中心主机全部 Docker 镜像/运行中容器, 下发探针扫探针主机(该主机装 Docker)的全部; 本地文件/目录需指定路径。
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
            :disabled="(targetRequired && !form.target) || (form.mode === 'queue' && schedOff)"
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
           排队提交不携带规则勾选(调度 Params 无对应字段, 选了会被静默丢弃), 故仅立即模式显示。
           2026-09-27 性能: 默认折叠(零 DOM 渲染), 展开后分页 100 条/页 + 关键字搜索,
           解决 8746 条全渲染卡死主线程的问题。数据全量在 webRules, 提交/计数不受影响。 -->
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
          <button class="btn xs" :disabled="webRulesLoading || busy" @click="loadWebRules(true)">
            <span class="spinner" v-if="webRulesLoading" style="width:11px;height:11px;border-width:1.5px"></span> 刷新
          </button>
          <button class="btn xs" @click="ruleDrawerOpen = true">规则库</button>
          <button class="btn xs" v-if="webRules.length" @click="ruleCardOpen = !ruleCardOpen">
            {{ ruleCardOpen ? '收起' : '展开' }}
          </button>
        </div>
        <div class="muted small err-line" v-if="webRulesErr">{{ webRulesErr }}</div>
        <!-- 折叠态提示: 不渲染列表 DOM, 用户知道"已全勾"即可 -->
        <div class="muted small" v-if="!ruleCardOpen && webRules.length" style="margin-top:4px">
          已全量勾选(默认全跑), 点「展开」可按关键字筛选或单条取消。
        </div>
        <!-- 展开态: 搜索 + 分页, 每页只渲染 100 条 DOM -->
        <div v-if="ruleCardOpen && webRules.length">
          <div class="form-row" style="margin:6px 0 4px">
            <div class="field" style="max-width:280px">
              <input class="input" v-model.trim="ruleQ" placeholder="按 ID / 名称 / 类型 / 模式 过滤">
            </div>
            <span class="muted small" v-if="ruleQ && ruleFiltered.length">{{ ruleFiltered.length }} 条命中</span>
            <div class="spacer"></div>
            <span class="muted small" v-if="ruleTotalPages > 1">
              第 {{ rulePage }}/{{ ruleTotalPages }} 页 · 共 {{ ruleFiltered.length }} 条
              <button class="btn xs" :disabled="rulePage <= 1" @click="rulePage--">上一页</button>
              <button class="btn xs" :disabled="rulePage >= ruleTotalPages" @click="rulePage++">下一页</button>
            </span>
          </div>
          <div class="rule-list" v-if="rulePageRows.length">
            <div v-for="r in rulePageRows" :key="r.id" class="rule-row" :class="{ off: !r.enabled }">
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
            {{ webRulesLoading ? '正在加载 Web 范围规则…' : (ruleQ ? '无匹配规则' : '暂无 Web 范围规则') }}
          </div>
        </div>
        <div class="empty" v-if="!ruleCardOpen && !webRules.length && !webRulesLoading" style="min-height:56px">
          暂无 Web 范围规则
        </div>
        <div class="empty" v-if="!ruleCardOpen && webRulesLoading" style="min-height:56px">
          <span class="spinner" style="vertical-align:middle"></span> 正在加载 Web 范围规则…
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
            <div v-for="(f, i) in findingsView" :key="i" style="border-bottom:1px solid var(--border); padding:9px 2px">
              <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap">
                <SevTag :sev="f.severity" />
                <b style="font-size:12.5px" :title="f.title">{{ f.title }}</b>
                <!-- 2026-09-26: 多引擎模式下标注漏洞来源(engine=外部引擎 / nuclei / 内置无标记) -->
                <span class="badge" v-if="f.source" style="font-size:10px">{{ f.source }}</span>
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
            <div class="muted small" v-if="findings.length > 500" style="padding:6px 2px">
              仅显示最近 500 条(共 {{ findings.length }} 条)
            </div>
          </div>
        </div>
      </div>

      <!-- 扫描结果(2026-09-26 用户口径): 独立"发现的主机"卡片已去掉 —— 它把未存活
           的扫描目标也算进"发现"(扫 254 个就显示 254 台), 把探测范围当成了发现结果。
           主机维度改由本表地址列的 IP 勾选承担(同一 IP 的多行联动), 卡片顶部按钮对
           勾选主机继续下一步(不勾 = 全部存活主机), 行内给端口级入口。
           行内操作只给有意义的: 弱口令(仅 weakpass 支持的端口) / Web 漏扫(仅 web
           端口) —— 不支持的端口给了点了也只会得到"协议不支持", 不如没有。 -->
      <div class="card" v-if="resultRows.length && form.mode === 'now'">
        <div class="card-title">
          扫描结果
          <span class="sub">{{ openPorts.length }} 个开放端口 · 存活 {{ aliveHostCount }} 台 · 已选 {{ selectedHosts.size || '全部' }}</span>
          <div class="spacer"></div>
          <button class="btn xs" @click="stepHostScan" :disabled="busy">主机漏扫</button>
          <button class="btn xs" @click="stepWebScan" :disabled="busy">Web 漏扫</button>
          <button class="btn xs" @click="stepWeakpass">弱口令测试</button>
          <button class="btn xs" v-if="isAdmin()" @click="stepPenta">渗透测试</button>
          <button class="btn xs" @click="clearResults">清空</button>
        </div>
        <div class="muted small" style="margin-bottom:6px">
          勾选要继续的主机(不勾 = 全部存活主机): 主机漏扫 / Web 漏扫在本页直接执行(沿用任务名「{{ form.jobName || '未命名' }}」); 弱口令 / 渗透跳对应页面并自动带上目标与任务名。
        </div>
        <div class="table-wrap" style="max-height:300px; overflow-y:auto">
          <table class="table">
            <thead>
              <tr>
                <th style="width:30px"><input type="checkbox" :checked="allHostsSelected" @change="toggleAllHosts" title="全选/取消(按主机)"></th>
                <th>地址</th>
                <th>服务</th>
                <th>横幅</th>
                <th style="width:160px">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in resultRowsView" :key="r.key">
                <td><input type="checkbox" :checked="selectedHosts.has(r.ip)" @change="toggleHost(r.ip)" :title="'选中主机 ' + r.ip + ' 的所有端口'"></td>
                <!-- 存活但无开放端口的主机只有 IP(没有端口可拼), 与端口行区分开 -->
                <td class="mono">{{ r.port ? r.ip + ':' + r.port : r.ip }}</td>
                <td>
                  <span class="badge blue" v-if="r.service">{{ r.service }}</span>
                  <span class="muted small" v-else>-</span>
                </td>
                <td class="small muted mono" :title="r.banner">{{ r.banner || '-' }}</td>
                <td>
                  <button class="btn xs" v-if="r.weakSvc" @click="goWeakpass(r)">弱口令</button>
                  <button class="btn xs" v-if="isWebPort(r)" @click="goWebScan(r)">Web 漏扫</button>
                  <span class="muted small" v-if="!r.weakSvc && !isWebPort(r)">-</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="muted small" v-if="resultRows.length > 2000" style="margin-top:4px">
          仅显示前 2000 行(共 {{ resultRows.length }} 行)
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
          <!-- 2026-10-02 用户口径: 筛选选项基于当前数据里存在的 —— 状态选项由后端
               按全量任务聚合回带(statuses), 没有任务的状态不出现, 有了再出现 -->
          <select class="select" v-model="taskFilter" @change="taskPage=1; loadTasks()">
            <option value="">全部状态</option>
            <option v-for="s in taskStatusOpts" :key="s.id" :value="s.id">{{ TASK_STATUS_CN[s.id] || s.id }} ({{ s.count }})</option>
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

      <!-- 2026-09-26: 扫描历史(用户口径"扫描记忆"): 立即扫描/排队/探针下发全部落
           scan_tasks 表(持久化, 重启不丢), 可"重扫"(按原参数重新执行)与多选删除。
           与上方"调度任务"(调度器内存态, 重启即失)互补: 一个管"正在排/在跑",
           一个管"之前扫过什么"。 -->
      <div class="card">
        <div class="toolbar">
          <span class="muted small">扫描历史(立即扫描/排队/探针下发)</span>
          <!-- 2026-10-02 用户口径: 状态选项由后端按全量扫描任务聚合回带, 无数据的状态不出现 -->
          <select class="select" v-model="histFilter" @change="histPage=1; loadHist()">
            <option value="">全部状态</option>
            <option v-for="s in histStatusOpts" :key="s.id" :value="s.id">{{ HIST_STATUS_CN[s.id] || s.id }} ({{ s.count }})</option>
          </select>
          <button class="btn sm" :disabled="histLoading" @click="loadHist"><span class="spinner" v-if="histLoading"></span> 刷新</button>
          <button class="btn sm danger" :disabled="!histSel.length || histLoading" @click="batchDelHist">
            删除选中{{ histSel.length ? ' (' + histSel.length + ')' : '' }}
          </button>
          <div class="spacer"></div>
          <span class="muted small">共 {{ histTotal }} 条</span>
        </div>

        <div class="table-wrap" v-if="histList.length">
          <table class="table">
            <thead>
              <tr>
                <th style="width:30px"><input type="checkbox" :checked="allHistSel" @change="toggleAllHist" :disabled="!histList.length" title="全选/取消本页"></th>
                <th>时间</th>
                <!-- 2026-09-27: 任务名单列(用户口径: 历史页要直接看到任务名 —— 它是报告聚合键,
                     此前埋在 params JSON 里, 探针下发路径甚至没存) -->
                <th>任务名</th>
                <th>类型</th><th>目标</th><th>状态</th>
                <!-- 进度列: 探针任务的实时进度(后端从 probe_tasks 附带到列表项);
                     本地扫描的进度在"立即扫描"页事件日志里, 这里只标"运行中" -->
                <th>进度</th>
                <th>发起</th><th>节点</th><th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="t in histList" :key="t.id">
                <td><input type="checkbox" :checked="histSel.includes(t.id)" @change="toggleHistSel(t.id)"></td>
                <td class="muted small mono">{{ fmtHistT(t.createdAt) }}</td>
                <td class="small" :title="t.jobName">{{ t.jobName || '-' }}</td>
                <td class="small">{{ KIND_NAME[t.type] || t.type }}</td>
                <td class="mono small" :title="t.target + (paramsBrief(t) ? ' | ' + paramsBrief(t) : '')">{{ t.target }}</td>
                <td><span class="badge" :class="schedClass(t.status)">{{ SCHED_STATUS[t.status] || t.status }}</span></td>
                <td class="small" :title="t.probeProgress || ''">{{ histProgressText(t) }}</td>
                <td class="small">{{ t.createdBy || '-' }}</td>
                <td class="small">{{ t.probeNode || '本地' }}</td>
                <td>
                  <div class="row-actions">
                    <!-- 2026-09-27: 取消(用户口径: 任务开始了去哪里取消) —— 运行中/待执行可取消,
                         后端按任务属性路由: 本地扫描/探针任务/调度任务(POST /scans/{id}/cancel) -->
                    <button class="btn xs danger" v-if="t.status === 'running' || t.status === 'pending'"
                      :title="'停止该任务(探针任务会通知探针停止执行)'" @click="cancelHistTask(t)">取消</button>
                    <!-- 2026-09-27: 详情(用户口径: 扫描历史要点进去看当时扫描的状态) -->
                    <button class="btn xs" :title="'查看该次扫描的当时状态(参数/进度/结果)'" @click="openHistDetail(t)">详情</button>
                    <button class="btn xs green" :disabled="t.status === 'running'" :title="'按该任务的原始参数重新扫描'" @click="rescanTask(t)">重扫</button>
                    <button class="btn xs danger" @click="delHistTask(t)">删除</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty" style="min-height:80px">暂无扫描历史(立即扫描/排队/下发探针的扫描都会记录在这里)</div>

        <div class="pager" v-if="histTotal > histPage * histSize">
          <span>第 {{ histPage }} 页</span>
          <div class="spacer"></div>
          <button class="btn xs" :disabled="histPage <= 1" @click="histPage--; loadHist()">上一页</button>
          <button class="btn xs" :disabled="histPage * histSize >= histTotal" @click="histPage++; loadHist()">下一页</button>
        </div>
      </div>

      <!-- 2026-09-27: 扫描历史详情(用户口径: 要点进去看当时扫描的状态)。
           统一任务记录(参数/状态/结果) + 探针执行明细(进度/回传结果, 探针执行的任务才有) -->
      <Modal v-if="histDetail" title="扫描详情" width="680px" @close="histDetail = null">
        <div v-if="histDetail.loading" class="muted small" style="padding:8px 0">
          <span class="spinner" style="vertical-align:middle"></span> 加载中…
        </div>
        <template v-else>
          <table class="table hist-detail" v-if="histDetail.task">
            <tr><td class="muted">状态</td><td><span class="badge" :class="schedClass(histDetail.task.status)">{{ SCHED_STATUS[histDetail.task.status] || histDetail.task.status }}</span></td></tr>
            <tr v-if="histDetail.task.jobName"><td class="muted">任务名</td><td class="small">{{ histDetail.task.jobName }}</td></tr>
            <tr><td class="muted">类型 / 目标</td><td class="mono small">{{ KIND_NAME[histDetail.task.type] || histDetail.task.type }} · {{ histDetail.task.target }}</td></tr>
            <tr><td class="muted">执行节点</td><td class="small">{{ histDetail.task.probeNode || '本地中心端' }}</td></tr>
            <tr><td class="muted">发起人 / 时间</td><td class="small">{{ histDetail.task.createdBy || '-' }} · {{ fmtHistT(histDetail.task.createdAt) }}</td></tr>
            <tr v-if="histDetail.task.finishedAt"><td class="muted">完成时间</td><td class="small">{{ fmtHistT(histDetail.task.finishedAt) }}</td></tr>
            <tr v-if="histDetail.task.result"><td class="muted">结果</td><td class="small">{{ histDetail.task.result }}</td></tr>
          </table>
          <div class="label" style="margin-top:10px">当时参数</div>
          <pre class="detail-pre">{{ fmtParams(histDetail.task && histDetail.task.params) || '(无)' }}</pre>
          <template v-if="histDetail.probeTask">
            <div class="label" style="margin-top:10px">探针执行明细 ({{ histDetail.probeTask.probeNode || histDetail.task.probeNode }})</div>
            <table class="table hist-detail">
              <tr v-if="histDetail.probeTask.progress"><td class="muted">进度</td><td class="small">{{ histDetail.probeTask.progress }}</td></tr>
              <tr v-if="histDetail.probeTask.summary"><td class="muted">摘要</td><td class="small">{{ histDetail.probeTask.summary }}</td></tr>
              <tr v-if="histDetail.probeTask.error"><td class="muted">错误</td><td class="small" style="color:var(--red)">{{ histDetail.probeTask.error }}</td></tr>
              <tr v-if="histDetail.probeTask.result"><td class="muted">回传结果</td><td><pre class="detail-pre">{{ truncateDetail(histDetail.probeTask.result) }}</pre></td></tr>
            </table>
          </template>
        </template>
        <template #footer>
          <button class="btn sm" @click="histDetail = null">关闭</button>
          <button class="btn sm primary" v-if="histDetail.task" :disabled="running" @click="rescanTask(histDetail.task)">重扫</button>
        </template>
      </Modal>

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

<script>
// 模块级: 跨 Console 组件挂载复用。规则库变更频率低(用户手动导入/NVD 同步),
// 5 分钟 TTL 内进页面选 web 直接读缓存秒开, 避免每次重拉 2.8MB(1.2s 卡感)。
// 用户点"刷新"时强制重拉并刷新此缓存。
let webRulesCache = null // { rules: [...], ts: number }
</script>

<script setup>
import { ref, reactive, computed, nextTick, onMounted, onBeforeUnmount, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import SevTag from '../components/SevTag.vue'
import RuleDrawer from '../components/RuleDrawer.vue'
import Modal from '../components/Modal.vue'
import AiAnalyzeButton from '../components/AiAnalyzeButton.vue'
import { api, v2 } from '../api/http'
import { isAdmin } from '../auth'
import { SEV_NAME, copyText } from '../utils'
import { SCAN_TYPES, typeToKind, TARGET_LABEL, TARGET_PH, KIND_NAME } from '../utils/scanTypes'
import { setPageData } from '../assistant/context'

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

// 弱口令检测支持的端口 -> 服务名(与 weakpass 包的支持列表一致, 10 协议)。
// 只有这些端口的行才出现「弱口令检测」按钮: 其它端口点了只会得到"协议不支持"。
// 2026-09-25 补齐 6 个协议端口(原先只有 4 个, postgresql/ssh/smb/vnc/rdp/oracle
// 的开放端口行看不到按钮, 与 weakpass 包实际支持不符)。
const WEAKPASS_PORT = {
  6379: 'redis', 3306: 'mysql', 5432: 'postgresql', 23: 'telnet',
  21: 'ftp', 22: 'ssh', 445: 'smb', 5900: 'vnc', 3389: 'rdp', 1521: 'oracle'
}
const openPorts = ref([]) // {key, ip, port, service, banner, weakSvc}

// ===== 事件日志去重(2026-09-26 用户口径: 同一主机/同一端口不要重复报) =====
// 统一扫描里"存活"事件会带上已探到的端口, 随后每个端口又各来一条"开放"事件 ——
// 同一个端口在日志里出现两次("存活 X 端口: 80, 8080" + "开放 X:80" + "开放
// X:8080"), 端口一多就数不清到底开了几个。
// 口径(让每行只承载一次信息): 存活行只报"存活 + 证据", **不再列端口明细**; 端口
// 统一由"开放"行输出(带服务名/横幅, 信息更全)。存活行里出现过、但始终没收到
// 对应"开放"事件的端口, 在扫描结束时补一行 —— 不能因为去重就把端口漏报。
const loggedAlive = new Set() // 已打过"存活"行的 IP(同一 IP 只打一次)
const pendingPorts = new Map() // "ip:port" -> {ip, port}: 存活行报过、等"开放"事件补齐
function resetLogDedup() {
  loggedAlive.clear()
  pendingPorts.clear()
}
// 扫描收尾: 补打那些只有存活事件、没有开放事件的端口(否则去重等于漏报)
function flushPendingPorts() {
  for (const [, p] of pendingPorts) {
    addLog(`开放 ${p.ip}:${p.port}`, 'lg-green')
  }
  pendingPorts.clear()
}

// ===== 存活主机(2026-09-25 命名扫描"下一步"入口) =====
// 立即扫描的 ip/port 事件实时聚合出的主机清单(按 IP 去重): 用户"扫出比如 10 个
// 地址, 基于这 10 个地址再进行主机漏扫和 web 扫描 / 弱口令 / 渗透"的落点。
// 只登记**存活**的(2026-09-26 用户口径): 此前未存活的目标也登记, 扫 254 个地址就
// 显示"发现 254 台" —— 把探测范围当成了发现结果。未存活的主机在结果表里没有
// 落点(既不能漏扫也不能弱口令), 登记它只会污染计数。
// {ip, alive, excluded, ports: [{port, service}]}
const hosts = ref([])
const selectedHosts = ref(new Set()) // 勾选的 IP(空 = 默认作用于全部存活主机)

function upsertHost(ip, patch) {
  if (!ip) return
  let h = hosts.value.find(x => x.ip === ip)
  if (!h) {
    h = { ip, alive: false, excluded: false, ports: [] }
    hosts.value.push(h)
  }
  Object.assign(h, patch)
}

function hostAddPort(ip, port, service) {
  if (!ip || !port) return
  const h = hosts.value.find(x => x.ip === ip)
  if (!h || h.ports.some(p => p.port === Number(port))) return
  h.ports.push({ port: Number(port), service: service || '' })
}

const allHostsSelected = computed(() => hosts.value.length > 0 && hosts.value.every(h => selectedHosts.value.has(h.ip)))
function toggleAllHosts() {
  if (allHostsSelected.value) selectedHosts.value.clear()
  else selectedHosts.value = new Set(hosts.value.map(h => h.ip))
}
function toggleHost(ip) {
  const s = new Set(selectedHosts.value)
  if (s.has(ip)) s.delete(ip); else s.add(ip)
  selectedHosts.value = s // 换新对象触发 computed 更新
}
// 未勾选 = 全部存活主机("选相对的主机进行下一步"的兜底: 不选不挡路)
function selectedHostList() {
  const sel = hosts.value.filter(h => selectedHosts.value.has(h.ip))
  return sel.length ? sel : hosts.value
}

// ===== 结果表行(2026-09-26: 独立"发现的主机"卡片去掉后的合并视图) =====
// 端口行 + "存活但没有开放端口"的主机行。后者必须补: 只做存活扫描、或主机确实
// 没开出被扫端口时, 若没有主机行, "主机漏扫"按钮就没有落点, 用户只能手抄 IP。
const resultRows = computed(() => {
  const rows = openPorts.value.map(p => ({
    kind: 'port', key: p.key, ip: p.ip, port: p.port,
    service: p.service, banner: p.banner, weakSvc: p.weakSvc
  }))
  const hasRow = new Set(rows.map(r => r.ip))
  for (const h of hosts.value) {
    if (hasRow.has(h.ip)) continue
    rows.push({ kind: 'host', key: 'host:' + h.ip, ip: h.ip, port: 0, service: '', banner: '', weakSvc: '' })
  }
  return rows
})
// 存活台数(严格模式下"端口推断"不计入存活, 与后端存活口径一致)
const aliveHostCount = computed(() => hosts.value.filter(h => h.alive && !h.excluded).length)

function clearResults() {
  openPorts.value = []
  hosts.value = []
  selectedHosts.value = new Set()
}

// web 漏扫"下一步"选端口: 发现过的 web 端口优先(带出正确端口), 没扫到 web 端口
// 就退回 80(http) —— 主机漏扫前未必枚举了全部端口, 不能因为没有 80 就整台跳过。
const WEB_STEP_PORTS = [80, 443, 8080, 8443]

// 主机漏扫下一步: 回填表单(host 类型 + 勾选的 IP, 逗号拼接多 IP), 立即执行。
// 任务名沿用当前值(同一任务的分步扫描, 结果聚到同一任务名下)。
function stepHostScan() {
  const list = selectedHostList()
  if (!list.length) { alert('还没有存活的主机(未存活的目标不做下一步)'); return }
  if (!form.jobName.trim()) { alert('请先填写扫描任务名(下一步结果按它关联)'); return }
  form.type = 'host'
  form.target = list.map(h => h.ip).join(',')
  start()
}

// web 漏扫下一步: 勾选主机里带 web 端口的按端口拼 URL, 没有的退回 http://<ip>。
function stepWebScan() {
  const list = selectedHostList()
  if (!list.length) { alert('还没有存活的主机(未存活的目标不做下一步)'); return }
  if (!form.jobName.trim()) { alert('请先填写扫描任务名(下一步结果按它关联)'); return }
  const urls = list.map(h => {
    const wp = h.ports.find(p => WEB_STEP_PORTS.includes(p.port))
    if (!wp) return 'http://' + h.ip
    const scheme = (wp.port === 443 || wp.port === 8443) ? 'https://' : 'http://'
    return scheme + h.ip + ((wp.port === 80 || wp.port === 443) ? '' : ':' + wp.port)
  })
  form.type = 'web'
  form.target = urls.join(',')
  start()
}

// 弱口令下一步: 勾选主机上 weakpass 支持的端口(ip:port)带到弱口令页(带任务名,
// 原始报告按任务名分类)。没有支持的端口就不跳(跳了也只能得到"无目标")。
function stepWeakpass() {
  const list = selectedHostList()
  const targets = []
  for (const h of list) {
    for (const p of h.ports) {
      if (WEAKPASS_PORT[p.port]) targets.push(h.ip + ':' + p.port)
    }
  }
  if (!targets.length) {
    alert('勾选的主机没有弱口令支持的开放端口(redis/mysql/postgresql/telnet/ftp/ssh/smb/vnc/rdp/oracle)')
    return
  }
  router.push({ path: '/weakpass', query: { targets: targets.join(','), job: form.jobName.trim() } })
}

// 渗透下一步: 勾选主机里 redis(6379) / web(80/443/8080/8443) 的, 批量建渗透任务
// (带任务名, 报告按任务名关联), 然后跳渗透工作台逐条执行(执行要授权确认, 不能
// 代替用户自动打)。模板按端口选: 6379 → redis-unauth, 其余 → http-dir-listing。
async function stepPenta() {
  const list = selectedHostList()
  const items = []
  for (const h of list) {
    if (h.ports.some(p => p.port === 6379)) items.push({ ip: h.ip, port: 6379, tpl: 'redis-unauth', proto: 'redis' })
    else {
      const web = h.ports.find(p => WEB_STEP_PORTS.includes(p.port))
      if (web) items.push({ ip: h.ip, port: web.port, tpl: 'http-dir-listing', proto: 'http' })
    }
  }
  if (!items.length) {
    alert('勾选的主机没有 redis(6379) 或 web(80/443/8080/8443) 开放端口, 无法建渗透任务')
    return
  }
  if (!form.jobName.trim()) { alert('请先填写扫描任务名(渗透结果按它关联)'); return }
  if (!confirm('为勾选的 ' + items.length + ' 台主机创建渗透任务(任务名「' + form.jobName.trim() + '」)? 创建后到渗透工作台逐条执行(需授权确认)。')) return
  let ok = 0
  let failMsg = ''
  for (const it of items) {
    try {
      await v2('/penta/tasks', {
        method: 'POST',
        body: {
          name: form.jobName.trim() + ' · 渗透 ' + it.ip,
          target: it.ip,
          port: it.port,
          protocol: it.proto,
          templateId: it.tpl,
          job: form.jobName.trim()
        }
      })
      ok++
    } catch (e) { failMsg = e.message }
  }
  if (ok) {
    addLog('已创建 ' + ok + '/' + items.length + ' 个渗透任务' + (failMsg ? '(' + failMsg + ')' : ''), 'lg-purple')
    router.push({ path: '/penta' })
  } else {
    alert('创建渗透任务失败: ' + failMsg)
  }
}

function addOpenPort(ip, port, service, banner) {
  if (!ip || !port) return
  const key = ip + ':' + port
  // 已存在时**补全**服务名/横幅而不是直接 return(2026-09-26 修): 统一扫描里
  // "存活"事件先到(只知道端口, 没有服务名/横幅), "开放"事件后到才带服务名与
  // 横幅 —— 直接 return 会把先建的占位行固化, 服务列永远显示 "-"(用户看到
  // "扫出这么多端口但信息都是空的")。
  const old = openPorts.value.find(p => p.key === key)
  if (old) {
    if (!old.service && service) old.service = service
    if (!old.banner && banner) old.banner = String(banner).slice(0, 90)
    return
  }
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

// web 端口判定(行内「Web 漏扫」入口): 端口或已识别服务名任一命中即可 —— 服务名
// 来自 banner 识别, 例如 8081 上跑着 http, 按固定端口表会漏掉。
function isWebPort(p) {
  if (!p || !p.port) return false
  return WEB_STEP_PORTS.includes(Number(p.port)) || /^https?/i.test(String(p.service || ''))
}

// 单端口 Web 漏扫: 行内直接拼 URL 在本页执行(沿用任务名), 免去手抄 IP:端口。
// 与顶部「Web 漏扫」(作用于勾选主机)的区别: 这里是精确到一个端口, 不会把同主机
// 其它端口也带进去。
function goWebScan(p) {
  if (!form.jobName.trim()) { alert('请先填写扫描任务名(下一步结果按它关联)'); return }
  const port = Number(p.port)
  const scheme = (port === 443 || port === 8443) ? 'https://' : 'http://'
  form.type = 'web'
  form.target = scheme + p.ip + ((port === 80 || port === 443) ? '' : ':' + port)
  start()
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
// 任务名默认值: 预填"扫描-MMDD-HHmm"减少用户输入(可改), 空则提交时拦截 ——
// 2026-09-25 用户口径: 立即扫描必须先有任务名(报告按它生成/原始报告按它分类)。
function defaultJobName() {
  const d = new Date()
  const p = n => String(n).padStart(2, '0')
  return '扫描-' + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes())
}

const form = reactive({
  type: 'quick', target: '', ports: '', timeoutMs: 1500, concurrency: 200,
  aliveMode: 'loose', aliveOnly: false, enableNuclei: false, nucleiTags: '',
  nucleiTagsExclude: '',
  webdeep: false,
  // 2026-09-26: 引擎多选(host: 内置+nmap / web: 内置规则+ZAP 可同时勾选)。
  // 单勾 → 发老 engine 字段(单引擎, 后端降级语义不变); 双勾 → 发 engines 列表
  // (多引擎模式, 各引擎独立执行, 结果合并去重)。guardEngine 防"两勾全取消"。
  engHostBuiltin: true, engHostNmap: false, engWebBuiltin: true, engWebZap: false,
  trivyKind: 'image', // 2026-09-26: image=镜像 / fs=本地文件 / container=运行中容器
  // 2026-09-27: 执行位置扩展到全部扫描类型(用户口径: 主机漏扫/Web 漏扫也要能选探针)。
  // local=本地中心端执行 / probe=下发到探针主机执行(探针端用其内置引擎 + Nuclei +
  // 该主机 bin/ 目录安装的外部引擎 nmap/zap/trivy, 结果回传中心端)。
  execAt: 'local', execProbeNode: '',
  mode: 'now', strategy: '', queueNode: '', priority: 0, autoRetry: true,
  jobName: defaultJobName() // 扫描任务名(命名扫描的聚合键, 见 runScanPipeline 登记)
})

// 2026-09-26: 引擎选择可用性 —— 按 /api/env 探测外部引擎是否已安装, 未装禁用选项。
// /api/env 的引擎名带 core 后缀(nmapcore/zapcore), 这里映射到选择项的 nmap/zap。
const engineFound = reactive({ nmap: false, zap: false, trivy: false })
async function loadEngines() {
  try {
    const d = await api('/api/env')
    for (const e of (d.engines || [])) {
      if (e.name === 'nmapcore') engineFound.nmap = !!e.found
      else if (e.name === 'zapcore') engineFound.zap = !!e.found
      else if (e.name === 'trivycore') engineFound.trivy = !!e.found
    }
  } catch (e) { /* 查询失败不阻断扫描: 选项保持可用, 后端探测到未装会自动降级内置 */ }
}
// 2026-09-27: 探针列表(执行位置"下发到探针"的选项源)。直取 /api/v2/probe/list
// (探针中心启用即可用, 不依赖调度器节点接口), 15s 轮询 —— 探针在线态(30s 心跳
// 口径)变化要能反映到选项上。
const probeList = ref([])
const probeOnline = computed(() => probeList.value.filter(p => p.online))
// 快速发现完整模式(unified 统一引擎)探针端无对应实现(探针只有 ip/alive/port/
// web/host/sca 任务类型): 此组合禁用探针选项, 提示改用"仅存活检查"或主机漏扫。
const probeAllowed = computed(() => !(form.type === 'quick' && !form.aliveOnly))
let probeTimer = null
async function loadProbeList() {
  try {
    const d = await v2('/probe/list')
    probeList.value = d.list || []
  } catch (e) { probeList.value = [] }
}
// 切到"不支持探针"的组合(快速发现完整模式)时, 若已选了探针执行则回退本地,
// 避免提交时才发现不可用。
watch(() => [form.type, form.aliveOnly], () => {
  if (!probeAllowed.value && form.execAt === 'probe') form.execAt = 'local'
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

// 规则列表: 默认折叠 + 分页 + 搜索。8746 条全渲染会卡死主线程,
// 折叠后零 DOM 渲染, 展开也只渲染当前页(100 条)。数据全量留在 webRules, 计数不受影响。
const ruleCardOpen = ref(false)
const ruleQ = ref('')
const rulePage = ref(1)
const RULE_PAGE_SIZE = 100
const WEB_RULES_CACHE_TTL = 5 * 60 * 1000

const ruleFiltered = computed(() => {
  const q = ruleQ.value.trim().toLowerCase()
  if (!q) return webRules.value
  return webRules.value.filter(r =>
    [r.id, r.name, r.type, r.pattern].some(v => String(v || '').toLowerCase().includes(q))
  )
})
const rulePageRows = computed(() => {
  const start = (rulePage.value - 1) * RULE_PAGE_SIZE
  return ruleFiltered.value.slice(start, start + RULE_PAGE_SIZE)
})
const ruleTotalPages = computed(() => Math.max(1, Math.ceil(ruleFiltered.value.length / RULE_PAGE_SIZE)))

// 渲染上限: 大段扫描时开放端口/漏洞可能上千, 全渲染每次 port 事件都 diff 全表
// 会卡。数据全量保留(计数/导出/下一步不受影响), 只截 DOM 渲染。
const findingsView = computed(() => findings.value.slice(0, 500))
const resultRowsView = computed(() => resultRows.value.slice(0, 2000))

const targetLabel = computed(() => TARGET_LABEL[form.type] || '目标')
// 2026-09-27 SCA 自动识别: Docker 镜像/运行中容器允许留空目标 = 自动枚举本机全部
// 镜像/容器逐个扫(用户不用知道本机有哪些镜像); 本地文件/目录(fs)没有"全部"概念,
// 仍必填。非 image 类型目标恒必填(行为不变)。
const targetRequired = computed(() => (form.type === 'image' ? form.trivyKind === 'fs' : true))
const targetPh = computed(() => {
  if (form.type === 'image') {
    if (form.trivyKind === 'image') return '留空 = 自动扫描全部本地 Docker 镜像; 或指定镜像名(如 nginx:1.25)'
    if (form.trivyKind === 'container') return '留空 = 自动扫描全部运行中容器; 或指定容器名(如 web-1)'
    return '本地文件/目录路径(必填, 如 ./myapp、/opt/repo)'
  }
  return TARGET_PH[form.type] || ''
})

// ===== c8: Web 漏洞库规则选择 =====
const selectedWebRuleIds = computed(() => webRules.value.filter(r => r.enabled).map(r => r.id))
const allWebEnabled = computed(() => webRules.value.length > 0 && webRules.value.every(r => r.enabled))

async function loadWebRules(force = false) {
  webRulesLoading.value = true
  webRulesErr.value = ''
  try {
    // 模块级缓存: 5 分钟内重复进 Console 选 web 不重拉 2.8MB。
    // force=true(用户点刷新) 跳过缓存。
    if (!force && webRulesCache && Date.now() - webRulesCache.ts < WEB_RULES_CACHE_TTL) {
      webRules.value = webRulesCache.rules.map(r => ({ ...r, enabled: true }))
      webRulesLoaded = true
      return
    }
    const d = await api('/api/vuln/rules')
    // 只保留 Web 范围规则: scope 已由后端归一化为 web/host, 缺失时按 type 推导(web)
    const rules = (d.rules || []).filter(r => (r.scope || 'web') === 'web')
    webRules.value = rules.map(r => ({ ...r, enabled: true })) // 默认全勾 = 全跑
    webRulesCache = { rules, ts: Date.now() }
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
    // 2026-09-26: 多引擎扫描的分引擎进度 —— 后端 status 事件带 engine 字段
    // (msg 内已含 [nmap]/[builtin] 前缀), 按引擎紫色标记, 与普通状态行区分
    addLog(d.msg || '', d.engine ? 'lg-purple' : 'lg-blue')
  } else if (ev === 'ip') {
    // 未存活的目标不进结果表(2026-09-26 用户口径): 扫 254 个地址不该显示"发现
    // 254 台" —— 未存活既不能漏扫也不能弱口令, 计数只会把探测范围误读成发现结果
    if (!d.alive) return
    upsertHost(d.ip, { alive: true, excluded: !!d.excludedByStrict })
    const ports = d.ports || []
    ports.forEach(pt => hostAddPort(d.ip, pt))
    // 存活行只报"存活 + 证据", 端口交给随后的"开放"行(带服务名) —— 两处都列就是重复
    if (!loggedAlive.has(d.ip)) {
      loggedAlive.add(d.ip)
      // 三路证据如实展示: ICMP 应答 / ARP 应答 / 仅端口推断(严格模式下后者不计入存活)
      const via = d.icmp ? 'ICMP ' + (d.rttMs || 0) + 'ms'
        : d.arp ? 'ARP ' + (d.mac || '')
        : (d.inferred ? 'TCP 端口推断' : 'TCP')
      const tail = d.excludedByStrict ? '  [严格模式未计入存活]' : ''
      addLog(`存活 ${d.ip}  ${via}${tail}`,
        d.excludedByStrict ? 'lg-yellow' : 'lg-green')
    }
    // 先建结果行(无服务名), 等"开放"事件来补服务名/横幅; 收尾时还没等到就补打日志
    ports.forEach(pt => {
      pendingPorts.set(d.ip + ':' + pt, { ip: d.ip, port: pt })
      addOpenPort(d.ip, pt, '', '')
    })
  } else if (ev === 'port') {
    if (d.state === 'open') {
      // 开放端口 = 存活证据: 即使没有 ip 事件(纯端口扫描/仅存活关闭), 也按存活登记
      upsertHost(d.ip, { alive: true })
      // 结果表始终更新: 存活行建的占位行在这里补上服务名/横幅
      addOpenPort(d.ip, d.port, d.service, d.banner)
      hostAddPort(d.ip, d.port, d.service)
      // 该端口已有"开放"行承载, 撤掉收尾补打
      pendingPorts.delete(d.ip + ':' + d.port)
      addLog(`开放 ${d.ip}:${d.port}  ${d.service || ''}  ${d.latencyMs != null ? d.latencyMs + 'ms' : ''}  ${d.banner || ''}`.trim(), 'lg-green')
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
    // 收尾: 补打"只有存活事件、没等到开放事件"的端口(去重不能变成漏报)
    flushPendingPorts()
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

// 多目标归一(2026-09-25): 用户可能用空格/分号分隔多个 IP/子网/域名, 后端
// ParseHosts/splitMultiTarget 认逗号 —— 统一换成逗号, 别指望后端每种分隔符都认。
function normTargets(s) {
  return (s || '').split(/[\s;]+/).map(x => x.trim()).filter(Boolean).join(',')
}
// web 目标裸域名补 scheme: 用户口径"输入任务名和域名", 不是"和 URL"
function normWebTarget(s) {
  const t = normTargets(s)
  return t.split(',').map(u =>
    /^https?:\/\//i.test(u) ? u : 'http://' + u
  ).join(',')
}

// 2026-09-26: 防"两个引擎都取消勾选"(取消后无引擎可用) —— 立即补勾内置。
// checkbox 的 v-model 在 @change 触发前已更新, 直接判断即可。
function guardEngine(kind) {
  if (kind === 'host' && !form.engHostBuiltin && !form.engHostNmap) form.engHostBuiltin = true
  if (kind === 'web' && !form.engWebBuiltin && !form.engWebZap) form.engWebBuiltin = true
}

// 2026-09-26: 引擎多选 → payload 字段。
// 双勾 = engines 列表(后端多引擎模式, 各引擎独立跑完整流程, 结果合并去重);
// 单勾 = 老 engine 单值(后端单引擎语义, 含"外部引擎失败回落内置");
// 双不勾理论不可达(guardEngine 兜底), 仍按内置处理避免无引擎。
function engineFields(kind) {
  if (kind === 'host') {
    if (form.engHostBuiltin && form.engHostNmap) return { engines: ['builtin', 'nmap'] }
    return { engine: form.engHostNmap ? 'nmap' : 'builtin' }
  }
  if (form.engWebBuiltin && form.engWebZap) return { engines: ['builtin', 'zap'] }
  return { engine: form.engWebZap ? 'zap' : 'builtin' }
}

// 立即执行 payload: quick → 统一扫描引擎(unified); "仅存活检查"映射到 ip 类型(不枚举端口)
function payload() {
  const p = {
    type: typeToKind(form.type, form.aliveOnly),
    timeoutMs: form.timeoutMs || 1500,
    concurrency: form.concurrency || 200,
    // 任务名: 后端 runScanPipeline 入口登记 + 打标记(漏洞/资产/原始报告按它关联)
    jobName: form.jobName.trim()
  }
  if (form.type === 'quick') {
    p.cidr = normTargets(form.target); p.ports = form.ports; p.aliveMode = form.aliveMode
  }
  if (form.type === 'host') { p.ip = normTargets(form.target); p.ports = form.ports; Object.assign(p, engineFields('host')) }
  if (form.type === 'image') {
    // 2026-09-26: trivy SCA —— type 细化为 image/fs/container(决定 trivy 子命令)
    p.type = form.trivyKind
    p.trivyTarget = (form.target || '').trim()
    p.engine = 'trivy'
  }
  // 2026-09-27: 执行位置(全部类型通用): 下发到探针 = 探针主机执行, 结果回传中心端。
  // 后端 dispatchToProbe 对 ip/alive/port/host/web/image 均支持(Nuclei/外部引擎参数同口径透传)。
  if (form.execAt === 'probe' && form.execProbeNode) {
    p.execAt = 'probe'
    p.probeNode = form.execProbeNode
  }
  if (form.type === 'web') {
    p.url = normWebTarget(form.target)
    Object.assign(p, engineFields('web'))
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

// 2026-09-27 全扫(any): 点击"全扫"按钮即执行全网段存活探测。
// 口径: 全扫=存活探测(不枚举端口), 故自动勾选"仅存活检查"(type 映射到 ip);
// 目标复用既有 target 字段填 'any'(normTargets 原样透传), 后端 ip/alive 分支
// 识别后按执行节点的本地网卡网段展开(本地=中心端, 下发探针=探针主机)。
function fullScan() {
  if (busy.value) return
  form.aliveOnly = true
  form.target = 'any'
  if (form.mode === 'now' && !form.jobName.trim()) {
    alert('请先输入扫描任务名(全扫结果也按任务名聚合)')
    return
  }
  start()
}

async function start() {
  if (targetRequired.value && !form.target) return
  // 2026-09-27: 下发探针执行(全部类型)必须选目标探针(否则 payload 不带 probeNode 会误走本地执行)
  if (form.execAt === 'probe' && !form.execProbeNode) {
    alert('下发到探针执行需先选择目标探针')
    return
  }
  // 双保险: 快速发现完整模式不支持探针(选项已禁用, 防旧状态/手改 form 绕过)
  if (form.execAt === 'probe' && form.type === 'quick' && !form.aliveOnly) {
    alert('快速发现完整模式不支持探针执行(探针端无统一引擎), 请勾"仅存活检查"或改用主机漏扫')
    return
  }
  // 2026-09-25 用户口径: 立即扫描必须先有任务名 —— 结果(漏洞/资产/原始报告)按
  // 任务名打标, 报告中心按任务名生成报告; 没名字的结果是"孤儿", 没法按任务聚合。
  if (form.mode === 'now' && !form.jobName.trim()) {
    alert('请先输入扫描任务名(报告按任务名生成, 原始报告按任务名分类)')
    return
  }
  if (form.mode === 'queue') { submitQueued(); return }
  running.value = true
  logs.value = []
  findings.value = []
  openPorts.value = []
  hosts.value = []
  selectedHosts.value = new Set()
  resetLogDedup() // 新一轮扫描重新计数(否则第二次扫同一目标会全被判成"已报过")
  aiBuf = ''
  scanStartAt = Date.now() // 报告里的开始时间/耗时口径
  const p = payload()
  addLog('启动扫描: 任务「' + (p.jobName || '未命名') + '」 ' + p.type + ' -> ' + form.target, 'lg-blue')

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
  // 兜底: 流式中断/异常结束时可能收不到 done 事件, 这里补打未上报的端口
  flushPendingPorts()
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

// 小 Y 助手(2026-09-27): 扫描控制台关键数据(当前扫描表单 + 任务队列概况)
setPageData('console', () => ({
  currentScan: running.value
    ? { type: form.type, target: form.target, jobName: form.jobName, aliveOnly: form.aliveOnly }
    : null,
  queue: {
    total: taskTotal.value,
    running: (stats.value.running || 0),
    queued: (stats.value.queued || 0),
    failed: (stats.value.failed || 0),
    tasks: tasks.value.slice(0, 30).map(t => ({
      jobName: t.jobName || '',
      type: t.type || '',
      target: t.target || '',
      status: t.status || '',
      node: t.node || '中心本地'
    }))
  }
}))

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
  // pending: v2 统一任务表(扫描历史)的初始态, 与调度器的 queued 同色
  return {
    queued: 'st-pending', pending: 'st-pending', running: 'st-running', paused: 'st-duplicate',
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

// 2026-10-02: 状态筛选选项 = 后端全量聚合回带的 statuses(只含真实存在的状态)
const TASK_STATUS_CN = { queued: '排队中', running: '运行中', paused: '已暂停', success: '已完成', failed: '已失败', cancelled: '已取消' }
const taskStatusOpts = ref([])
async function loadTasks() {
  taskLoading.value = true
  try {
    const p = new URLSearchParams({ page: String(taskPage.value), size: String(taskSize) })
    if (taskFilter.value) p.set('status', taskFilter.value)
    const d = await v2('/scheduler/tasks?' + p.toString())
    taskData.value = d || {}
    tasks.value = d.items || []
    taskTotal.value = d.total || 0
    taskStatusOpts.value = d.statuses || []
    // 已选状态对应任务全删/清空 → 选项消失, 筛选自清(防列表卡死为空)
    if (taskFilter.value && !taskStatusOpts.value.some(s => s.id === taskFilter.value)) {
      taskFilter.value = ''
      loadTasks()
    }
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
  if (targetRequired.value && !form.target) { qErr.value = '目标不能为空'; return }
  qBusy.value = true
  const body = {
    type: typeToKind(form.type, form.aliveOnly),
    queue: true,
    strategy: form.strategy,
    queueNode: form.queueNode,
    priority: Number(form.priority) || 0,
    autoRetry: !!form.autoRetry,
    // 任务名: 排队执行同样带标记(调度器透传, 派发执行时 runScanPipeline 统一登记),
    // 让"排队扫的任务"也能按任务名进报告(可选: 空 = 不关联任务名)
    jobName: form.jobName.trim()
  }
  if (form.type === 'quick') body.cidr = normTargets(form.target)
  else if (form.type === 'web') body.url = normWebTarget(form.target)
  else if (form.type === 'image') {
    // 2026-09-27: trivy 目标走 trivyTarget(此前镜像名错放进 ip 字段, 排队链路根本
    // 传不到执行层); 留空 = 自动枚举本机 Docker 镜像/运行中容器(后端按执行节点在
    // 中心或探针主机上枚举)。
    body.type = form.trivyKind
    body.trivyTarget = (form.target || '').trim()
  }
  else body.ip = normTargets(form.target)
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

// ===== 2026-09-26: 扫描历史(用户口径"扫描记忆": 查看 + 重扫 + 多选删除) =====
// 数据源 GET /api/v2/scans(scan_tasks 表, 持久化): 立即扫描/排队/探针下发
// 全部登记在后端, 重启不丢。与上方"调度任务"(调度器内存态)互补。
const histList = ref([])
const histTotal = ref(0)
const histPage = ref(1)
const histSize = 20
const histFilter = ref('')
const histLoading = ref(false)
const histSel = ref([])
const allHistSel = computed(() => histList.value.length > 0 && histList.value.every(t => histSel.value.includes(t.id)))

// 2026-10-02: 扫描历史状态筛选选项 = 后端全量聚合回带的 statuses(只含真实存在的状态)
const HIST_STATUS_CN = { running: '运行中', success: '已完成', failed: '已失败', cancelled: '已取消', pending: '待执行' }
const histStatusOpts = ref([])
async function loadHist() {
  histLoading.value = true
  try {
    const p = new URLSearchParams({ page: String(histPage.value), size: String(histSize) })
    if (histFilter.value) p.set('status', histFilter.value)
    const d = await v2('/scans?' + p.toString())
    histList.value = d.list || []
    histTotal.value = d.total || 0
    histStatusOpts.value = d.statuses || []
    // 已选状态对应记录全删/清空 → 选项消失, 筛选自清(防列表卡死为空)
    if (histFilter.value && !histStatusOpts.value.some(s => s.id === histFilter.value)) {
      histFilter.value = ''
      loadHist()
    }
    // 选中项只保留当前页仍存在的(翻页/删除后不残留)
    histSel.value = histSel.value.filter(id => histList.value.some(t => t.id === id))
  } catch (e) {
    alert(e.message)
  } finally { histLoading.value = false }
}

function toggleHistSel(id) {
  const i = histSel.value.indexOf(id)
  if (i >= 0) histSel.value.splice(i, 1)
  else histSel.value.push(id)
}
function toggleAllHist() {
  histSel.value = allHistSel.value ? [] : histList.value.map(t => t.id)
}

function fmtHistT(s) {
  if (!s) return '-'
  const d = new Date(s)
  if (isNaN(d.getTime())) return s
  return d.toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

// 参数摘要(目标列 hover 提示): 端口集/引擎等关键参数一眼可见
function paramsBrief(t) {
  let p = t.params
  if (typeof p === 'string') { try { p = JSON.parse(p) } catch (e) { p = null } }
  if (!p || typeof p !== 'object') return ''
  const bits = []
  if (p.ports) bits.push('端口 ' + p.ports)
  if (Array.isArray(p.engines) && p.engines.length > 1) bits.push(p.engines.map(e => e === '' ? '内置' : e).join('+'))
  else if (p.engine && p.engine !== 'builtin') bits.push(p.engine)
  if (p.enableNuclei) bits.push('nuclei')
  if (p.webdeep) bits.push('web深度')
  if (p.aliveMode && p.aliveMode !== 'loose') bits.push('存活' + p.aliveMode)
  return bits.join(' · ')
}

// 2026-09-27: 扫描历史详情(用户口径: 要点进去看当时扫描的状态)。
// 统一任务记录(/scans/{id}) + 探针执行明细(/probe/tasks, 探针执行的任务才有:
// 进度/摘要/回传结果 —— trivy 这类探针任务的结果正文就在这里)。
const histDetail = ref(null) // { loading, task, probeTask }
async function openHistDetail(t) {
  histDetail.value = { loading: true, task: { ...t }, probeTask: null }
  try {
    const d = await v2('/scans/' + encodeURIComponent(t.id))
    histDetail.value.task = d
    if (d.probeNode) {
      try {
        const pl = await v2('/probe/tasks?probeId=' + encodeURIComponent(d.probeNode) + '&size=100')
        const pt = (pl.list || []).find(x => x.id === d.id)
        if (pt) histDetail.value.probeTask = pt
      } catch (e) { /* 探针明细是次要展示, 失败忽略 */ }
    }
  } catch (e) {
    alert('详情加载失败: ' + e.message)
  } finally {
    histDetail.value.loading = false
  }
}
function fmtParams(p) {
  if (p == null) return ''
  if (typeof p === 'string') { try { p = JSON.parse(p) } catch (e) { return p } }
  return JSON.stringify(p, null, 2)
}
function truncateDetail(s) {
  s = String(s || '')
  return s.length > 2000 ? s.slice(0, 2000) + '\n…(已截断, 共 ' + s.length + ' 字符)' : s
}

// 重扫: 按该任务的原始参数(后端存了完整 scanReq JSON)回填"立即扫描"表单,
// 切回扫描页并自动启动 —— 结果流在扫描页实时可见(不另开隐藏 SSE 流)。
async function rescanTask(t) {
  if (running.value) { alert('当前有扫描进行中, 请等完成后再重扫'); return }
  const label = (KIND_NAME[t.type] || t.type || '-') + ' ' + (t.target || '')
  if (!confirm('重新扫描: ' + label + '\n\n将按该任务的原始参数在"立即扫描"页重新启动, 继续?')) return
  try {
    const d = await v2('/scans/' + encodeURIComponent(t.id))
    let p = d.params
    if (typeof p === 'string') { try { p = JSON.parse(p) } catch (e) { p = null } }
    if (!p || typeof p !== 'object') p = {}
    if (!p.type) p.type = t.type
    if (!p.target) p.target = t.target
    if (!applyTaskToForm(p, t)) return
    setTab('scan')
    start()
  } catch (e) { alert(e.message) }
}

// 参数 → 表单字段映射(重扫用): 目标/端口/引擎多选/nuclei/web 深度等。
// 后端 Params 是 scanReq 的 JSON(字段名与 payload() 基本一致)。
function applyTaskToForm(p, t) {
  const target = p.ip || p.cidr || p.url || p.trivyTarget || t.target || ''
  if (!target) { alert('该任务缺少目标, 无法重扫'); return false }
  const ty = String(p.type || '').toLowerCase()
  let ft = 'quick'
  if (ty === 'host') ft = 'host'
  else if (ty === 'web') ft = 'web'
  else if (ty === 'image' || ty === 'fs' || ty === 'container') ft = 'image'
  // ip/port/unified/alive 都映射回"快速发现"(同一统一扫描引擎的不同入口)
  Object.assign(form, {
    type: ft,
    target: target,
    ports: p.ports || form.ports,
    aliveMode: p.aliveMode || form.aliveMode,
    enableNuclei: !!p.enableNuclei,
    nucleiTags: p.nucleiTags || '',
    nucleiTagsExclude: p.nucleiTagsExclude || '',
    webdeep: !!p.webdeep,
    jobName: p.jobName || form.jobName
  })
  if (ft === 'image') form.trivyKind = ty
  // 引擎多选回显(engines 列表里 "" = 内置, 后端已归一化)
  if (Array.isArray(p.engines)) {
    const e = p.engines.map(s => String(s).toLowerCase())
    const hasBuiltin = e.includes('') || e.includes('builtin')
    if (ft === 'host') {
      form.engHostNmap = e.includes('nmap')
      form.engHostBuiltin = hasBuiltin || !form.engHostNmap
    } else if (ft === 'web') {
      form.engWebZap = e.includes('zap')
      form.engWebBuiltin = hasBuiltin || !form.engWebZap
    }
  } else if (p.engine && p.engine !== 'trivy') {
    if (ft === 'host') {
      form.engHostNmap = p.engine === 'nmap'
      form.engHostBuiltin = !form.engHostNmap
    } else if (ft === 'web') {
      form.engWebZap = p.engine === 'zap'
      form.engWebBuiltin = !form.engWebZap
    }
  }
  return true
}

async function delHistTask(t) {
  if (!confirm('确认删除扫描历史「' + (t.type || '-') + ' ' + (t.target || '') + '」?\n(只删任务记录, 该次扫描已落库的资产/漏洞/报告不受影响)')) return
  try {
    await v2('/scans/' + encodeURIComponent(t.id), { method: 'DELETE' })
    histSel.value = histSel.value.filter(id => id !== t.id)
    await loadHist()
  } catch (e) { alert(e.message) }
}

// 批量删除选中(走 /api/v2/scans/batch-delete, 后端上限 500/次)
async function batchDelHist() {
  const n = histSel.value.length
  if (!n) return
  if (n > 500) { alert('单次最多删除 500 条'); return }
  if (!confirm('确认删除选中的 ' + n + ' 条扫描历史?\n(只删任务记录, 已落库的资产/漏洞/报告不受影响)')) return
  try {
    const r = await v2('/scans/batch-delete', { method: 'POST', body: { ids: [...histSel.value] } })
    alert('已删除 ' + (r.deleted || 0) + ' 条')
    histSel.value = []
    await loadHist()
  } catch (e) { alert(e.message) }
}

// 2026-09-27: 进度列展示(用户口径: 扫描历史里能看到扫描进度)。
// 探针任务: 后端把 probe_tasks 的实时进度附到列表项(probeProgress);
// 本地扫描: 进度在"立即扫描"页的 SSE 事件日志里, 不落表, 这里只标"运行中"。
function histProgressText(t) {
  if (t.status !== 'running') return '-'
  if (t.probeNode) return t.probeProgress || '等待探针回传进度…'
  return '运行中'
}

// 2026-09-27: 取消运行中的扫描(用户口径: "任务开始了, 去哪里取消?")。
// 统一入口 POST /scans/{id}/cancel, 后端按任务属性路由:
// 本地立即扫描(ctx 取消, 立即停) / 探针任务(通知探针停, trivy 等子进程一并杀) / 调度任务。
async function cancelHistTask(t) {
  const label = t.jobName || (KIND_NAME[t.type] || t.type) + ' ' + t.target
  if (!confirm('取消任务「' + label + '」?\n\n探针任务会通知探针停止执行; 本地扫描立即停止。已产出的结果(资产/漏洞)保留。')) return
  try {
    const r = await v2('/scans/' + encodeURIComponent(t.id) + '/cancel', { method: 'POST' })
    const via = r.via === 'probe' ? '已通知探针停止'
      : r.via === 'scheduler' ? '调度任务已取消'
      : '本地扫描已停止'
    addLog('取消扫描: ' + label + ' (' + via + ')', 'lg-orange')
    await loadHist()
  } catch (e) { alert('取消失败: ' + e.message) }
}

let timer = null
onMounted(() => {
  connectGlobal()
  loadEngines() // 2026-09-26: 探测 nmap/zap 是否已安装(决定引擎选择项可用性)
  // 任务队列数据: 调度状态 / 任务 / 策略 / 限速 / 节点(原任务管理页同口径)
  loadSched()
  loadTasks()
  loadHist() // 2026-09-26: 扫描历史(持久化, 不需要 4s 轮询 —— 历史条目状态由扫描收尾一次性回写)
  loadStrategies()
  loadRate()
  loadNodes()
  loadProbeList() // 2026-09-27: 执行位置"下发到探针"选项
  probeTimer = setInterval(loadProbeList, 15000)
  // 轮询 4s: 调度状态是"变动中的"(排队→运行→完成), 比资产类页面需要更快刷新
  timer = setInterval(() => {
    // 2026-09-27: 扫描历史有运行中/待执行条目时自动刷新 —— 看探针实时进度、
    // 取消后的状态回写, 不用手动点刷新(与"任务自动刷新"开关解耦: 进度可见性
    // 是基础体验, 不应被用户关掉的开关影响)
    if (histList.value.some(t => t.status === 'running' || t.status === 'pending')) loadHist()
    if (!taskAuto.value) return
    loadTasks()
    loadRate()
  }, 4000)
})
onBeforeUnmount(() => {
  if (controller) controller.abort()
  disconnectEvt()
  if (timer) clearInterval(timer)
  if (probeTimer) clearInterval(probeTimer)
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
/* 2026-09-27: 扫描历史详情弹窗的参数/结果展示 */
.hist-detail td { padding: 5px 8px; vertical-align: top; }
.hist-detail td:first-child { width: 92px; white-space: nowrap; }
.detail-pre {
  background: rgba(127, 127, 127, .08);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px;
  margin: 4px 0 0;
  max-height: 220px;
  overflow: auto;
  font-size: 12px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>

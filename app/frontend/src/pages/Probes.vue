<template>
  <div>
    <PageHeader :title="t('pb.title')" :desc="t('pb.desc')">
      <button class="btn sm" :disabled="loading" @click="load"><span class="spinner" v-if="loading"></span> {{ t('common.refresh') }}</button>
      <button class="btn sm" @click="openDownload">{{ t('pb.download') }}</button>
      <button class="btn sm primary" :disabled="!assignReady" @click="showAssign = !showAssign">{{ t('pb.assignTask') }}</button>
    </PageHeader>

    <!-- 未启用: 一行说明 + 一键开启(写 settings.json, 重启生效) + 部署指引 -->
    <div class="alert info" v-if="status && !status.centerEnabled && !status.clientEnabled">
      {{ t('pb.disIntro') }}
      <button class="btn sm primary" style="margin-left:10px" :disabled="enabling" @click="enableProbe">
        {{ enabling ? t('pb.enabling') : t('pb.enable') }}
      </button>
      <a class="small" href="/api/v2/probe/agent/install" target="_blank">{{ t('pb.guide') }}</a>
      <span class="muted small" v-if="enableMsg" style="margin-left:8px">{{ enableMsg }}</span>
      <details style="margin-top:8px">
        <summary class="muted small" style="cursor:pointer">{{ t('pb.advCfg') }}</summary>
        <div class="muted small" style="margin-top:6px">
          {{ t('pb.advIn') }} <span class="mono">settings.json</span> {{ t('pb.advAdd') }} <span class="mono">probe</span> {{ t('pb.advSec') }},
          {{ t('pb.advOr') }} <span class="mono">-probe=center</span>{{ t('pb.advCenter') }} / <span class="mono">-probe=both</span>{{ t('pb.advBoth') }}。
          {{ t('pb.advDeploy') }} <span class="mono">yugsight-agent</span>({{ t('pb.advDl') }}<b>{{ t('pb.download') }}</b>{{ t('pb.advDlEnd') }})。
        </div>
      </details>
    </div>
    <div class="alert info" v-else-if="status && status.clientEnabled && !status.clientOnline" style="margin-bottom:14px">
      {{ t('pb.clientOffline', { addr: status.centerAddr || '-' }) }}
    </div>

    <!-- 状态卡 -->
    <div class="grid cols-4">
      <div class="card">
        <div class="stat-label">{{ t('pb.centerCard') }}</div>
        <div class="stat-value" style="font-size:20px">{{ centerText }}</div>
        <div class="stat-sub">{{ t('pb.centerSub') }}</div>
      </div>
      <div class="card">
        <div class="stat-label">{{ t('pb.probeCard') }}</div>
        <div class="stat-value" style="font-size:20px">{{ online.filter(p => p.online).length }} / {{ total }}</div>
        <div class="stat-sub">{{ t('pb.regNodes', { n: total }) }}</div>
      </div>
      <div class="card">
        <div class="stat-label">{{ t('pb.roleCard') }}</div>
        <div class="stat-value" style="font-size:20px">{{ roleText }}</div>
        <div class="stat-sub mono">{{ status && status.clientId ? status.clientId : '-' }}</div>
      </div>
      <div class="card">
        <div class="stat-label">{{ t('pb.protoVer') }}</div>
        <div class="stat-value" style="font-size:20px">{{ status ? status.protocol : '-' }}</div>
        <div class="stat-sub">{{ t('pb.protoSame') }}</div>
      </div>
    </div>

    <!-- 2026-09-26: 上报参数下发(用户口径"时间控制在中心端探针管理可以下发"):
         指标不再实时发, 累积 N 秒发一次; 心跳/离线判定一并可调。
         保存后各探针在下次注册(重连/重启)时生效。 -->
    <div class="card" v-if="status && status.centerEnabled">
      <div class="card-title">
        {{ t('pb.reportCfg') }}
        <span class="sub">{{ t('pb.reportCfgSub') }}</span>
      </div>
      <div class="form-row">
        <div class="field" style="max-width:150px">
          <label class="label">{{ t('pb.heartbeat') }}</label>
          <input class="input mono" type="number" v-model.number="cfgForm.heartbeatSec" min="3" max="600">
        </div>
        <div class="field" style="max-width:170px">
          <label class="label">{{ t('pb.metrics') }}</label>
          <input class="input mono" type="number" v-model.number="cfgForm.metricsSec" min="5" max="3600"
            :title="t('pb.metricsTip')">
        </div>
        <div class="field" style="max-width:180px">
          <label class="label">{{ t('pb.offlineSec') }}</label>
          <input class="input mono" type="number" v-model.number="cfgForm.offlineSec" min="0">
        </div>
        <div class="field" style="max-width:150px; align-self:flex-end">
          <button class="btn primary" :disabled="savingCfg" @click="saveCfg">{{ savingCfg ? t('pb.saving') : t('pb.saveCfg') }}</button>
        </div>
        <span class="muted small" style="align-self:flex-end">{{ cfgNote }}</span>
      </div>
    </div>

    <!-- 调度节点负载(GET /api/v2/scheduler/nodes): 探针列表给的是"注册快照",
         这里是调度器视角的"此刻能不能接活" —— 槽位占用/负载/能力/拒绝原因。 -->
    <div class="card">
      <div class="card-title">
        {{ t('pb.schedTitle') }}
        <span class="sub">{{ t('pb.schedSub') }}</span>
        <div class="spacer"></div>
        <span class="chip" :class="schedOn ? 'on' : 'off'">{{ schedOn ? t('pb.schedOn') : t('pb.schedOff') }}</span>
        <span class="muted small" v-if="schedNodes.length">{{ t('pb.schedCap', { n: schedCapacity || '-' }) }}</span>
      </div>
      <div v-if="!schedNodes.length" class="empty" style="min-height:80px">
        {{ t('pb.noSchedNode') }}
      </div>
      <div class="table-wrap" v-else>
        <table class="table">
          <thead>
            <tr><th>{{ t('pb.sNode') }}</th><th>{{ t('pb.cType') }}</th><th>{{ t('pb.sOnline') }}</th><th>{{ t('pb.sSlots') }}</th><th>CPU</th><th>{{ t('pb.sMem') }}</th><th>{{ t('pb.sRunning') }}</th><th>{{ t('pb.cCaps') }}</th><th>{{ t('pb.sAccept') }}</th></tr>
          </thead>
          <tbody>
            <tr v-for="n in schedNodes" :key="n.id">
              <td>
                <div class="small">{{ n.name || (n.kind === 'local' ? t('pb.kLocal') : n.id) }}</div>
                <div class="muted small mono">{{ n.id }}</div>
              </td>
              <td class="small">{{ t(NODE_KIND[n.kind] || n.kind || '-') }}</td>
              <td><span class="badge" :class="n.online ? 'st-success' : 'st-failed'">{{ n.online ? t('pb.online') : t('pb.offline') }}</span></td>
              <!-- 槽位是调度器真正关心的量: 探针自报的 tasksRunning 只作交叉校验 -->
              <td class="mono small">{{ n.running || 0 }} / {{ n.max || '-' }}</td>
              <td class="mono small">{{ pct(n.cpuPercent) }}</td>
              <td class="mono small">{{ pct(n.memPercent) }}</td>
              <td class="mono small">{{ n.tasksRunning || 0 }}</td>
              <td>
                <span class="badge" v-for="c in capListOf(n.capabilities)" :key="c" style="margin-right:4px">{{ c }}</span>
                <span class="muted small" v-if="!capListOf(n.capabilities).length">-</span>
              </td>
              <td>
                <span class="badge st-success" v-if="!n.reject">{{ t('pb.acceptable') }}</span>
                <span class="badge st-failed" v-else :title="n.reject.msg">{{ n.reject.msg }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 下发任务 -->
    <div class="card" v-if="showAssign">
      <div class="card-title">{{ t('pb.assignTitle') }} <span class="sub">{{ t('pb.assignSub') }}</span></div>
      <div class="form-row">
        <div class="field" style="max-width:240px">
          <label class="label">{{ t('pb.targetProbe') }} *</label>
          <select class="select" v-model="assign.probeId">
            <option value="">{{ t('pb.pickOnline') }}</option>
            <option v-for="p in onlineProbes" :key="p.id" :value="p.id">{{ p.name || p.id }} ({{ p.addr || '-' }})</option>
          </select>
        </div>
        <div class="field" style="max-width:150px">
          <label class="label">{{ t('pb.cType') }}</label>
          <select class="select" v-model="assign.type">
            <option value="port">{{ t('pb.kPort') }}</option>
            <option value="ip">{{ t('pb.kIp') }}</option>
            <option value="web">{{ t('pb.kWeb') }}</option>
            <option value="host">{{ t('pb.kHost') }}</option>
            <!-- 2026-09-26: 镜像/容器远程扫描(探针端 trivy 执行, 探针装 trivy+Docker 即可) -->
            <option value="image">{{ t('pb.kImage') }}</option>
            <!-- 2026-09-27: ARP 异常监测(环路/IP 冲突/MAC 漂移), 目标是探针本机网卡 -->
            <option value="arp">{{ t('pb.kArp') }}</option>
          </select>
        </div>
        <div class="field">
          <label class="label">{{ assignTargetLabel }} *</label>
          <input class="input mono" v-model.trim="assign.target" :placeholder="assignTargetPh" @keyup.enter="doAssign">
        </div>
        <div class="field" style="max-width:180px" v-if="assign.type === 'port'">
          <label class="label">{{ t('pb.portsOpt') }}</label>
          <input class="input mono" v-model.trim="assign.ports" :placeholder="t('pb.portsPh')">
        </div>
        <!-- 2026-09-26: 探针继承中心端漏扫 —— 主机/Web 可带 nuclei 参数(SCA 可带 trivy 参数) -->
        <div class="field" style="max-width:160px" v-if="assign.type === 'host' || assign.type === 'web'">
          <label class="label">{{ t('pb.scanEngine') }}</label>
          <div style="display:flex; gap:10px; padding-top:2px">
            <label class="checkbox"><input type="checkbox" v-model="assign.enableNuclei"> nuclei</label>
            <input class="input mono" v-model.trim="assign.nucleiTags" :placeholder="t('pb.tagsPh')" style="width:120px">
          </div>
        </div>
        <div class="field" style="max-width:200px" v-if="assign.type === 'image'">
          <label class="label">{{ t('pb.trivyArgs') }}</label>
          <input class="input mono" v-model.trim="assign.trivyArgs" placeholder="--scanners misconfig,secret">
        </div>
        <!-- 2026-09-27: ARP 异常监测 —— 目标=网卡名(local=自动选), 另选监测时长 -->
        <div class="field" style="max-width:150px" v-if="assign.type === 'arp'">
          <label class="label">{{ t('pb.arpDuration') }}</label>
          <input class="input mono" type="number" v-model.number="assign.arpDuration" min="10" max="600">
        </div>
        <div class="field" style="max-width:120px; align-self:flex-end">
          <button class="btn primary" style="width:100%" :disabled="assigning" @click="doAssign">
            {{ assigning ? t('pb.assigning') : t('pb.assign') }}
          </button>
        </div>
      </div>
      <div class="login-err" style="text-align:left">{{ assignErr }}</div>
      <!-- 2026-09-27: ARP 监测说明(能力依赖 + 结果去向, 用户口径"要做说明") -->
      <div class="muted small" v-if="assign.type === 'arp'" style="margin-top:8px">
        {{ t('pb.arpNote') }}
      </div>
      <div class="muted small" v-if="assignMsg" style="margin-top:8px">{{ assignMsg }}</div>
    </div>

    <!-- 探针列表 -->
    <div class="card">
      <div class="toolbar">
        <span class="muted small">{{ t('pb.listTitle') }}</span>
        <button class="btn sm" @click="load"><span class="spinner" v-if="loading"></span> {{ t('common.refresh') }}</button>
        <div class="spacer"></div>
        <label class="checkbox"><input type="checkbox" v-model="onlyOnline"> {{ t('pb.onlyOnline') }}</label>
      </div>

      <div class="table-wrap" v-if="displayList.length">
        <table class="table">
          <thead>
            <tr>
              <th>{{ t('pb.cStatus') }}</th><th>{{ t('pb.cId') }}</th><th>{{ t('pb.cName') }}</th>
              <!-- 2026-09-27: IP/MAC 字段补充(注册时上报的 nodeInfo.netIfaces, 取首个带地址的网卡) -->
              <th>IP</th><th>MAC</th>
              <th>{{ t('pb.cOs') }}</th><th>{{ t('pb.cVer') }}</th><th>{{ t('pb.cAddr') }}</th>
              <th>{{ t('pb.cCaps') }}</th><th>{{ t('pb.cHeart') }}</th><th>{{ t('pb.cOp') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="pg in displayList" :key="pg.id">
              <td>
                <span class="badge" :class="pg.online ? 'st-success' : 'st-failed'">{{ pg.online ? t('pb.online') : t('pb.offline') }}</span>
              </td>
              <td class="mono small">{{ pg.id }}</td>
              <td class="small">{{ pg.name || '-' }}</td>
              <td class="mono small" :title="t('pb.nicWord') + ' ' + nicText(pg)">{{ probeIP(pg) || '-' }}</td>
              <td class="mono small">{{ probeMac(pg) || '-' }}</td>
              <td class="small mono">{{ osText(pg) }}</td>
              <td class="mono small">
                <!-- 版本不一致时标红并给提示: 探针会在下次注册时自动更新(中心端已在
                     注册应答里下发更新指令), 用户看到红色只需知道"它会自己修好"，
                     不必手工去替换文件。 -->
                <span v-if="verState(pg) === 'diff'" class="badge st-failed"
                      :title="t('pb.verOld') + ' ' + centerAgentVer">
                  {{ pg.version || t('pb.unknown') }} ↑{{ centerAgentVer }}
                </span>
                <span v-else-if="verState(pg) === 'same'">{{ pg.version }}</span>
                <span v-else class="muted">{{ pg.version || '-' }}</span>
              </td>
              <td>
                <span class="badge" v-for="c in capList(pg)" :key="c" style="margin-right:4px">{{ c }}</span>
                <span class="muted small" v-if="!capList(pg).length">-</span>
              </td>
              <td class="muted small mono">{{ fmtDT(pg.lastSeenAt) }}</td>
              <td>
                <div class="row-actions">
                  <button class="btn xs" @click="openDetail(pg)">{{ t('pb.detail') }}</button>
                  <button class="btn xs" :disabled="!pg.online" @click="quickAssign(pg)">{{ t('pb.assign') }}</button>
                  <button class="btn xs danger" :disabled="pg.online" :title="pg.online ? t('pb.remOnlineTip') : ''" @click="del(pg)">{{ t('pb.remove') }}</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else :text="t('pb.noProbes')" />
    </div>

    <!-- 本机探针端状态 -->
    <div class="grid cols-2" v-if="status && status.clientEnabled">
      <div class="card">
        <div class="card-title">{{ t('pb.localTitle') }} <span class="sub">{{ t('pb.localSub') }}</span></div>
        <div class="kv">
          <div class="k">{{ t('pb.nodeId') }}</div><div class="v mono">{{ status.clientId || '-' }}</div>
          <div class="k">{{ t('pb.centerAddr') }}</div><div class="v mono">{{ status.centerAddr || '-' }}</div>
          <div class="k">{{ t('pb.connStatus') }}</div>
          <div class="v">
            <span class="badge" :class="status.clientOnline ? 'st-success' : 'st-failed'">{{ status.clientOnline ? t('pb.connected') : t('pb.reconnecting') }}</span>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">{{ t('pb.infoTitle') }} <span class="sub">{{ t('pb.infoSub') }}</span></div>
        <div class="kv">
          <div class="k">{{ t('pb.cOs') }}</div><div class="v mono">{{ myInfo.os }} {{ myInfo.arch }}</div>
          <div class="k">{{ t('pb.kernelVer') }}</div><div class="v mono small">{{ myInfo.osVersion || '-' }}</div>
          <div class="k">{{ t('pb.cpuMem') }}</div><div class="v small">{{ myInfo.cpuCores || 0 }} {{ t('pb.cores') }} / {{ mb(myInfo.memTotal) }} MB</div>
          <div class="k">Npcap</div>
          <div class="v"><span class="badge" :class="myInfo.npcapInstalled ? 'st-success' : 'st-failed'">{{ myInfo.npcapInstalled ? t('pb.installed') : t('pb.notInstalled') }}</span></div>
        </div>
      </div>
    </div>

    <!-- 任务明细 -->
    <div class="card">
      <div class="toolbar">
        <!-- 2026-10-02 用户口径: 筛选选项基于当前数据里存在的 —— 探针/状态选项由
             后端按全量任务聚合回带(不再用探针注册表全量; 已删探针的历史任务按 ID 仍可筛) -->
        <select class="select" v-model="taskProbeId" @change="loadTasks">
          <option value="">{{ t('pb.allTasks') }}</option>
          <option v-for="p in taskProbeOpts" :key="p.id" :value="p.id">{{ probeLabel(p.id) }} ({{ p.count }})</option>
        </select>
        <select class="select" v-model="taskStatus" @change="loadTasks">
          <option value="">{{ t('pb.allStatus') }}</option>
          <option v-for="s in taskStatusOpts" :key="s.id" :value="s.id">{{ t(TASK_STATUS[s.id] || s.id) }} ({{ s.count }})</option>
        </select>
        <button class="btn sm" @click="loadTasks"><span class="spinner" v-if="taskLoading"></span> {{ t('common.refresh') }}</button>
        <div class="spacer"></div>
        <span class="muted small">{{ t('pb.taskTotal', { n: taskTotal }) }}</span>
      </div>
      <div class="table-wrap" v-if="tasks.length">
        <table class="table">
          <thead>
            <tr><th>{{ t('pb.tId') }}</th><th>{{ t('pb.tProbe') }}</th><th>{{ t('pb.cType') }}</th><th>{{ t('pb.tTarget') }}</th><th>{{ t('pb.cStatus') }}</th><th>{{ t('pb.tProgress') }}</th><th>{{ t('pb.tFinding') }}</th><th>{{ t('pb.tDuration') }}</th><th>{{ t('pb.cOp') }}</th></tr>
          </thead>
          <tbody>
            <tr v-for="tk in tasks" :key="tk.id">
              <td class="mono small">{{ tk.id }}</td>
              <td class="small">{{ tk.probeNode || '-' }}</td>
              <td class="small">{{ t(TASK_KIND[tk.kind] || tk.kind) }}</td>
              <td class="mono small" :title="tk.target">{{ tk.target }}</td>
              <td><span class="badge" :class="taskClass(tk.status)">{{ t(TASK_STATUS[tk.status] || tk.status) }}</span></td>
              <td class="small muted" :title="tk.progress">{{ tk.progress || '-' }}</td>
              <td class="small">{{ tk.findingNum || 0 }}</td>
              <td class="small mono">{{ tk.durationMs ? (tk.durationMs / 1000).toFixed(1) + 's' : '-' }}</td>
              <td>
                <div class="row-actions">
                  <button class="btn xs" v-if="tk.status === 'success' || tk.status === 'failed'" @click="openResult(tk)">{{ t('pb.result') }}</button>
                  <button class="btn xs danger" v-if="tk.status === 'sent' || tk.status === 'running'" @click="cancelTask(tk)">{{ t('common.cancel') }}</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else :text="t('pb.noTasks')" />
    </div>

    <!-- 探针详情弹窗 -->
    <div class="modal-mask" v-if="detail" @click.self="detail = null">
      <div class="modal">
        <div class="modal-head">
          <span>{{ t('pb.detailTitle') }} · {{ detail.name || detail.id }}</span>
          <button class="btn xs" @click="detail = null">{{ t('common.close') }}</button>
        </div>
        <div class="kv">
          <div class="k">{{ t('pb.cId') }}</div><div class="v mono">{{ detail.id }}</div>
          <div class="k">{{ t('pb.cStatus') }}</div>
          <div class="v"><span class="badge" :class="detail.online ? 'st-success' : 'st-failed'">{{ detail.online ? t('pb.online') : t('pb.offline') }}</span></div>
          <div class="k">{{ t('pb.cOs') }}</div><div class="v mono">{{ osText(detail) }}</div>
          <div class="k">{{ t('pb.kernelVer') }}</div><div class="v mono small">{{ nodeOf(detail).kernel || '-' }}</div>
          <div class="k">CPU</div><div class="v small">{{ nodeOf(detail).cpuModel || '-' }} ({{ nodeOf(detail).cpuCores || 0 }} {{ t('pb.cores') }})</div>
          <div class="k">{{ t('pb.memDisk') }}</div>
          <div class="v small">
            {{ mb(nodeOf(detail).memTotal) }} MB<span v-if="nodeOf(detail).memUsed"> ({{ t('pb.used') }} {{ mb(nodeOf(detail).memUsed) }} MB)</span>
            / {{ gb(nodeOf(detail).diskTotal) }} GB<span v-if="nodeOf(detail).diskUsed"> ({{ t('pb.used') }} {{ gb(nodeOf(detail).diskUsed) }} GB)</span>
          </div>
          <div class="k">{{ t('pb.gwDns') }}</div>
          <div class="v mono small">{{ nodeOf(detail).gateway || '-' }} / {{ (nodeOf(detail).dns || []).join(', ') || '-' }}</div>
          <div class="k">{{ t('pb.osVer') }}</div><div class="v mono small">{{ nodeOf(detail).osVersion || '-' }}</div>
          <div class="k">Npcap</div>
          <div class="v small">{{ nodeOf(detail).npcapInstalled ? t('pb.npcapOn') : t('pb.npcapOff') }}</div>
          <div class="k">{{ t('pb.engines') }}</div>
          <div class="v small">
            <span v-for="e in (nodeOf(detail).engines || [])" :key="e.name" class="badge" style="margin-right:4px">
              {{ e.name }}{{ e.found ? ' ' + (e.version || 'ok') : ' ' + t('pb.missing') }}
            </span>
            <span class="muted" v-if="!(nodeOf(detail).engines || []).length">{{ t('pb.noEngines') }}</span>
          </div>
          <div class="k">{{ t('pb.probeVer') }}</div><div class="v mono small">{{ nodeOf(detail).version || '-' }} · {{ t('pb.started') }} {{ nodeOf(detail).startedAt || '-' }}</div>
          <div class="k">{{ t('pb.nic') }}</div>
          <div class="v small mono">{{ nicText(detail) }}</div>
          <div class="k">{{ t('pb.cLoad') }}</div>
          <div class="v small">{{ loadText(detail) }}</div>
          <div class="k">{{ t('pb.cHeart') }}</div><div class="v mono small">{{ fmtDT(detail.lastSeenAt) }}</div>
          <div class="k">{{ t('pb.taskStats') }}</div>
          <div class="v small">{{ t('pb.taskStatsTxt', { total: detail.taskTotal || 0, ok: detail.taskSuccess || 0, fail: detail.taskFailed || 0 }) }}</div>
        </div>
      </div>
    </div>

    <!-- 任务结果弹窗 -->
    <div class="modal-mask" v-if="result" @click.self="result = null">
      <div class="modal" style="max-width:820px">
        <div class="modal-head">
          <span>{{ t('pb.resultTitle') }} · {{ result.id }}</span>
          <button class="btn xs" @click="result = null">{{ t('common.close') }}</button>
        </div>
        <div class="kv">
          <div class="k">{{ t('pb.cStatus') }}</div>
          <div class="v"><span class="badge" :class="taskClass(result.status)">{{ t(TASK_STATUS[result.status] || result.status) }}</span></div>
          <div class="k">{{ t('pb.summary') }}</div><div class="v small">{{ result.summary || '-' }}</div>
          <div class="k">{{ t('pb.error') }}</div><div class="v small" style="color:var(--red)">{{ result.error || '-' }}</div>
          <div class="k">{{ t('pb.findings') }}</div><div class="v small">{{ result.findingNum || 0 }}</div>
          <div class="k">{{ t('pb.tDuration') }}</div><div class="v small mono">{{ result.durationMs ? (result.durationMs / 1000).toFixed(1) + 's' : '-' }}</div>
        </div>
        <div class="card-title" style="margin-top:12px">{{ t('pb.resultDetail') }}</div>
        <pre class="code-block" style="max-height:420px; overflow:auto">{{ result.result || t('pb.noDetail') }}</pre>
      </div>
    </div>

    <!-- 探针下载弹窗 -->
    <Modal v-if="showDownload" :title="t('pb.dlTitle')" width="760px" @close="showDownload = false">
      <div class="alert info">
        {{ t('pb.dlIntro1') }}<b>{{ t('pb.dlIntroZero') }}</b>{{ t('pb.dlIntro2') }}
      </div>

      <div class="kv" style="margin-bottom:14px">
        <div class="k">{{ t('pb.centerAddr') }}</div>
        <div class="v mono">{{ dlCenterAddr || t('pb.dlAddrNone') }}</div>
        <div class="k">{{ t('pb.nodeKey') }}</div>
        <div class="v mono">{{ dlToken || t('pb.dlTokenNone') }}</div>
        <div class="k">{{ t('pb.protoVer') }}</div>
        <div class="v mono">v{{ dlProtocol }} <span class="muted small">{{ t('pb.dlProtoSame') }}</span></div>
        <div class="k">{{ t('pb.dlDir') }}</div>
        <div class="v mono small">{{ dlDir || '-' }}</div>
      </div>

      <div class="table-wrap" v-if="dlList.length">
        <table class="table">
          <thead><tr><th>{{ t('pb.cPlat') }}</th><th>{{ t('pb.cArch') }}</th><th>{{ t('pb.cFile') }}</th><th>{{ t('pb.cSize') }}</th><th>{{ t('pb.cOp') }}</th></tr></thead>
          <tbody>
            <tr v-for="p in dlList" :key="p.os + '/' + p.arch + '/' + p.file">
              <td class="small">{{ p.label }}</td>
              <td class="mono small">{{ p.os ? p.os + '/' + p.arch : '-' }}</td>
              <td class="mono small" :title="p.file">{{ p.file }}</td>
              <td class="small muted">{{ fmtSize(p.size) }}</td>
              <td>
                <button class="btn xs" v-if="p.os" @click="downloadAgent(p)">{{ t('pb.dlBtn') }}</button>
                <span class="muted small" v-else :title="t('pb.listOnlyTip')">{{ t('pb.listOnly') }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="empty-hint" v-else>
        <b>{{ t('pb.dlNone') }}</b>
        <p class="muted small">{{ t('pb.dlNoneHint') }}</p>
      </div>

      <div class="card-title" style="margin-top:14px">{{ t('pb.dlUsage') }} <span class="sub">{{ t('pb.dlUsageSub') }}</span></div>
      <div class="alert info" style="margin:0 0 10px">
        <b>Windows</b>{{ t('pb.dlWin1') }}<b>{{ t('pb.dlWinDouble') }}</b>{{ t('pb.dlWin2') }}<span class="mono">C:\YugsightAgent</span>{{ t('pb.dlWin3') }}
        {{ t('pb.dlWin4') }}<b>{{ t('pb.dlWinUninst') }}</b>{{ t('pb.dlWin5') }}
      </div>
      <pre class="code-block" v-for="p in cmdList" :key="'cmd-' + p.os + p.arch">{{ cmdFor(p) }}</pre>
      <div class="toolbar" style="margin-top:10px" v-if="cmdList.length">
        <button class="btn sm" @click="copy(cmdsText())">{{ t('pb.copyCmd') }}</button>
        <button class="btn sm" @click="openGuide">{{ t('pb.guide') }}</button>
        <button class="btn sm primary" @click="openInstall">{{ t('pb.install') }}</button>
      </div>

      <div class="alert info" style="margin-top:10px">
        <b>{{ t('pb.dlAddrChgTitle') }}</b>: {{ t('pb.dlAddrChg1') }}
        <b>{{ t('pb.dlAddrChgRerun') }}</b>{{ t('pb.dlAddrChg2') }}
        <span class="muted small">{{ t('pb.dlAddrChg3') }}</span>
      </div>

      <template #footer>
        <button class="btn sm" @click="showDownload = false">{{ t('common.close') }}</button>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import Empty from '../components/Empty.vue'
import Modal from '../components/Modal.vue'
import { v2 } from '../api/http'
import { fmtDT } from '../utils'
import { setPageData } from '../assistant/context'
import { t } from '../i18n'

// 任务类型/状态值存 i18n 词条键, 模板渲染处 t() 解析(2026-10-04 i18n 批次 8)
const TASK_KIND = { port: 'pb.kPort', ip: 'pb.kIp', web: 'pb.kWeb', host: 'pb.kHost', image: 'pb.kImage', arp: 'pb.kArp' }
// 小 Y 助手(2026-09-27): 节点监控"探针管理"Tab 的关键数据(在线状态/版本/告警)
setPageData('nodemonitor:probe', () => ({
  total: total.value,
  probes: online.value.slice(0, 50).map(p => ({
    name: p.name || p.id,
    online: !!p.online,
    version: p.version || '',
    addr: p.addr || '',
    lastSeen: p.lastSeen || ''
  }))
}))
const TASK_STATUS = { pending: 'pb.stPending', sent: 'pb.stSent', running: 'pb.stRunning', success: 'pb.stSuccess', failed: 'pb.stFailed' }
const OS_NAME = { windows: 'Windows', linux: 'Linux', darwin: 'macOS' }
// 调度节点类型(scheduler.Node.Kind): 中心本地节点 ID 为空串, 展示名单独兜底
const NODE_KIND = { local: 'pb.kLocal', probe: 'pb.kProbe' }

const status = ref(null)
const online = ref([])
const total = ref(0)
const loading = ref(false)
const onlyOnline = ref(false)
const detail = ref(null)
const result = ref(null)
const showAssign = ref(false)
const assigning = ref(false)
const assignErr = ref('')
const assignMsg = ref('')
// 2026-09-26: 下发参数扩展 —— 探针继承中心端漏扫(host/web 可带 nuclei;
// image 类型走探针端 trivy, 可带 trivyArgs)
// 2026-09-27: arpDuration 供 type=arp 的 ARP 异常监测(默认 60s)
const assign = reactive({ probeId: '', type: 'port', target: '', ports: '', enableNuclei: false, nucleiTags: '', trivyArgs: '', arpDuration: 60 })
const enabling = ref(false)
const enableMsg = ref('')

// 2026-09-26: 上报参数下发(心跳/指标周期/离线判定)
const cfgForm = reactive({ heartbeatSec: 15, metricsSec: 30, offlineSec: 0 })
const savingCfg = ref(false)
const cfgNote = ref('')

const tasks = ref([])
const taskTotal = ref(0)
const taskLoading = ref(false)
const taskProbeId = ref('')
const taskStatus = ref('')

// centerAgentVer 中心端当前对外提供的 agent 版本(来自 /probe/status)。
//
// 用来把"探针版本"与"中心端版本"做对比展示。中心端是版本权威来源: 探针版本不等于
// 它时, 探针下次注册会自动更新(中心端在注册应答里下发更新指令), 页面只需如实标注。
const centerAgentVer = computed(() => (status.value && status.value.agentVersion) || '')

// verState 判断单个探针的版本状态: 'diff'(需更新) / 'same'(一致) / 'unknown'(无法判断)。
// 拿不到任一版本号时返回 unknown —— 不猜, 避免把"信息缺失"显示成"版本不一致"。
function verState(p) {
  const center = centerAgentVer.value
  if (!center || !p || !p.version) return 'unknown'
  return p.version === center ? 'same' : 'diff'
}

let timer = null

const centerText = computed(() => {
  if (!status.value) return '-'
  if (!status.value.centerEnabled) return t('pb.stNotEnabled')
  return status.value.center ? t('pb.stRunning') : t('pb.stStartFail')
})
const roleText = computed(() => {
  if (!status.value) return '-'
  const c = status.value.centerEnabled, p = status.value.clientEnabled
  if (c && p) return t('pb.roleCenterProbe')
  if (c) return t('pb.roleCenter')
  if (p) return t('pb.roleProbe')
  return t('pb.roleSolo')
})
const displayList = computed(() => (onlyOnline.value ? online.value.filter(p => p.online) : online.value))
const onlineProbes = computed(() => online.value.filter(p => p.online))
const assignReady = computed(() => !!(status.value && status.value.center && onlineProbes.value.length))
const myInfo = computed(() => (status.value && status.value.clientInfo) || {})
// 2026-09-27: arp 目标=本机网卡名(local=自动选), 与其它"远端目标"语义不同
const assignTargetLabel = computed(() => t({ ip: 'pb.tlCidr', port: 'pb.tlIp', web: 'pb.tlUrl', host: 'pb.tlIp', image: 'pb.tlImage', arp: 'pb.tlArp' }[assign.type] || 'pb.tlDefault'))
const assignTargetPh = computed(() => t({ ip: 'pb.phCidr', port: 'pb.phIp', web: 'pb.phIp', host: 'pb.phIp', image: 'pb.phImage', arp: 'pb.phArp' }[assign.type] || 'pb.phDefault'))

function capList(p) {
  return (p.capabilities || '').split(',').map(s => s.trim()).filter(Boolean)
}
function osText(p) {
  const n = nodeOf(p)
  const os = OS_NAME[n.os] || n.os || '-'
  return n.arch ? os + '/' + n.arch : os
}
// nodeOf 节点信息(注册时上报的原始快照, 字段见 probe.NodeInfo)
function nodeOf(p) {
  return (p && p.nodeInfo) || {}
}
function nicText(p) {
  const nics = nodeOf(p).netIfaces || []
  if (!nics.length) return (p && p.addr) || '-'
  return nics.map(n => n.name + ' ' + n.ip + (n.mac ? ' (' + n.mac + ')' : '')).join(' | ')
}
// 2026-09-27: 列表展示的 IP/MAC 取首个带地址的网卡(探针可能多网卡,
// 完整清单在"详情"弹窗的"网卡"行, 列表只给一眼可用的主网卡)。
function probeIP(p) {
  const n = (nodeOf(p).netIfaces || []).find(x => x && x.ip)
  return (n && n.ip) || ''
}
function probeMac(p) {
  const nics = nodeOf(p).netIfaces || []
  const n = nics.find(x => x && x.ip && x.mac) || nics.find(x => x && x.mac)
  return (n && n.mac) || ''
}
function loadText(p) {
  const ld = p && p.load
  if (!ld) return t('pb.loadNone')
  return t('pb.loadTxt', { cpu: Number(ld.cpuPercent || 0).toFixed(1), mem: Number(ld.memPercent || 0).toFixed(1), n: ld.tasksRunning || 0 }) +
    (ld.currentTask ? ' (' + ld.currentTask + ')' : '')
}
// mb 字节 -> MB(节点信息里内存/磁盘均为字节)
function mb(v) { return Math.round(Number(v || 0) / 1048576) }
function gb(v) { return Math.round(Number(v || 0) / 1073741824) }
function taskClass(s) {
  return { pending: 'st-pending', sent: 'st-running', running: 'st-running', success: 'st-success', failed: 'st-failed' }[s] || ''
}

// 一键开启探针中心端: 后端写 settings.json 的 probe 节(保留已有 listen/token),
// 重启后生效 —— 替代"手工编辑 JSON 再重启"的老路径(功能审计 P0-5)。
async function enableProbe() {
  enabling.value = true
  enableMsg.value = ''
  try {
    const d = await v2('/probe/enable', { method: 'POST' })
    enableMsg.value = (d && d.msg) || t('pb.cfgWritten')
    if (d && d.restartRequired) {
      if (confirm(t('pb.restartConfirm'))) {
        try {
          await fetch('/api/quit', { method: 'POST' })
        } catch (e) { /* 服务停止瞬间连接中断属正常 */ }
      }
    }
  } catch (e) {
    enableMsg.value = t('pb.enableFail', { err: e.message || e })
  } finally {
    enabling.value = false
  }
}

async function load() {
  loading.value = true
  try {
    const [st, ls] = await Promise.all([v2('/probe/status'), v2('/probe/list')])
    status.value = st
    online.value = ls.list || []
    total.value = ls.total || 0
    // 节点密钥仅供"下载探针"弹窗生成部署命令; 取不到就退回占位符(不报错)
    probeToken.value = (st && st.centerCfg && st.centerCfg.token) || ''
    // 2026-09-26: 上报参数表单从中心端当前配置回填(只回填一次, 避免轮询覆盖用户输入)
    if (st && st.centerCfg && !cfgInited.value) {
      cfgForm.heartbeatSec = st.centerCfg.heartbeatSec || 15
      cfgForm.metricsSec = st.centerCfg.metricsSec || 30
      cfgForm.offlineSec = st.centerCfg.offlineSec || 0
      cfgInited.value = true
    }
    // 详情弹窗数据实时刷新
    if (detail.value) {
      const cur = online.value.find(x => x.id === detail.value.id)
      if (cur) detail.value = cur
    }
  } catch (e) {
    status.value = null
  } finally { loading.value = false }
  await loadTasks()
  await loadSchedNodes() // 节点负载随心跳变化, 与探针状态同频刷新
}

// 2026-10-02: 探针/状态筛选选项 = 后端按全量任务聚合回带(只含真实存在的值)
const taskProbeOpts = ref([])
const taskStatusOpts = ref([])
function probeLabel(id) {
  const p = online.value.find(x => x.id === id)
  return (p && p.name) || id   // 探针已删/未注册 → 显 ID(历史任务仍可筛)
}
async function loadTasks() {
  taskLoading.value = true
  try {
    const p = new URLSearchParams({ page: '1', size: '50' })
    if (taskProbeId.value) p.set('probeId', taskProbeId.value)
    if (taskStatus.value) p.set('status', taskStatus.value)
    const d = await v2('/probe/tasks?' + p.toString())
    tasks.value = d.list || []
    taskTotal.value = d.total || 0
    taskProbeOpts.value = d.probes || []
    taskStatusOpts.value = d.statuses || []
    // 已选的筛选值对应任务全删 → 选项消失, 筛选自清(防列表卡死为空)
    if (taskProbeId.value && !taskProbeOpts.value.some(x => x.id === taskProbeId.value)) taskProbeId.value = ''
    if (taskStatus.value && !taskStatusOpts.value.some(x => x.id === taskStatus.value)) taskStatus.value = ''
  } catch (e) { tasks.value = [] } finally { taskLoading.value = false }
}

function openDetail(p) { detail.value = p }
function openResult(t) { result.value = t }

function quickAssign(p) {
  assign.probeId = p.id
  showAssign.value = true
  assignErr.value = ''
  assignMsg.value = ''
}

async function doAssign() {
  assignErr.value = ''
  assignMsg.value = ''
  if (!assign.probeId) { assignErr.value = t('pb.pickProbe'); return }
  // 2026-09-27: arp 的目标是"本机网卡", 允许留空(后端归一为 local=自动选);
  // 其它类型仍要求非空目标。
  if (assign.type !== 'arp' && !assign.target) { assignErr.value = t('pb.targetReq'); return }
  assigning.value = true
  try {
    // 2026-09-26: 漏扫参数随类型透传(host/web → nuclei; image → trivyArgs)
    const target = assign.type === 'arp' ? (assign.target || 'local') : assign.target
    const body = { probeId: assign.probeId, type: assign.type, target, ports: assign.ports }
    if (assign.type === 'host' || assign.type === 'web') {
      body.enableNuclei = assign.enableNuclei
      if (assign.nucleiTags) body.nucleiTags = assign.nucleiTags
    }
    if (assign.type === 'image' && assign.trivyArgs) body.trivyArgs = assign.trivyArgs
    if (assign.type === 'arp') body.arpDuration = assign.arpDuration || 60
    const d = await v2('/probe/assign', { method: 'POST', body })
    assignMsg.value = t('pb.assigned', { id: d.taskId, probe: d.probeId }) + (assign.type === 'arp' ? t('pb.assignedArp', { n: assign.arpDuration || 60 }) : '')
    assign.target = ''
    await loadTasks()
  } catch (e) { assignErr.value = e.message } finally { assigning.value = false }
}

// 2026-09-26: 保存并下发上报参数(PUT /probe/config, 中心端热应用)
const cfgInited = ref(false)
async function saveCfg() {
  cfgNote.value = ''
  savingCfg.value = true
  try {
    const d = await v2('/probe/config', {
      method: 'PUT',
      body: { heartbeatSec: cfgForm.heartbeatSec, metricsSec: cfgForm.metricsSec, offlineSec: cfgForm.offlineSec },
    })
    cfgNote.value = d.note || t('pb.saved')
  } catch (e) {
    cfgNote.value = e.message
  } finally { savingCfg.value = false }
}

async function cancelTask(task) {
  if (!confirm(t('pb.cancelConfirm', { id: task.id }))) return
  try {
    await v2('/probe/cancel', { method: 'POST', body: { probeId: task.probeNode, taskId: task.id } })
    await loadTasks()
  } catch (e) { alert(e.message) }
}

async function del(pg) {
  if (!confirm(t('pb.removeConfirm', { id: pg.id }))) return
  try { await v2('/probe/' + encodeURIComponent(pg.id), { method: 'DELETE' }); await load() }
  catch (e) { alert(e.message) }
}

// ===== 探针下载(agent 分发) =====

const showDownload = ref(false)
const dlList = ref([])
const dlDir = ref('')
const dlCenterAddr = ref('')
const dlToken = ref('')
const dlProtocol = ref(1)
// cmdList 需要命令行启动的平台(Windows 是双击自安装, 不需要命令)
const cmdList = computed(() => dlList.value.filter(x => x.os && x.os !== 'windows'))

async function openDownload() {
  showDownload.value = true
  try {
    const d = await v2('/probe/agent/list')
    dlList.value = d.list || []
    dlDir.value = d.dir || ''
    dlCenterAddr.value = d.centerAddr || ''
    dlProtocol.value = d.protocol || 1
  } catch (e) {
    dlList.value = []
  }
  // 密钥只在中心端启用时才有意义(未启用时 probeCfg 为空, 不误报"无密钥")
  dlToken.value = (status.value && status.value.centerEnabled) ? (probeToken.value || '') : ''
}

// agent 启动命令(Linux/macOS): 中心端地址与密钥取自后端(地址已按 listen 推导为
// 可连的局域网 IP), 缺失时保留占位符, 让用户明确知道要替换什么, 而不是给出一条
// 跑不通的命令。Windows 走双击自安装, 不需要命令。
function cmdFor(p) {
  const addr = dlCenterAddr.value || t('pb.cmdAddrPh')
  const token = dlToken.value || t('pb.cmdTokenPh')
  return './' + (p.file || 'yugsight-agent').replace(/\.exe$/, '') + ' -center ' + addr + ' -token ' + token
}

function cmdsText() {
  return cmdList.value.map(cmdFor).join('\n')
}

// 下载走浏览器原生下载: 服务端已设置 Content-Disposition, 且走会话 cookie 鉴权
// (不在 URL 带 token —— 密钥会进浏览器历史/代理日志)。
function downloadAgent(p) {
  window.open('/api/v2/probe/agent/download?os=' + p.os + '&arch=' + p.arch, '_blank')
}

function openGuide() {
  window.open('/api/v2/probe/agent/guide', '_blank')
}

// 可视化安装页: 服务端渲染的 HTML(含中心端地址与节点密钥的现成命令)。
// 走 requireAuth + 会话 cookie, 因此不能把链接随便外发给未登录的人 —— 页面里
// 带密钥。文案已在上方说明用途, 这里不再二次弹窗打断。
function openInstall() {
  window.open('/api/v2/probe/agent/install', '_blank')
}

async function copy(s) {
  try {
    await navigator.clipboard.writeText(s)
    alert(t('pb.copied'))
  } catch (e) { alert(t('pb.copyFail')) }
}

function fmtSize(v) {
  const n = Number(v || 0)
  if (!n) return '-'
  if (n < 1024) return n + ' B'
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'
  return (n / 1048576).toFixed(2) + ' MB'
}

// probeToken 中心端节点密钥(从 /probe/status 的 centerCfg 取, 见 load()).
const probeToken = ref('')

// ===== 调度节点负载(只读视图, 来自 /api/v2/scheduler/nodes) =====
const schedNodes = ref([])
const schedCapacity = ref(0)
// 调度总开关取自 /scheduler/status。必须如实标注"未启用": 未启用时节点表仍会
// 返回一个"可接纳"的中心本地节点, 只看节点会让人误以为排队派发已经在工作。
const schedEnabled = ref(false)
const schedOn = computed(() => schedEnabled.value)

function capListOf(s) {
  return (s || '').split(',').map(x => x.trim()).filter(Boolean)
}
// 负载未上报时显示 '-' 而不是 0%: 与"上报了 0%"是两回事, 混同会掩盖采集故障
function pct(v) {
  return v === null || v === undefined ? '-' : Number(v).toFixed(1) + '%'
}

async function loadSchedNodes() {
  try {
    const [nd, st] = await Promise.all([v2('/scheduler/nodes'), v2('/scheduler/status')])
    schedNodes.value = nd.nodes || []
    schedCapacity.value = nd.capacity || 0
    schedEnabled.value = !!(st && st.enabled)
  } catch (e) {
    schedNodes.value = []
    schedCapacity.value = 0
  }
}

onMounted(() => {
  load() // 内部已带 loadSchedNodes, 与探针状态同频刷新
  timer = setInterval(load, 5000) // 探针状态面板自动刷新
})
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
/* 同 Console.vue: 卡片标题栏的 .spacer 需要 flex:1 才能把右侧状态推到边 */
.card-title .spacer { flex: 1; }
</style>

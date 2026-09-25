<template>
  <div>
    <PageHeader title="规则库管理" desc="漏洞规则, 按适用范围(Web / 主机)归位">
      <span class="chip" :class="count ? 'on' : 'off'">共 {{ count }} 条规则</span>
      <button class="btn sm" @click="load" :disabled="loading"><span class="spinner" v-if="loading"></span> 刷新</button>
    </PageHeader>

    <!-- 统计: 总数 / 内置 / 外部导入 / 适用范围拆分 -->
    <div class="card">
      <div class="toolbar" style="flex-wrap:wrap; gap:10px">
        <span class="chip blue">规则总数 {{ count }}</span>
        <span class="chip">内置 {{ builtinCount }}</span>
        <span class="chip">外部导入 {{ externalCount }}</span>
        <span class="chip" :class="scopeCount('web') ? 'on' : 'off'">Web 范围 {{ scopeCount('web') }}</span>
        <span class="chip" :class="scopeCount('host') ? 'warn' : 'off'">主机范围 {{ scopeCount('host') }}</span>
      </div>
      <!-- 第二行: 严重级别分布 + 验证状态(导入规则默认已验证; 显式暂存的待验证规则不参与扫描, 需"标记已验证"后生效) -->
      <div class="toolbar" style="flex-wrap:wrap; gap:10px; margin-top:10px">
        <span class="chip" :class="'sev-' + s" v-for="s in SEVS" :key="s" :title="SEV_NAME[s]">
          {{ SEV_NAME[s] }} {{ sevCount(s) }}
        </span>
        <span class="chip on">已验证 {{ statusCount.verified }}</span>
        <span class="chip warn" v-if="statusCount.pending">
          <span class="spinner" v-if="verifying"></span> 待验证 {{ statusCount.pending }}
        </span>
        <span class="muted small" v-if="lastSync">上次 NVD 同步: <span class="mono">{{ lastSync }}</span></span>
      </div>
      <div class="muted small" style="margin-top:8px">
        外部规则目录: <span class="mono">{{ dir || 'vuln/' }}</span> (*.json, 导入即热加载, 无需重启)
      </div>
      <!-- 主机漏洞 CPE 库: 与上面的 Web 正则规则是两套独立体系(版本->CVE 匹配 + EOL 停补判定),
           用户曾反馈"规则库才 10 条还是 Web 的" —— 把主机侧的规模显式展示出来 -->
      <div class="muted small" style="margin-top:6px" v-if="cpeProducts">
        主机漏洞 CPE 库(服务版本 → CVE 匹配 + 停止支持判定, 主机扫描自动生效):
        <b>{{ cpeProducts }}</b> 个产品 / <b>{{ cpeCves }}</b> 条 CVE。
        内置于 exe; 一键同步可从 NVD 拉取最新 CVE 扩充规则(产物热生效, 无需重启)。
      </div>
      <!-- 一键同步 NVD: 后台拉取 + 进度轮询, 与官方模板更新共用进度条样式。
           2026-09 起 NVD 旧 2.0 端点退役(403), 后端已迁移 2.1 API; 可选 API Key
           把限速档从 5次/30秒 提到 50次/30秒(填一次自动保存到 settings.json) -->
      <div style="margin-top:10px" v-if="cpeProducts">
        <button class="btn sm" :disabled="sync.running || syncBusy" @click="startSync"
                title="从 NVD 2.1 API 拉取最新 CVE 数据扩充主机 CPE 规则库(需网络可达 services.nvd.nist.gov, 国内可能需要代理)。
默认增量: 有上次同步记录时只拉之后修改过的 CVE(秒级~分钟级); 勾选全量重同步则拉全部 ~40 万条(带 Key 约 3-5 分钟, 匿名约 20 分钟)。">
          <span class="spinner" v-if="sync.running"></span> 一键同步 NVD
        </button>
        <label style="margin-left:10px; cursor:pointer; user-select:none"
               title="默认增量: 只拉上次同步之后 NVD 修改过的 CVE, 秒级~分钟级。勾选后拉全部 ~40 万条(带 Key 约 3-5 分钟, 匿名约 20 分钟)。">
          <input type="checkbox" :disabled="sync.running || syncBusy" v-model="syncFull"> 全量重同步
        </label>
        <input class="input mono" style="width:280px; margin-left:10px" v-model.trim="syncKey"
               :disabled="sync.running || syncBusy" @keyup.enter="startSync"
               :placeholder="sync.apiKeyConfigured ? 'NVD API Key 已保存, 留空即用' : '可选: NVD API Key(留空=匿名档 5次/30秒)'"
               title="NVD 免费 API Key(nist.gov 申请)。带 Key 限速 50 次/30 秒, 全量同步约 3-5 分钟; 匿名约 20 分钟。填写后保存到 settings.json 的 nvd 节。">
        <span class="muted small" v-if="sync.running" style="margin-left:12px">
          {{ syncModeText }} ·
          <!-- 全量分批(2026-09-25): 按页分批, 每批 n 页, 跑完一批落一次盘, 中断可续 -->
          <template v-if="sync.batchTotal > 0">
            第 {{ (sync.batchIndex || 0) + 1 }}/{{ sync.batchTotal }} 批<template v-if="sync.batchFromPage"> (第 {{ sync.batchFromPage }}-{{ sync.batchToPage }} 页)</template> ·
          </template>
          {{ sync.currentPage }}/{{ sync.totalPages || '?' }} 页
          · 本次拉取 {{ sync.totalCves }} 条, 库内共 {{ sync.keptCves }}
        </span>
        <span class="muted small" v-else-if="sync.finished" style="margin-left:12px">
          完成: {{ sync.products }} 个产品 / {{ sync.keptCves }} 条 CVE
          <template v-if="sync.error"> (失败: {{ sync.error }})</template>
        </span>
        <!-- 中断过的分批同步: 必须说清"再点一次是续跑, 不是从头再来", 否则用户
             不敢点(怕 20 分钟白等)或误勾全量重跑(把已完成的批又跑一遍) -->
        <div class="muted small" v-if="sync.resumable && !sync.running" style="margin-left:12px; margin-top:4px">
          上次同步在第 {{ (sync.batchIndex || 0) + 1 }}/{{ sync.batchTotal }} 批中断, 已完成批次的数据已落盘 ——
          再点「一键同步」从第 {{ (sync.batchIndex || 0) + 1 }} 批继续; 勾选"全量重同步"则从头重跑。
        </div>
      </div>
      <div class="muted small err-line">{{ err }}</div>
    </div>

    <!-- ===== 官方规则模板更新 ===== -->
    <div class="card">
      <div class="card-title">
        官方规则模板更新
        <span class="sub">从官方模板仓库(Nuclei Templates)拉取可被内置引擎执行的 HTTP 模板, 应用前自动备份旧版本</span>
      </div>

      <!-- 版本状态: 本地版本 / 远端版本 / 直连通道可用性 -->
      <div class="toolbar" style="flex-wrap:wrap; gap:10px">
        <!-- 这个徽标说的是**自建源**通道(updater.sources)。没配源时 available 恒为
             false —— 早期版本这时直接显示绿色的"已是最新", 与下面"官方源有新修订"
             自相矛盾, 用户会以为官方模板也没更新(实际是根本没去查)。 -->
        <span class="chip" :class="upd.running ? 'warn' : (upd.available ? 'blue' : (upd.configured ? 'on' : 'off'))">
          <span class="spinner" v-if="upd.running"></span>
          {{ upd.running ? '更新进行中' : (upd.available ? '有新版本可更新' : (upd.configured ? '已是最新' : '自建源未配置')) }}
        </span>
        <span class="chip">本地版本 <span class="mono">{{ shortRev(upd.localCommit) }}</span></span>
        <span class="chip" v-if="upd.remoteCommit">远端版本 <span class="mono">{{ shortRev(upd.remoteCommit) }}</span></span>
        <span class="chip" v-if="upd.directRemoteRev">官方修订 <span class="mono">{{ shortRev(upd.directRemoteRev) }}</span></span>
        <span class="chip" :class="directEnabled ? 'on' : 'off'">
          官方源直连{{ directEnabled ? '已启用' : '未启用' }}
        </span>
        <div class="spacer"></div>
        <button class="btn sm" :disabled="updBusy || upd.running" @click="loadUpdStatus">检查更新</button>
        <button class="btn sm" :disabled="updBusy || upd.running" @click="openUpdLog">更新日志</button>
        <button class="btn sm" :disabled="updBusy || upd.running || !directEnabled" @click="startUpdate('direct')">
          <span class="spinner" v-if="upd.running && upd.channel === 'direct'"></span> 一键更新官方模板
        </button>
        <!-- 自建源通道(经典页迁移 P1-3): 走 settings.json updater.sources, 与官方直连是两个独立端点。
             〔2026-09-24〕未配置源时直接禁用: 点了必然报"未配置下载源", 而页面同时显示
             "官方源已启用 + 有新修订", 用户会误判成官方模板更新坏了(实测踩过)。 -->
        <button class="btn sm" :disabled="updBusy || upd.running || !upd.configured" @click="startUpdate('rules')"
                :title="upd.configured
                  ? '从 updater.sources 配置的自建下载源更新(源端需带 rules-manifest.json)'
                  : '未配置自建下载源: 需在 settings.json 的 updater.sources 填源地址。只想更新官方模板请用左侧「一键更新官方模板」(无需任何配置)'">
          <span class="spinner" v-if="upd.running && upd.channel === 'rules'"></span> 一键更新(自建源)
        </button>
      </div>

      <div class="muted small" style="margin-top:8px">
        <template v-if="!directEnabled">
          官方源直连未启用 —— 在 exe 同目录 settings.json 的 updater 节增加
          <span class="mono">"direct": { "enabled": true }</span> 即可(无需自建下载源)。
        </template>
        <template v-else-if="upd.directCheckError">
          官方源直连({{ upd.directRepo }}): {{ upd.directCheckError }}
        </template>
        <template v-else>
          官方源直连(<span class="mono">{{ upd.directRepo || '-' }}</span>): 本地
          <span class="mono">{{ shortRev(upd.directLocalRev) }}</span> ·
          {{ upd.directAvailable ? '远端有新修订, 可一键更新' : '本地已是最新, 无需更新' }}
        </template>
      </div>
      <!-- 网络优化指引折叠一行(审计 §7): 平时只占 summary 一行, 点开才展开三个方案。
           原来是 620px 弹窗 —— 指引是低频参考, 弹窗太重, 折叠行更符合"提示 ≤1 句"的规范 -->
      <details class="net-help" v-if="directEnabled && !upd.running && upd.directAvailable">
        <summary>直连 GitHub 可能较慢 —— 网络优化指引(代理 / 自建镜像 / 手动导入)</summary>
        <div class="net-help-body">
          <div class="net-plan">
            <div class="net-plan-head"><b style="color:var(--accent)">方案一 · 配代理环境变量</b>（推荐, 代理关了自动回退直连)
              <div style="flex:1"></div>
              <button class="btn xs" @click="copyText(netHelpProxy)">{{ copied === netHelpProxy ? '已复制' : '一键复制' }}</button>
            </div>
            <div class="small muted">程序只认环境变量, 不读 Windows「Internet 选项」。PowerShell 设一次(用户级), 重启生效:</div>
            <pre class="code-block">{{ netHelpProxy }}</pre>
            <div class="small muted">也可写死在 settings.json 的 updater.proxy, 但代理一关更新会直接失败, 不推荐。</div>
          </div>
          <div class="net-plan">
            <div class="net-plan-head"><b style="color:var(--accent)">方案二 · 自建内网镜像</b>(企业最优, 无变化零下载)
              <div style="flex:1"></div>
              <button class="btn xs" @click="copyText(netHelpSources)">{{ copied === netHelpSources ? '已复制' : '一键复制' }}</button>
            </div>
            <div class="small muted">镜像源需自带 rules-manifest.json(官方仓库不提供), 否则请用方案三:</div>
            <pre class="code-block">{{ netHelpSources }}</pre>
          </div>
          <div class="net-plan">
            <div class="net-plan-head"><b style="color:var(--accent)">方案三 · 手动导入模板包</b>(拷目录重启生效)</div>
            <div class="small muted">在能上网的机器上更新好, 把规则目录 <span class="mono">rules/</span> 整个拷到目标机器, 重启即生效(本地版本正确时不会再下载)。</div>
          </div>
          <div class="small muted" style="margin-top:8px">更新失败不影响在用规则: 失败会清除暂存并保留旧版本。</div>
        </div>
      </details>
      <div class="muted small" style="margin-top:4px" v-if="upd.tiered && upd.tiered.enabled">
        分级加载: 常驻 {{ upd.tiered.residentCount }} / 按需 {{ upd.tiered.onDemandCount }}
        (已加载 {{ upd.tiered.loadedCount }})
      </div>
      <div class="muted small err-line" v-if="updErr">{{ updErr }}</div>

      <!-- 进度条: 进行中显示, 结束后保留最后一次结果 -->
      <div v-if="upd.running || updProgText" style="margin-top:14px">
        <!-- 字节级进度(单包下载阶段): totalBytes=0 表示对端未给长度, 只显示已下载量不编造百分比 -->
        <div class="bar-row" v-if="upd.progress && upd.progress.totalBytes > 0">
          <span class="bar-label">下载</span>
          <div class="bar-track">
            <div class="bar-fill" :style="{ width: dlPercent + '%', background: 'var(--green)' }"></div>
          </div>
          <span class="bar-val">{{ dlPercent }}%</span>
        </div>
        <!-- 逐文件进度(自建源通道) -->
        <div class="bar-row" v-else-if="upd.progress && upd.progress.total > 0">
          <span class="bar-label">文件</span>
          <div class="bar-track">
            <div class="bar-fill" :style="{ width: filePercent + '%', background: 'var(--accent)' }"></div>
          </div>
          <span class="bar-val">{{ upd.progress.done || 0 }}/{{ upd.progress.total }}</span>
        </div>
        <div class="muted small mono" style="margin-left:74px">{{ updProgText }}</div>
      </div>

      <!-- 备份版本回滚: 更新出错或想退回旧版规则时使用 -->
      <div v-if="upd.backups && upd.backups.length" style="margin-top:14px; padding-top:12px; border-top:1px dashed var(--border)">
        <div class="small muted" style="margin-bottom:6px">
          可回滚的备份版本(每次更新前自动备份, 保留最近 3 版; 恢复后自动热加载):
        </div>
        <div class="toolbar" style="flex-wrap:wrap; gap:8px">
          <span v-for="b in upd.backups" :key="b" class="badge">
            <span class="mono">{{ b }}</span>
            <button class="btn xs" style="margin-left:6px" :disabled="updBusy || upd.running" @click="restore(b)">回滚</button>
          </span>
        </div>
      </div>
    </div>

    <!-- 适用范围页签: 全部 / Web / 主机 -->
    <div class="tabs">
      <div class="tab" :class="{ active: scopeTab === '' }" @click="scopeTab = ''">全部 ({{ rows.length }})</div>
      <div class="tab" :class="{ active: scopeTab === 'web' }" @click="scopeTab = 'web'">Web 范围 ({{ scopeCount('web') }})</div>
      <div class="tab" :class="{ active: scopeTab === 'host' }" @click="scopeTab = 'host'">主机范围 ({{ scopeCount('host') }})</div>
    </div>

    <div class="card">
      <div class="toolbar">
        <input class="input" v-model.trim="q" placeholder="过滤: ID / 名称 / 模式 / 详情">
        <select class="select" v-model="fSeverity">
          <option value="">全部等级</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
          <option value="info">信息</option>
        </select>
        <select class="select" v-model="fType">
          <option value="">全部匹配方式</option>
          <option value="body">body (响应体)</option>
          <option value="header">header (响应头)</option>
          <option value="path">path (敏感路径)</option>
        </select>
        <button class="btn sm" @click="resetF">清空</button>
        <div class="spacer"></div>
        <button class="btn sm" @click="showBuiltin">查看内置规则 JSON</button>
        <button class="btn sm primary" @click="openImport">导入自定义规则</button>
      </div>

      <div class="table-wrap" v-if="filtered.length">
        <!-- 规则库扩充到数千条后全量渲染会卡死页面: 截断到 500 行并引导用户用搜索/筛选收敛 -->
        <div class="muted small" v-if="filtered.length > 500" style="padding:8px 10px">
          共 {{ filtered.length }} 条, 仅显示前 500 条 —— 请用上方搜索或筛选条件收敛
        </div>
        <!-- 本表用 fixed 布局 + colgroup 定宽: auto 布局下列宽由内容决定, 4238 字符的
             模式会把该列撑到几千 px(横向滚动 + 大片空白); 且 td 上的 max-width 在 auto
             布局下不可靠(CSS 规范未定义)。fixed 后列宽只认 colgroup, 内容再长也不变形。 -->
        <table class="table rules-table">
          <colgroup>
            <col style="width:76px"><col style="width:190px"><col style="width:auto">
            <col style="width:80px"><col style="width:92px"><col style="width:280px">
            <col style="width:76px"><col style="width:160px"><col style="width:auto">
          </colgroup>
          <thead>
            <tr>
              <th>适用范围</th><th>ID</th><th>名称</th><th>等级</th>
              <th>匹配方式</th><th>模式</th><th>来源</th><th>状态</th><th>说明</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in visibleRows" :key="r.id">
              <td><span class="badge" :class="scopeBadge(r)">{{ scopeName(r) }}</span></td>
              <td class="mono small">{{ r.id }}</td>
              <td class="small"><b>{{ r.name }}</b></td>
              <td><SevTag :sev="r.severity" /></td>
              <td class="mono small">{{ r.type }}</td>
              <!-- 模式列: 单行截断 + 悬停 title 全文 + 点击弹窗看完整(可复制)。
                   【宽度约束必须落在内层 div 上】table-layout:auto 下 <td> 的 max-width
                   不生效(CSS 规范对 table-cell 的 max-width 未定义, 浏览器实测忽略) ——
                   早期版本把 max-width 写在 td 上, 4238 字符的正则折出上百行把整行撑变形。 -->
              <td>
                <div class="pattern-cell mono small" :title="r.pattern" @click="openPattern(r)">{{ r.pattern }}</div>
              </td>
              <td class="small">
                <span class="muted" v-if="r.source === 'builtin'">内置</span>
                <span class="badge st-pending" v-else>{{ r.source || '外部' }}</span>
              </td>
              <td>
                <!-- 内置规则恒已验证; 导入规则默认已验证(导入即生效); 显式待验证(暂存)的规则可手动"标记已验证" -->
                <span class="badge st-success" v-if="r.source === 'builtin'">已验证</span>
                <span class="badge st-success" v-else-if="r.status === 'verified'">已验证</span>
                <span v-else class="badge st-pending">待验证</span>
                <button class="btn xs" v-if="r.source !== 'builtin' && r.status !== 'verified'"
                        style="margin-left:6px" :disabled="verifying" @click="verifyRule(r)">标记已验证</button>
              </td>
              <td class="small muted" style="max-width:260px">{{ r.detail || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else :text="hasFilter ? '无匹配规则' : '暂无规则(内置规则应至少 10 条, 请检查服务端加载)'" />
    </div>

    <!-- 导入弹窗 -->
    <Modal v-if="importOpen" title="导入自定义规则" width="640px" @close="importOpen = false">
      <div class="field">
        <label class="label">文件名(可选, 留空按时间戳命名)</label>
        <input class="input mono" v-model.trim="importName" placeholder="custom_rules.json">
      </div>
      <div class="field" style="margin-top:10px">
        <label class="label">规则 JSON *</label>
        <textarea class="input mono" rows="10" v-model="importJSON" :placeholder="importPh"></textarea>
      </div>
      <div class="muted small" style="margin-top:8px">
        结构: <span class="mono">{ "rules": [ { "id", "name", "severity", "type", "pattern", "detail", "scope" } ] }</span>;
        type 仅支持 body / header / path; scope 为 web 或 host(留空按 type 推导)。
      </div>
      <div class="login-err" style="text-align:left">{{ importErr }}</div>
      <div class="login-err ok" style="text-align:left">{{ importOk }}</div>
      <template #footer>
        <button class="btn sm" @click="importOpen = false">关闭</button>
        <button class="btn sm primary" :disabled="busy" @click="doImport">导入</button>
      </template>
    </Modal>

    <!-- 内置规则 JSON 弹窗 -->
    <Modal v-if="builtinOpen" title="内置规则 JSON (vuln_builtin.json)" width="760px" @close="builtinOpen = false">
      <pre class="code-block" style="max-height:60vh; overflow:auto">{{ builtinJSON }}</pre>
      <template #footer>
        <button class="btn sm" @click="builtinOpen = false">关闭</button>
      </template>
    </Modal>

    <!-- 规则模式全文弹窗: 列表里只显示一行(超长正则否则会把整行撑变形), 点开看完整并可复制 -->
    <Modal v-if="patternOpen" :title="'规则模式 · ' + (patternRule.id || '')" width="760px" @close="patternOpen = false">
      <div class="muted small" style="margin-bottom:8px">
        {{ patternRule.name }} · 匹配方式 <span class="mono">{{ patternRule.type }}</span> ·
        共 {{ (patternRule.pattern || '').length }} 字符
      </div>
      <pre class="code-block mono" style="max-height:60vh; overflow:auto; white-space:pre-wrap; word-break:break-all">{{ patternRule.pattern }}</pre>
      <template #footer>
        <button class="btn sm" @click="patternOpen = false">关闭</button>
        <button class="btn sm primary" @click="copyText(patternRule.pattern)">
          {{ copied === patternRule.pattern ? '已复制' : '复制正则' }}
        </button>
      </template>
    </Modal>

    <!-- 更新日志弹窗 -->
    <Modal v-if="logOpen" title="规则库更新日志" width="900px" @close="logOpen = false">
      <div class="table-wrap" v-if="logEntries.length">
        <table class="table">
          <thead>
            <tr><th>时间</th><th>类型</th><th>版本变化</th><th>文件</th><th>结果</th><th>耗时</th><th>说明</th></tr>
          </thead>
          <tbody>
            <tr v-for="(e, i) in logEntries" :key="i">
              <td class="mono small">{{ fmtDT(e.time) }}</td>
              <td class="small">{{ e.kind || '-' }}</td>
              <td class="mono small">{{ shortRev(e.fromCommit) }} → {{ shortRev(e.toCommit) }}</td>
              <td class="mono small">{{ e.files || 0 }}</td>
              <td>
                <span class="badge" :class="e.status === 'success' ? 'st-success' : 'st-failed'">
                  {{ e.status === 'success' ? '成功' : '已回滚' }}
                </span>
              </td>
              <td class="mono small">{{ e.durationMs || 0 }}ms</td>
              <td class="small muted" style="max-width:280px">{{ e.error || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <Empty v-else text="暂无更新记录" />
      <template #footer>
        <button class="btn sm" @click="logOpen = false">关闭</button>
      </template>
    </Modal>

  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import Empty from '../components/Empty.vue'
import SevTag from '../components/SevTag.vue'
import Modal from '../components/Modal.vue'
import { api } from '../api/http'
import { fmtDT, fmtBytes, fmtSpeed, fmtDuration, etaSeconds, copyText as copy } from '../utils'

// 与 scanner.ScopeWeb / ScopeHost 对齐(见 scanner/vuln.go 的 Scope* 常量)
const SCOPE_NAME = { web: 'Web', host: '主机' }

const loading = ref(false)
const busy = ref(false)
const rows = ref([])
const dir = ref('')
const count = ref(0)
const serverScopes = ref(null) // 服务端汇总的适用范围计数(缺失时前端自行统计)
const scopeTab = ref('')
const q = ref('')
const fSeverity = ref('')
const fType = ref('')
const err = ref('')

const importOpen = ref(false)
const importName = ref('')
const importJSON = ref('')
const importErr = ref('')
const importOk = ref('')
const builtinOpen = ref(false)
const builtinJSON = ref('')
// 模式全文弹窗: nuclei 转换来的正则可达 5000+ 字符, 列表里单行截断, 点开看完整内容
const patternOpen = ref(false)
const patternRule = ref({})
function openPattern(r) {
  patternRule.value = r
  patternOpen.value = true
}

// 主机漏洞 CPE 库规模(来自 /api/info; 端点不可用时整行隐藏, 不报错)
const cpeProducts = ref(0)
const cpeCves = ref(0)
async function loadCpeStats() {
  try {
    const d = await api('/api/info')
    cpeProducts.value = d.cpeProducts || 0
    cpeCves.value = d.cpeCves || 0
  } catch (e) { /* 静默: 统计行是展示增强, 失败不影响页面主体 */ }
}

// 上次 NVD 同步完成时间(进度端点回带 finishedAt; 从未同步则为空, 隐藏展示)。
// 同步是长达 ~20 分钟的后台任务, 页面刷新/切页回来时若后端仍在跑, 必须
// 恢复进度显示并接续轮询(与 onMounted 里官方模板更新的接续逻辑同口径),
// 否则用户看到"按钮可点、没有任何进度", 误以为点击没生效。
async function loadLastSync() {
  try {
    const p = await api('/api/vuln/rules/sync/progress')
    if (!p) return
    if (p.running) {
      sync.value = { ...sync.value, ...p, running: true, finished: false }
      startSyncPoll()
      return
    }
    // 运行中 finishedAt 是零值字符串 "0001-01-01T00:00:00Z"(truthy), 不当完成时间展示
    if (p.finishedAt && p.finishedAt !== '0001-01-01T00:00:00Z') lastSync.value = fmtDT(p.finishedAt)
    // 同步"是否已保存 API Key", 供输入框占位符切换
    sync.value.apiKeyConfigured = !!p.apiKeyConfigured
    // 未运行时后端会回带"可续传"标记与断点批次(停服务/刷新页面后仍能看见)
    sync.value.resumable = !!p.resumable
    sync.value.batchIndex = p.batchIndex || 0
    sync.value.batchTotal = p.batchTotal || 0
  } catch (e) { /* 静默: 展示项, 失败不影响页面主体 */ }
}

// ===== NVD 一键同步 =====
// batchIndex/batchTotal/windowFrom~To: 全量分批进度; resumable: 存在未完成的批计划
const sync = ref({ running: false, finished: false, currentPage: 0, totalPages: 0, totalCves: 0, keptCves: 0, products: 0, error: '', apiKeyConfigured: false, mode: '', batchIndex: 0, batchTotal: 0, batchFromPage: 0, batchToPage: 0, resumable: false })
const syncModeText = computed(() => {
  const m = sync.value.mode
  if (m === 'incremental') return '增量'
  if (m === 'resume') return '续传'
  if (m === 'full-batch') return '全量分批'
  return '全量'
})
const syncBusy = ref(false)
// 可选 NVD API Key(留空 = 用已保存的或匿名档)。仅本地持有, 提交后由后端保存到 settings.json
const syncKey = ref('')
// 全量重同步开关(默认关 = 有上次同步记录时自动增量, 只拉修改过的 CVE)
const syncFull = ref(false)
let syncTimer = null

async function startSync() {
  if (sync.value.running) return
  const withKey = !!syncKey.value.trim()
  const how = syncFull.value
    ? '全量: 拉取全部 ~40 万条 CVE, 带 API Key 约 3-5 分钟, 匿名约 20 分钟(官方限流 5 次/30 秒)。\n'
    : '增量: 只拉上次同步之后 NVD 修改过的 CVE, 通常秒级~分钟级\n(无上次同步记录时自动回退全量)。\n'
  // 有未完成的批计划时, 本次是"续跑" —— 必须写在确认框里, 否则用户以为又要从头等 20 分钟
  const resumeNote = (sync.value.resumable && !syncFull.value)
    ? `\n检测到上次未完成的同步(第 ${(sync.value.batchIndex || 0) + 1}/${sync.value.batchTotal} 批), 本次从断点继续, 已完成批次不会重跑。\n`
    : ''
  if (!confirm('将从 NVD 2.1 API (services.nvd.nist.gov) 拉取 CVE 数据, 过滤到可指纹产品后写入 vuln/cpe/ 目录。\n\n' + how +
    resumeNote +
    '注意: 需网络可达 NVD(国内可能需要代理)。\n\n' +
    (withKey ? '本次将保存并使用新填写的 API Key。\n\n' : '') + '继续?')) return
  syncBusy.value = true
  sync.value = { running: true, finished: false, currentPage: 0, totalPages: 0, totalCves: 0, keptCves: 0, products: 0, error: '', apiKeyConfigured: withKey, mode: syncFull.value ? 'full' : (sync.value.resumable ? 'resume' : 'full-batch'), batchIndex: sync.value.resumable ? sync.value.batchIndex : 0, batchTotal: sync.value.batchTotal, batchFromPage: 0, batchToPage: 0, resumable: false }
  try {
    const body = { minCvss: 0, full: syncFull.value }
    if (syncKey.value.trim()) body.apiKey = syncKey.value.trim()
    await api('/api/vuln/rules/sync', { method: 'POST', body })
    syncKey.value = '' // 已保存到后端, 清空输入框让占位符回到"已保存, 留空即用"
    startSyncPoll()
  } catch (e) {
    sync.value.running = false
    sync.value.finished = true
    sync.value.error = e.message
  } finally { syncBusy.value = false }
}

function startSyncPoll() {
  if (syncTimer) return
  syncTimer = setInterval(async () => {
    try {
      const p = await api('/api/vuln/rules/sync/progress')
      if (p.running) {
        sync.value = { ...sync.value, ...p, finished: false }
        return
      }
      stopSyncPoll()
      sync.value = { ...sync.value, ...p, running: false, finished: true }
      if (p.finishedAt) lastSync.value = fmtDT(p.finishedAt)
      // 同步完成后刷新 CPE 统计
      loadCpeStats()
    } catch (e) { /* 瞬时网络抖动不终止 */ }
  }, 3000)
}

function stopSyncPoll() {
  if (syncTimer) { clearInterval(syncTimer); syncTimer = null }
}

// ===== 官方规则模板更新状态 =====
// upd 保存 /api/rules/update/status 的最新快照(版本 + 备份 + 直连通道)
const upd = ref({})
const updBusy = ref(false)
const updErr = ref('')
const updProgText = ref('')   // 进度文案(进行中与结束后共用, 结束后保留最后结果)
const logOpen = ref(false)
const logEntries = ref([])
let updTimer = null           // 进度轮询定时器, 必须在卸载时清理(否则离开页面仍在请求)

// 网络优化指引里的配置示例用 JS 常量而不是模板字面量:
// Vue 模板里直接写 JSON(含 {{ }})会被当插值解析并报 Unterminated string constant(历史踩坑)
const netHelpProxy =
  '# 设一次即可(用户级环境变量), 之后重启 Yugsight 生效\n' +
  '# 端口换成你自己代理的监听端口(Clash 默认 7890, v2ray 常见 10809)\n' +
  "[Environment]::SetEnvironmentVariable('HTTP_PROXY', 'http://127.0.0.1:7890', 'User')\n" +
  "[Environment]::SetEnvironmentVariable('HTTPS_PROXY', 'http://127.0.0.1:7890', 'User')\n" +
  // NO_PROXY 让内网地址不走代理: 否则内网请求被绕到代理, 轻则变慢重则连不通
  "[Environment]::SetEnvironmentVariable('NO_PROXY', 'localhost,127.0.0.1,192.168.*,10.*', 'User')"

const netHelpSources =
  '{\n' +
  '  "updater": {\n' +
  '    "sources": ["https://mirror.example.com/yugsight/"],\n' +
  '    "direct": { "enabled": false }\n' +
  '  }\n' +
  '}'

// 配置示例一键复制(审计 §4: 裸 JSON 只能手抄, 容易抄错引号与逗号)
const copied = ref('')
async function copyText(text) {
  if (await copy(text)) {
    copied.value = text
    setTimeout(() => { if (copied.value === text) copied.value = '' }, 2000)
  }
}

const directEnabled = computed(() => !!(upd.value.direct && upd.value.direct.enabled))

// 单包下载的百分比: totalBytes 为 0 表示对端未给 Content-Length, 此时不显示进度条
const dlPercent = computed(() => {
  const p = upd.value.progress || {}
  if (!p.totalBytes || p.totalBytes <= 0) return 0
  return Math.min(100, Math.floor((p.bytes || 0) * 100 / p.totalBytes))
})
const filePercent = computed(() => {
  const p = upd.value.progress || {}
  if (!p.total || p.total <= 0) return 0
  return Math.min(100, Math.floor((p.done || 0) * 100 / p.total))
})

// shortRev 把 commit 哈希截短展示(空值给出人话而不是空白)
function shortRev(s) {
  if (!s) return '未应用'
  return String(s).slice(0, 10)
}

// updProgTextLine 把进度结构拼成一行可读文案。
// 单包下载阶段 total/done(文件数)恒为 0/1, 没有信息量, 真正反映进度的是字节,
// 所以有字节时优先展示字节与速度, 没有才退回文件计数。
function updProgTextLine(p, prefix) {
  if (!p) return ''
  const status = p.status || '...'
  const bytes = p.bytes ? ' · ' + fmtBytes(p.bytes) + (p.totalBytes ? '/' + fmtBytes(p.totalBytes) : '') : ''
  const speed = p.speed ? ' · ' + fmtSpeed(p.speed) : ''
  const eta = fmtDuration(etaSeconds(p.bytes, p.totalBytes, p.speed))
  const files = p.total > 0 ? ' · ' + (p.done || 0) + '/' + p.total + ' 个文件' : ''
  return (prefix || '状态: ') + status + files + bytes + speed + (eta ? ' · 剩余约 ' + eta : '') +
    (p.current ? ' · ' + p.current : '')
}

async function loadUpdStatus() {
  updBusy.value = true
  updErr.value = ''
  try {
    const d = await api('/api/rules/update/status')
    upd.value = d || {}
    // 状态端点回带的 direct 段只含 enabled/repo/ref; 把 repo 提升到顶层供模板直接取用
    if (d && d.direct) upd.value.directRepo = d.direct.repo
  } catch (e) { updErr.value = '更新状态查询失败: ' + e.message }
  finally { updBusy.value = false }
}

// startUpdate 启动更新并开始轮询进度。
// 两个通道(direct / rules)共用同一套 /progress 状态, 只是启动端点不同, 因此合并成一个函数
// 避免两份几乎相同的轮询代码各自漂移。
async function startUpdate(channel) {
  if (upd.value.running) { updErr.value = '已有更新任务进行中'; return }
  if (channel === 'direct') {
    if (!confirm('将从官方模板仓库拉取 HTTP 模板并更新本地规则库(只保留可被内置引擎执行的模板)。\n\n首次更新需下载几十 MB 源码包, 请确认网络可达。继续?')) return
  }
  updErr.value = ''
  updProgText.value = channel === 'direct' ? '正在查询官方仓库最新修订...' : '更新已启动, 等待下载...'
  try {
    const path = channel === 'direct' ? '/api/rules/update/direct/start' : '/api/rules/update/start'
    await api(path, { method: 'POST' })
  } catch (e) {
    updErr.value = '无法启动更新: ' + e.message
    updProgText.value = ''
    return
  }
  // channel 一并写入 upd: 模板用它决定 spinner 挂在哪个按钮上
  upd.value = { ...upd.value, running: true, channel }
  startUpdPoll(channel)
}

// startUpdPoll 1.5s 轮询进度。定时器是长任务轮询的唯一来源,
// 停止条件必须覆盖"任务已结束"与"组件卸载"两种情况, 否则会泄漏。
function startUpdPoll(channel) {
  if (updTimer) return
  updTimer = setInterval(async () => {
    let p
    try {
      p = await api('/api/rules/update/progress')
    } catch (e) {
      // 瞬时网络抖动不终止轮询(下一轮重试); 但连续失败不应无限轮询, 由用户手动刷新兜底
      updProgText.value = '进度查询失败, 重试中...'
      return
    }
    if (p.running) {
      upd.value = { ...upd.value, running: true, progress: p.progress || {} }
      updProgText.value = updProgTextLine(p.progress, channel === 'direct' ? '直连: ' : '状态: ')
      return
    }
    // 任务结束: 先停轮询再处理结果, 避免结果处理期间又被定时器覆盖
    stopUpdPoll()
    const pg = p.progress || {}
    upd.value = { ...upd.value, running: false, progress: pg }
    if (p.error) {
      updErr.value = (channel === 'direct' ? '直连更新失败: ' : '更新失败: ') + p.error
      updProgText.value = '旧规则包未受影响, 详情见更新日志'
    } else if (p.result) {
      const r = p.result
      updProgText.value = r.updated
        ? '更新完成: ' + (r.files || 0) + ' 个模板, 版本 ' + shortRev(r.commit) + '(已自动热加载)'
        : '本地已是最新, 无需更新'
      if (r.errors && r.errors.length) updErr.value = '部分文件处理告警: ' + r.errors.join('; ')
    } else {
      updProgText.value = ''
    }
    // 更新后本地版本与规则列表都会变, 一并刷新
    loadUpdStatus()
    load()
  }, 1500)
}

function stopUpdPoll() {
  if (updTimer) { clearInterval(updTimer); updTimer = null }
}

// restore 回滚到指定备份版本(恢复后服务端自动热加载)
async function restore(label) {
  if (!confirm('确认回滚到备份版本 ' + label + ' ?\n\n当前同名规则文件会被该备份覆盖, 恢复后立即生效。')) return
  updBusy.value = true
  updErr.value = ''
  try {
    const d = await api('/api/rules/update/restore', { method: 'POST', body: { backup: label } })
    updProgText.value = '已回滚: 恢复 ' + (d.files || 0) + ' 个文件, 当前版本 ' + shortRev(d.localCommit) + '(已自动热加载)'
    await loadUpdStatus()
    await load()
  } catch (e) { updErr.value = '回滚失败: ' + e.message }
  finally { updBusy.value = false }
}

async function openUpdLog() {
  logOpen.value = true
  logEntries.value = []
  try {
    const d = await api('/api/rules/update/log')
    logEntries.value = d.entries || []
  } catch (e) { updErr.value = '更新日志查询失败: ' + e.message }
}

// 占位文案用 JS 常量: Vue 模板里直接写 {{...}} 字面量会被当插值解析,
// 报 "Unterminated string constant"(历史踩坑)
const importPh =
  '{"rules":[{"id":"CUSTOM-0001","name":"示例规则","severity":"medium",' +
  '"type":"body","pattern":"example","detail":"说明","scope":"web"}]}'

// 严重级别展示(与 scanner.RuleSeverityStats 的键一致): 顺序 = 风险高到低
const SEVS = ['critical', 'high', 'medium', 'low', 'info']
const SEV_NAME = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }

// 服务端 /api/vuln/rules 回带的统计(缺失时前端自行兜底为 0, 不报错)
const sevMap = ref({})      // 等级分布 {critical: n, ...}
const statusCount = ref({ verified: 0, pending: 0 })
const lastSync = ref('')    // 上次 NVD 同步完成时间(展示"上次拉取时间")
const verifying = ref(false)

const builtinCount = computed(() => rows.value.filter(r => r.source === 'builtin').length)
const externalCount = computed(() => Math.max(0, rows.value.length - builtinCount.value))
function sevCount(s) { return (sevMap.value && sevMap.value[s]) || 0 }

// verifyRule 把一条待验证(显式暂存)规则标记为已验证(靶机测试通过后的确认动作), 立即参与扫描。
async function verifyRule(r) {
  verifying.value = true
  try {
    await api('/api/vuln/rules/verify', { method: 'POST', body: { ids: [r.id] } })
    await load()
  } catch (e) { alert('标记失败: ' + e.message) }
  finally { verifying.value = false }
}
const hasFilter = computed(() => !!(q.value || fSeverity.value || fType.value || scopeTab.value))

function scopeName(r) { return SCOPE_NAME[r.scope] || r.scope || 'Web' }
// host 用蓝色徽章(中性区分), web 用绿色: 两者只是分类不是风险, 不用红色以免误读为告警
function scopeBadge(r) { return r.scope === 'host' ? 'st-pending' : 'st-success' }

const localScopeCounts = computed(() => {
  const c = { web: 0, host: 0 }
  for (const r of rows.value) c[r.scope === 'host' ? 'host' : 'web']++
  return c
})
function scopeCount(s) {
  if (serverScopes.value && typeof serverScopes.value[s] === 'number') return serverScopes.value[s]
  return localScopeCounts.value[s] || 0
}

const filtered = computed(() => {
  const kw = q.value.toLowerCase()
  return rows.value.filter(r => {
    if (scopeTab.value && (r.scope === 'host' ? 'host' : 'web') !== scopeTab.value) return false
    if (fSeverity.value && r.severity !== fSeverity.value) return false
    if (fType.value && r.type !== fType.value) return false
    if (!kw) return true
    return [r.id, r.name, r.pattern, r.detail].some(v => String(v || '').toLowerCase().includes(kw))
  })
})

// 渲染上限: 规则库扩充到数千条后全量渲染会卡死页面, 截断 500 行(数据全量在 filtered, 计数不受影响)
const visibleRows = computed(() => filtered.value.slice(0, 500))

function resetF() { q.value = ''; fSeverity.value = ''; fType.value = '' }

async function load() {
  loading.value = true
  err.value = ''
  try {
    const d = await api('/api/vuln/rules')
    rows.value = d.rules || []
    dir.value = d.dir || ''
    count.value = d.count != null ? d.count : rows.value.length
    serverScopes.value = d.scopes || null
    sevMap.value = d.severities || {}
    statusCount.value = d.status || { verified: 0, pending: 0 }
  } catch (e) { err.value = '加载失败: ' + e.message }
  finally { loading.value = false }
}

function openImport() {
  importErr.value = ''
  importOk.value = ''
  importOpen.value = true
}

async function doImport() {
  importErr.value = ''
  importOk.value = ''
  if (!importJSON.value.trim()) { importErr.value = '规则 JSON 不能为空'; return }
  busy.value = true
  try {
    const d = await api('/api/vuln/import', {
      method: 'POST',
      body: { json: importJSON.value, filename: importName.value }
    })
    importOk.value = '导入成功: 有效 ' + d.imported + ' 条, 当前共 ' + d.total + ' 条' +
      (d.warnings && d.warnings.length ? '; 警告: ' + d.warnings.join('; ') : '')
    importJSON.value = ''
    await load()
  } catch (e) { importErr.value = e.message }
  finally { busy.value = false }
}

async function showBuiltin() {
  try {
    // 该端点直接返回原始 JSON 文本(非 {error} 包装), api() 对非 JSON 响应已做兼容
    const d = await api('/api/vuln/builtin')
    builtinJSON.value = typeof d === 'string' ? d : JSON.stringify(d, null, 2)
    builtinOpen.value = true
  } catch (e) { err.value = '内置规则读取失败: ' + e.message }
}

onMounted(async () => {
  await load()
  await loadUpdStatus()
  loadCpeStats()
  loadLastSync()
  // 页面刷新时若后端仍有更新任务在跑(如切页/刷新浏览器), 自动接续轮询,
  // 否则用户会看到"按钮可点但一点就提示已有任务进行中", 无从得知正在跑什么
  try {
    const p = await api('/api/rules/update/progress')
    if (p && p.running) {
      upd.value = { ...upd.value, running: true }
      updProgText.value = updProgTextLine(p.progress, '状态: ')
      startUpdPoll('rules')
    }
  } catch (e) { /* 进度端点不可用不影响页面其它功能 */ }
})

// 定时器必须在卸载时清掉: 否则用户离开页面后仍以 1.5s 频率请求进度端点
onBeforeUnmount(() => { stopUpdPoll(); stopSyncPoll() })
</script>

<style scoped>
.err-line { color: var(--red); min-height: 16px; }
.login-err.ok { color: var(--green); }
textarea.input { resize: vertical; font-family: var(--mono); font-size: 12px; }

/* 等级分布 chip 配色(与漏洞列表等级色一致, 便于对照) */
.chip.sev-critical { color: var(--red); border-color: var(--red); }
.chip.sev-high { color: var(--red); border-color: var(--red); opacity: 0.85; }
.chip.sev-medium { color: var(--yellow); border-color: var(--yellow); }
.chip.sev-low { color: var(--accent); border-color: var(--accent); }
.chip.sev-info { color: var(--muted, #888); border-color: var(--border); }

/* 网络优化指引: 折叠时只占一行(summary), 展开后三个方案纵向排开 */
.net-help { margin-top: 4px; }
.net-help summary { cursor: pointer; color: var(--yellow); }
.net-help-body { margin-top: 10px; padding-left: 4px; line-height: 1.8; }
.net-plan { margin-bottom: 12px; }
.net-plan-head { display: flex; align-items: center; gap: 8px; }
.net-plan .code-block { margin: 6px 0; }

/* 规则列表用 fixed 布局: 列宽由 colgroup 定, 内容再长也不参与计算(见模板注释)。
   min-width 抬高到 1280px —— 9 列在 fixed 下若容器不够会挤成竖条, 宁可横向滚动。 */
.rules-table { table-layout: fixed; min-width: 1280px; }

/* 模式列: 单行截断, 超长正则(nuclei 转换的可达 5000+ 字符)不再把整行撑变形。
   【约束为什么写在内层 div 而不是 td 上】table.table 是 table-layout:auto,
   这种布局下 <td> 的 max-width 不生效 —— CSS 规范对 table-cell 的 max-width 在
   auto 布局里未定义, 浏览器实测直接忽略。早期版本写在 td 上, 4238 字符的规则
   折出上百行、单格 2000px+ 高。块级 div 的 max-width/overflow 才是可靠的。 */
.pattern-cell {
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: pointer;
}
.pattern-cell:hover { color: var(--accent); }
</style>

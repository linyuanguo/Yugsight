<template>
  <div>
    <PageHeader title="报告中心" desc="生成、对比与存档安全报告"></PageHeader>

    <!-- 未启用引导 -->
    <div class="card" v-if="status && !status.enabled">
      <div class="empty-hint">
        <b>报告引擎未启用</b>
        <p class="muted small">{{ status.hint || '请在配置文件中开启后重试' }}</p>
        <p class="muted small mono">配置文件: {{ status.configPath }}</p>
      </div>
    </div>

    <template v-else>
      <div class="tabs">
        <button class="tab" :class="{ on: tab === 'gen' }" @click="tab = 'gen'">报告生成</button>
        <button class="tab" :class="{ on: tab === 'raw' }" @click="tab = 'raw'; loadRaw()">原始报告</button>
        <button class="tab" :class="{ on: tab === 'arch' }" @click="tab = 'arch'; loadArchives()">报告存档</button>
        <button class="tab" :class="{ on: tab === 'topo' }" @click="tab = 'topo'; loadTopo()">资产拓扑</button>
        <button class="tab" :class="{ on: tab === 'diff' }" @click="tab = 'diff'; loadHistory()">历史对比</button>
        <!-- 模板管理默认隐藏(2026-09-21 收尾): 进阶功能, "报告生成"里已有模板下拉,
             独立 tab 常驻会干扰主流程; "高级"开关记忆用户选择(localStorage) -->
        <button class="tab" v-if="tplTabVisible" :class="{ on: tab === 'tpl' }" @click="tab = 'tpl'; loadTemplates(); loadPacks()">模板管理</button>
        <div class="spacer"></div>
        <a class="adv-toggle" href="javascript:void(0)" @click="toggleTplTab"
           :title="tplTabVisible ? '隐藏模板管理页签' : '显示模板管理页签(自定义报告模板)'">{{ tplTabVisible ? '收起高级' : '高级' }}</a>
        <span class="muted small" v-if="status && status.rawCount != null">原始报告 {{ status.rawCount }} 份</span>
        <span class="muted small" v-if="status && status.archiveCount != null">已存档 {{ status.archiveCount }} 份</span>
      </div>

      <!-- ===== 报告生成 ===== -->
      <div class="card" v-show="tab === 'gen'">
        <div class="form-grid">
          <label>报告标题<input class="input" v-model.trim="form.title" placeholder="留空则按时间自动命名"></label>
          <label>报告人<input class="input" v-model.trim="form.operator" placeholder="安全部"></label>
          <label>导出格式
            <select class="select" v-model="form.format">
              <option value="html">HTML(可离线归档)</option>
              <option value="pdf">PDF(自动唤起打印)</option>
              <option value="word">Word(.docx)</option>
            </select>
          </label>
          <label>模板包
            <select class="select" v-model="form.packId">
              <option value="">内置默认模板</option>
              <option v-for="p in packs" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
          </label>
          <label>旧版模板
            <select class="select" v-model="form.templateId">
              <option value="">不使用(页眉页脚模板)</option>
              <option v-for="t in templates" :key="t.id" :value="t.id">{{ t.name }}</option>
            </select>
          </label>
        </div>

        <div class="block-title">多维度筛选</div>
        <div class="form-grid">
          <label>风险等级
            <select class="select" v-model="form.f.severity">
              <option value="">全部等级</option>
              <option value="critical">严重</option>
              <option value="high">高危</option>
              <option value="medium">中危</option>
              <option value="low">低危</option>
              <option value="info">信息</option>
            </select>
          </label>
          <label>IP 段<input class="input mono" v-model.trim="form.f.cidr" placeholder="192.168.1.0/24"></label>
          <label>资产 IP<input class="input mono" v-model.trim="form.f.ip" placeholder="精确匹配"></label>
          <label>CVE 编号<input class="input mono" v-model.trim="form.f.cve" placeholder="支持前缀, 如 CVE-2021"></label>
          <label>扫描起始<input class="input" type="date" v-model="form.f.from"></label>
          <label>扫描截止<input class="input" type="date" v-model="form.f.to"></label>
          <label>探针节点
            <select class="select" v-model="form.f.probeNode">
              <option value="">全部节点</option>
              <option v-for="n in options.nodes" :key="n.id" :value="n.id">{{ n.name }}</option>
            </select>
          </label>
          <label class="chk"><input type="checkbox" v-model="form.f.onlyEvidence"> 仅含验证证据的漏洞</label>
        </div>

        <div class="toolbar" style="margin-top:14px">
          <button class="btn" @click="genPreview" :disabled="busy">预览报告</button>
          <button class="btn primary" @click="genDownload" :disabled="busy">生成并下载</button>
          <button class="btn" @click="genArchive" :disabled="busy">生成并存档</button>
          <span class="muted small" v-if="busy">处理中...</span>
        </div>

        <div class="preview-frame" v-if="previewURL">
          <div class="toolbar">
            <b>预览</b>
            <div class="spacer"></div>
            <button class="btn xs" @click="closePreview">关闭</button>
          </div>
          <iframe :src="previewURL" title="报告预览"></iframe>
        </div>
      </div>

      <!-- ===== 原始报告(二期: 业务模块执行后的原始结构化结果) ===== -->
      <div class="card" v-show="tab === 'raw'">
        <p class="muted small" style="margin:0 0 10px">
          实时抓包 / 扫描作业 / 弱口令检测 / 节点监控执行完成后, 原始结构化结果自动存到这里(只存原始数据, 不做加工)。
          业务页"AI 分析"的研判结果挂在本报告下(带 AI 徽标), 原始数据 + AI 研判可同时查看;
          勾选多份(含已 AI 分析的)可合并为汇总报告, AI 内容随合并保留。
        </p>
        <div class="toolbar">
          <select class="select" v-model="rawF.module" @change="loadRaw()">
            <option value="">全部来源</option>
            <option v-for="m in rawOptions.modules" :key="m.id" :value="m.id">{{ m.label }} ({{ m.count }})</option>
          </select>
          <select class="select" v-model="rawF.tag" @change="loadRaw()">
            <option value="">全部标签</option>
            <option v-for="t in rawOptions.tags" :key="t" :value="t">{{ t }}</option>
          </select>
          <input class="input mono" v-model.trim="rawF.asset" placeholder="资产 IP(支持前缀)" @keyup.enter="loadRaw()">
          <input class="input" type="date" v-model="rawF.from" title="起始日期">
          <span class="muted">~</span>
          <input class="input" type="date" v-model="rawF.to" title="截止日期">
          <input class="input" v-model.trim="rawF.keyword" placeholder="标题/摘要关键字" @keyup.enter="loadRaw()">
          <button class="btn sm" @click="loadRaw()">查询</button>
          <button class="btn xs" @click="resetRawFilter">重置</button>
          <div class="spacer"></div>
          <span class="muted small">共 {{ rawTotal }} 份</span>
        </div>

        <!-- 合并栏: 选中 >=1 份时出现 -->
        <div class="raw-mergebar" v-if="rawSel.length">
          <span><b>{{ rawSel.length }}</b> 份已选</span>
          <input class="input" v-model.trim="mergeForm.title" placeholder="合并报告标题(留空自动命名)">
          <input class="input" v-model.trim="mergeForm.tags" placeholder="标签(逗号分隔)">
          <button class="btn primary sm" @click="mergeRaw" :disabled="rawBusy || rawSel.length < 2">
            {{ rawBusy ? '合并中...' : '合并为汇总报告' }}
          </button>
          <button class="btn xs" @click="rawSel = []">清空选择</button>
          <span class="muted small" v-if="rawSel.length === 1">至少选 2 份才能合并</span>
        </div>

        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th style="width:30px"><input type="checkbox" :checked="allRawSelected" @change="toggleAllRaw"></th>
                <th>报告</th>
                <th>来源模块</th>
                <th>来源标记</th>
                <th>资产</th>
                <th>关键统计</th>
                <th>标签</th>
                <th>生成时间</th>
                <th style="width:110px">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in rawList" :key="r.id">
                <td><input type="checkbox" :checked="rawSel.includes(r.id)" @change="toggleRawSel(r.id)"></td>
                <td>
                  <b class="small">{{ r.title }}</b>
                  <span class="badge ai-badge" v-if="r.aiAnalyzedAt" :title="'AI 分析于 ' + fmtDT(r.aiAnalyzedAt)">AI</span>
                  <div class="muted small" v-if="r.summary">{{ r.summary }}</div>
                </td>
                <td><span class="badge" :class="'mod-' + rawModKey(r.module)">{{ rawModLabel(r.module) }}</span></td>
                <td class="mono small">{{ r.source || '-' }}<template v-if="r.operator"> / {{ r.operator }}</template></td>
                <td class="mono small">
                  <template v-if="r.assets && r.assets.length">
                    {{ r.assets.slice(0, 3).join(', ') }}<span v-if="r.assets.length > 3"> …共{{ r.assets.length }}</span>
                  </template>
                  <span v-else class="muted">-</span>
                </td>
                <td class="mono small">{{ rawStatsText(r) }}</td>
                <td><span class="tag-mini" v-for="t in (r.tags || [])" :key="t">{{ t }}</span></td>
                <td class="muted small mono">{{ fmtDT(r.createdAt) }}</td>
                <td>
                  <button class="btn xs" @click="viewRaw(r)">查看</button>
                  <button class="btn xs" @click="delRaw(r)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-if="!rawList.length" text="暂无原始报告(各业务模块执行完成后自动存入; 节点监控在「立即采集」或「存快照」时存入)"></Empty>

        <!-- 原始报告详情 -->
        <Modal v-if="rawDetail" :title="rawDetail.title" @close="rawDetail = null">
          <table class="kv">
            <tr><td>来源模块</td><td><span class="badge" :class="'mod-' + rawModKey(rawDetail.module)">{{ rawModLabel(rawDetail.module) }}</span></td></tr>
            <tr><td>来源标记</td><td class="mono">{{ rawDetail.source || '-' }}<template v-if="rawDetail.operator"> / {{ rawDetail.operator }}</template></td></tr>
            <tr v-if="rawDetail.target"><td>目标</td><td class="mono">{{ rawDetail.target }}</td></tr>
            <tr v-if="rawDetail.assets && rawDetail.assets.length"><td>涉及资产</td><td class="mono small">{{ rawDetail.assets.join(', ') }}</td></tr>
            <tr v-if="rawDetail.tags && rawDetail.tags.length"><td>标签</td><td><span class="tag-mini" v-for="t in rawDetail.tags" :key="t">{{ t }}</span></td></tr>
            <tr v-if="rawDetail.durationMs"><td>执行耗时</td><td class="mono">{{ (rawDetail.durationMs / 1000).toFixed(1) }} s</td></tr>
            <tr><td>生成时间</td><td class="mono">{{ fmtDT(rawDetail.createdAt) }}</td></tr>
          </table>
          <p class="muted small" v-if="rawDetail.summary" style="margin:8px 0 0">{{ rawDetail.summary }}</p>

          <!-- 按模块的摘要视图(只读原始结构化数据, 不做加工) -->
          <template v-if="rawDetail.module === 'scan' && rawScanFindings.length">
            <div class="block-title">漏洞发现({{ rawScanFindings.length }})</div>
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>级别</th><th>标题</th><th>CVE</th><th>资产</th><th>端口</th></tr></thead>
                <tbody>
                  <tr v-for="(f, i) in rawScanFindings" :key="i">
                    <td><SevTag :sev="f.severity || 'info'" /></td>
                    <td class="small">{{ f.title }}</td>
                    <td class="mono small">{{ f.cve || '-' }}</td>
                    <td class="mono small">{{ f.host || '-' }}</td>
                    <td class="mono small">{{ f.port || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>

          <template v-if="rawDetail.module === 'weakpass' && rawWpResults.length">
            <div class="block-title">检测结果({{ rawWpResults.length }})</div>
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>目标</th><th>服务</th><th>结果</th><th>命中口令</th><th>备注</th></tr></thead>
                <tbody>
                  <tr v-for="(r, i) in rawWpResults" :key="i">
                    <td class="mono small">{{ r.host }}:{{ r.port }}</td>
                    <td class="mono small">{{ r.service }}</td>
                    <td>
                      <span class="badge" :class="r.ok ? 'mod-weakpass' : 'mod-other'">{{ r.ok ? '命中' : '未命中' }}</span>
                      <span class="muted small" v-if="r.emptyPass && r.ok">空口令</span>
                    </td>
                    <td class="mono small">{{ r.password || '-' }}</td>
                    <td class="small muted">{{ r.stopped || r.error || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>

          <template v-if="rawDetail.module === 'capture' && rawPkts.length">
            <div class="block-title">报文({{ rawDetail.payload && rawDetail.payload.packets ? rawDetail.payload.packets.length : 0 }}, 展示前 {{ rawPkts.length }} 条)</div>
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>时间</th><th>协议</th><th>源</th><th>目的</th><th>长度</th><th>摘要</th></tr></thead>
                <tbody>
                  <tr v-for="p in rawPkts" :key="p.seq">
                    <td class="mono small">{{ p.time }}</td>
                    <td class="mono small">{{ p.protocol }}</td>
                    <td class="mono small">{{ p.srcIp || p.srcMac }}</td>
                    <td class="mono small">{{ p.dstIp || p.dstMac }}</td>
                    <td class="mono small">{{ p.length }}</td>
                    <td class="small muted">{{ p.info }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>

          <template v-if="rawDetail.module === 'monitor' && rawMonTargets.length">
            <div class="block-title">监控目标({{ rawMonTargets.length }})</div>
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>名称</th><th>地址</th><th>版本</th><th>状态</th><th>运行时长</th><th>CPU</th><th>内存</th><th>接口数</th></tr></thead>
                <tbody>
                  <tr v-for="t in rawMonTargets" :key="t.id">
                    <td class="small">{{ t.name || t.id }}</td>
                    <td class="mono small">{{ t.addr }}</td>
                    <td class="mono small">{{ t.version }}</td>
                    <td>
                      <span v-if="t.sample" class="badge" :class="t.sample.ok ? 'mod-scan' : 'mod-other'">{{ t.sample.ok ? '在线' : '离线' }}</span>
                      <span v-else class="muted small">未采集</span>
                    </td>
                    <td class="mono small">{{ t.sample && t.sample.uptimeSec ? (t.sample.uptimeSec / 3600).toFixed(1) + ' h' : '-' }}</td>
                    <td class="mono small">{{ t.sample && t.sample.cpuLoad ? t.sample.cpuLoad + '%' : '-' }}</td>
                    <td class="mono small">{{ t.sample && t.sample.memTotal ? (t.sample.memUsed / 1048576).toFixed(0) + '/' + (t.sample.memTotal / 1048576).toFixed(0) + ' MB' : '-' }}</td>
                    <td class="mono small">{{ t.sample && t.sample.ifNumber || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>

          <template v-if="rawDetail.module === 'merged' && rawSections.length">
            <div class="block-title">汇总章节(按来源模块)</div>
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>来源模块</th><th>报告数</th></tr></thead>
                <tbody>
                  <tr v-for="s in rawSections" :key="s.module">
                    <td><span class="badge" :class="'mod-' + rawModKey(s.module)">{{ rawModLabel(s.module) }}</span></td>
                    <td class="mono small">{{ s.count }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="block-title" v-if="rawMergedFrom.length">来源报告({{ rawMergedFrom.length }})</div>
            <div class="table-wrap" v-if="rawMergedFrom.length">
              <table class="table">
                <thead><tr><th>ID</th><th>标题</th><th>来源</th><th>时间</th><th>AI</th></tr></thead>
                <tbody>
                  <tr v-for="m in rawMergedFrom" :key="m.id">
                    <td class="mono small">{{ m.id }}</td>
                    <td class="small">{{ m.title }}</td>
                    <td class="mono small">{{ m.source || '-' }}</td>
                    <td class="muted small mono">{{ fmtDT(m.createdAt) }}</td>
                    <td>
                      <span class="badge ai-badge" v-if="m.ai && m.ai.aiNote" :title="'AI: ' + m.ai.aiNote">AI</span>
                      <span v-else class="muted small">—</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <!-- 合并报告的源 AI 研判: 逐源可展开(合并 = 原始报告 + AI 报告的整合) -->
            <details v-for="m in rawMergedFrom" :key="'ai-' + m.id" v-if="m.ai && m.ai.aiNote" class="raw-ai-src">
              <summary class="muted small">查看「{{ m.title }}」的 AI 研判</summary>
              <pre class="raw-ai-note">{{ m.ai.aiNote }}</pre>
            </details>
          </template>

          <!-- AI 分析(阶段 3): 业务页触发的研判结果挂在本报告下 -->
          <div class="block-title">AI 分析</div>
          <p class="muted small" v-if="!rawDetail.aiAnalyzedAt">
            尚未进行 AI 分析。在对应业务页面(实时抓包 / 扫描作业 / 弱口令 / 节点监控)点"AI 分析",
            研判结果会自动存到本报告(参数与知识库在 系统配置 → AI 配置 管理)。
          </p>
          <div v-else>
            <p class="muted small mono">
              分析时间: {{ fmtDT(rawDetail.aiAnalyzedAt) }}
              <template v-if="rawAiData.model"> · 模型: {{ rawAiData.model }}</template>
              <template v-if="rawAiData.template"> · {{ rawAiData.template }}</template>
              <template v-if="rawAiData.ragHits"> · RAG 参考 {{ rawAiData.ragHits }} 条</template>
              <template v-if="rawAiData.memoryItems"> · 历史记忆 {{ rawAiData.memoryItems }} 条</template>
              <template v-if="rawAiData.elapsedMs"> · 耗时 {{ (rawAiData.elapsedMs / 1000).toFixed(1) }}s</template>
            </p>
            <pre class="raw-ai-note">{{ rawDetail.aiNote }}</pre>
          </div>

          <!-- 原始 JSON(可折叠, 大正文截断展示) -->
          <details class="raw-json">
            <summary>原始数据(JSON)</summary>
            <pre class="mono small">{{ prettyPayload() }}</pre>
          </details>
          <template #footer>
            <button class="btn sm" @click="copyPayload">复制原始 JSON</button>
            <button class="btn sm" @click="rawDetail = null">关闭</button>
          </template>
        </Modal>
      </div>

      <!-- ===== 报告存档 ===== -->
      <div class="card" v-show="tab === 'arch'">
        <div class="toolbar">
          <button class="btn sm" @click="loadArchives">刷新</button>
          <div class="spacer"></div>
          <span class="muted small">共 {{ archives.length }} 份</span>
        </div>
        <div class="table-wrap" v-if="archives.length">
          <table class="table">
            <thead>
              <tr><th>标题</th><th>格式</th><th>漏洞</th><th>资产</th><th>风险分</th><th>报告人</th><th>生成时间</th><th style="width:150px">操作</th></tr>
            </thead>
            <tbody>
              <tr v-for="a in archives" :key="a.id">
                <td>
                  <b style="font-size:12.5px">{{ a.title }}</b>
                  <span class="badge" v-if="a.kind === 'diff'" style="margin-left:6px">对比</span>
                </td>
                <td class="mono small">{{ (a.format || 'html').toUpperCase() }}</td>
                <td class="mono small">{{ a.stats ? a.stats.vulnTotal : '-' }}</td>
                <td class="mono small">{{ a.stats ? a.stats.assetTotal : '-' }}</td>
                <td><span class="score" :class="scoreCls(a.stats)">{{ a.stats ? a.stats.riskScore : '-' }}</span></td>
                <td class="small muted">{{ a.operator || '-' }}</td>
                <td class="muted small mono">{{ fmtDT(a.createdAt) }}</td>
                <td>
                  <button class="btn xs" @click="download(a)">下载</button>
                  <button class="btn xs" @click="del(a)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else text="暂无报告存档(生成报告时默认归档)"></Empty>
      </div>

      <!-- ===== 资产拓扑 ===== -->
      <div class="card" v-show="tab === 'topo'">
        <div class="toolbar">
          <select class="select" v-model="topoFilter.severity" @change="loadTopo">
            <option value="">全部等级</option>
            <option value="critical">严重</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
          </select>
          <input class="input mono" v-model.trim="topoFilter.cidr" placeholder="IP 段筛选 10.0.0.0/24" @keyup.enter="loadTopo">
          <button class="btn sm" @click="loadTopo">查询</button>
          <div class="spacer"></div>
          <span class="muted small" v-if="topoStats">
            资产 {{ topoStats.assets }} / 端口 {{ topoStats.ports }} / 服务 {{ topoStats.services }} / 高危资产 {{ topoStats.atRisk }}
          </span>
        </div>

        <div class="legend">
          <span class="lg"><i class="dot critical"></i>严重</span>
          <span class="lg"><i class="dot high"></i>高危</span>
          <span class="lg"><i class="dot medium"></i>中危</span>
          <span class="lg"><i class="dot low"></i>低危</span>
          <span class="lg"><i class="dot none"></i>无风险</span>
          <span class="lg"><i class="dot offline"></i>离线/未知</span>
        </div>

        <div class="topo-wrap" v-if="topoNodes.length">
          <div class="topo-node" v-for="n in topoNodes" :key="n.id"
               :class="['risk-' + (n.risk || 'none'), { dim: n.unknown }]"
               @click="onNodeClick(n)">
            <div class="tn-head">
              <span class="tn-kind">{{ nodeKindName(n.kind) }}</span>
              <span class="tn-on" v-if="n.kind === 'asset'">{{ n.unknown ? '未知' : (n.online ? '在线' : '离线') }}</span>
            </div>
            <div class="tn-label mono">{{ n.label }}</div>
            <div class="tn-meta" v-if="n.service">服务: {{ n.service }}</div>
            <div class="tn-meta" v-if="n.vulnCount">漏洞: {{ n.vulnCount }}</div>
            <div class="tn-meta" v-if="n.probeNode">节点: {{ n.probeNode }}</div>
          </div>
        </div>
        <Empty v-else text="暂无拓扑数据(需先有资产与扫描结果)"></Empty>

        <!-- 点击节点详情 -->
        <Modal v-if="sel" :title="'节点详情 · ' + sel.label" @close="sel = null">
          <table class="kv">
            <tr><td>类型</td><td>{{ nodeKindName(sel.kind) }}</td></tr>
            <tr><td>标识</td><td class="mono">{{ sel.id }}</td></tr>
            <tr v-if="sel.kind === 'asset'"><td>IP</td><td class="mono">{{ sel.ip }}</td></tr>
            <tr v-if="sel.hostname"><td>主机名</td><td>{{ sel.hostname }}</td></tr>
            <tr v-if="sel.os"><td>操作系统</td><td>{{ sel.os }}</td></tr>
            <tr v-if="sel.service"><td>服务</td><td>{{ sel.service }}</td></tr>
            <tr v-if="sel.probeNode"><td>探针节点</td><td class="mono">{{ sel.probeNode }}</td></tr>
            <tr><td>风险等级</td><td><SevTag :sev="sel.risk || 'info'" /></td></tr>
            <tr v-if="sel.kind === 'asset'"><td>在线状态</td><td>{{ sel.unknown ? '未知' : (sel.online ? '在线' : '离线') }}</td></tr>
            <tr><td>关联漏洞</td><td>{{ sel.vulnCount || 0 }}</td></tr>
          </table>
          <template #footer>
            <button class="btn sm" @click="viewVulns(sel)" v-if="sel.kind === 'asset'">查看该资产漏洞</button>
            <button class="btn sm" @click="sel = null">关闭</button>
          </template>
        </Modal>
      </div>

      <!-- ===== 历史对比 ===== -->
      <div class="card" v-show="tab === 'diff'">
        <div class="toolbar">
          <span class="small muted">目标轮次时间窗</span>
          <input class="input" type="date" v-model="diffForm.from">
          <span class="muted">~</span>
          <input class="input" type="date" v-model="diffForm.to">
          <button class="btn sm" @click="runDiff" :disabled="diffBusy">开始对比</button>
          <div class="spacer"></div>
          <label class="chk small"><input type="checkbox" v-model="diffForm.save"> 存档对比报告</label>
        </div>
        <p class="muted small" style="margin:6px 0 0">
          基线自动取目标时间窗之前等长的一段; 两侧都按「资产 + CVE」匹配(无 CVE 时按资产+协议:端口+标题)。人工标记的误报不参与对比。
        </p>

        <div v-if="diff">
          <div class="block-title">差异总览</div>
          <div class="stat-row">
            <div class="stat new"><b>{{ diff.stats.newCount }}</b><span>新增漏洞</span></div>
            <div class="stat fixed"><b>{{ diff.stats.fixedCount }}</b><span>已修复</span></div>
            <div class="stat keep"><b>{{ diff.stats.persistedCount }}</b><span>仍然存在</span></div>
            <div class="stat delta"><b>{{ diff.stats.delta }}</b><span>总数变化</span></div>
            <div class="stat crit"><b>{{ diff.stats.newCritical }}</b><span>新增严重</span></div>
          </div>

          <div class="block-title">新增漏洞({{ diff.stats.newCount }})</div>
          <div class="table-wrap" v-if="diff.new && diff.new.length">
            <table class="table">
              <thead><tr><th>级别</th><th>标题</th><th>CVE</th><th>资产</th><th>端口</th></tr></thead>
              <tbody>
                <tr v-for="(d, i) in diff.new" :key="i">
                  <td><SevTag :sev="d.targetSeverity" /></td>
                  <td class="small">{{ d.title }}</td>
                  <td class="mono small">{{ d.cve || '-' }}</td>
                  <td class="mono small">{{ d.assetIp }}</td>
                  <td class="mono small">{{ d.port || '-' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <Empty v-else text="本段对比未发现新增漏洞"></Empty>

          <div class="block-title">已修复漏洞({{ diff.stats.fixedCount }})</div>
          <div class="table-wrap" v-if="diff.fixed && diff.fixed.length">
            <table class="table">
              <thead><tr><th>原级别</th><th>标题</th><th>CVE</th><th>资产</th><th>端口</th></tr></thead>
              <tbody>
                <tr v-for="(d, i) in diff.fixed" :key="i">
                  <td><SevTag :sev="d.baseSeverity" /></td>
                  <td class="small">{{ d.title }}</td>
                  <td class="mono small">{{ d.cve || '-' }}</td>
                  <td class="mono small">{{ d.assetIp }}</td>
                  <td class="mono small">{{ d.port || '-' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <Empty v-else text="本段对比未发现已修复漏洞"></Empty>

          <div class="block-title">仍然存在({{ diff.stats.persistedCount }})</div>
          <div class="table-wrap" v-if="diff.persisted && diff.persisted.length">
            <table class="table">
              <thead><tr><th>级别</th><th>标题</th><th>CVE</th><th>资产</th><th>端口</th><th>等级变化</th></tr></thead>
              <tbody>
                <tr v-for="(d, i) in diff.persisted" :key="i">
                  <td><SevTag :sev="d.targetSeverity" /></td>
                  <td class="small">{{ d.title }}</td>
                  <td class="mono small">{{ d.cve || '-' }}</td>
                  <td class="mono small">{{ d.assetIp }}</td>
                  <td class="mono small">{{ d.port || '-' }}</td>
                  <td class="small muted">{{ d.severityChange || '未变化' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <Empty v-else text="没有重复出现的漏洞"></Empty>

          <div class="toolbar" style="margin-top:12px">
            <button class="btn sm" @click="diffPreview" v-if="lastDiffID">查看对比报告</button>
          </div>
        </div>

        <div class="block-title">历史扫描记录</div>
        <div class="table-wrap" v-if="history.length">
          <table class="table">
            <thead><tr><th>任务 ID</th><th>类型</th><th>目标</th><th>状态</th><th>探针节点</th><th>时间</th></tr></thead>
            <tbody>
              <tr v-for="hTask in history" :key="hTask.id">
                <td class="mono small">{{ hTask.id }}</td>
                <td class="small">{{ hTask.type }}</td>
                <td class="mono small">{{ hTask.target }}</td>
                <td class="small">{{ hTask.status }}</td>
                <td class="mono small">{{ hTask.probeNode || 'local' }}</td>
                <td class="muted small mono">{{ fmtDT(hTask.createdAt) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else text="暂无扫描任务记录"></Empty>
      </div>

      <!-- ===== 模板管理 ===== -->
      <div class="card" v-show="tab === 'tpl'">
        <div class="block-title">新建 / 编辑模板</div>
        <div class="form-grid">
          <label>模板名称<input class="input" v-model.trim="tpl.name" placeholder="如: 公司季度报告"></label>
          <label>主题色<input class="input" v-model.trim="tpl.accent" placeholder="#4f46e5"></label>
          <label>副标题<input class="input" v-model.trim="tpl.subtitle" placeholder="XX 公司 内部资料"></label>
        </div>
        <div class="form-grid">
          <label>页眉左<input class="input" v-model.trim="tpl.header.headerLeft" :placeholder="phTitle"></label>
          <label>页眉中<input class="input" v-model.trim="tpl.header.headerCenter"></label>
          <label>页眉右<input class="input" v-model.trim="tpl.header.headerRight" :placeholder="phTime"></label>
        </div>
        <div class="form-grid">
          <label>页脚左<input class="input" v-model.trim="tpl.header.footerLeft"></label>
          <label>页脚中<input class="input" v-model.trim="tpl.header.footerCenter" :placeholder="phOperator"></label>
          <label>页脚右<input class="input" v-model.trim="tpl.header.footerRight"></label>
        </div>
        <div class="form-grid">
          <label class="wide">免责声明<input class="input" v-model.trim="tpl.header.disclaimer"></label>
        </div>
        <p class="muted small">可用占位符: {{ placeholderHint }}</p>
        <div class="toolbar">
          <button class="btn primary" @click="saveTpl">保存模板</button>
          <button class="btn" @click="resetTpl">清空</button>
        </div>

        <div class="block-title">已有模板</div>
        <div class="table-wrap" v-if="templates.length">
          <table class="table">
            <thead><tr><th>名称</th><th>主题色</th><th>页脚</th><th>创建时间</th><th style="width:140px">操作</th></tr></thead>
            <tbody>
              <tr v-for="t in templates" :key="t.id">
                <td>{{ t.name }}</td>
                <td><span class="swatch" :style="{ background: t.accent || '#4f46e5' }"></span><span class="mono small">{{ t.accent || '默认' }}</span></td>
                <td class="small muted">{{ (t.header && t.header.footerCenter) || '-' }}</td>
                <td class="muted small mono">{{ fmtDT(t.createdAt) }}</td>
                <td>
                  <button class="btn xs" @click="editTpl(t)">编辑</button>
                  <button class="btn xs" @click="delTpl(t)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else text="暂无自定义模板(未配置时使用内置模板)"></Empty>

        <div class="block-title">模板包(HTML / Word / PDF 三出口)</div>
        <p class="muted small">
          模板包是 exe 同目录 res/report_templates/&lt;模板名&gt;/ 下的目录: config.yaml(名称/logo/配色/页脚/章节)
          + report.html.tpl + report.docx.tpl。改完重启服务生效, 不需要重新编译。
        </p>
        <div class="table-wrap" v-if="packs.length">
          <table class="table">
            <thead><tr><th>名称</th><th>ID</th><th>出口</th><th>客户</th><th>配色</th><th style="width:180px">操作</th></tr></thead>
            <tbody>
              <tr v-for="p in packs" :key="p.id">
                <td>{{ p.name }}<span class="tag-mini" v-if="p.builtin">内置</span></td>
                <td class="mono small">{{ p.id }}</td>
                <td class="small">
                  <span v-if="p.hasHtml">HTML</span><span v-if="p.hasHtml && p.hasDocx"> / </span>
                  <span v-if="p.hasDocx">Word</span>
                  <span v-if="!p.hasHtml && !p.hasDocx" class="muted">-</span>
                </td>
                <td class="small muted">{{ p.config && p.config.client || '-' }}</td>
                <td><span class="swatch" :style="{ background: (p.config && p.config.accent) || '#4f46e5' }"></span></td>
                <td>
                  <button class="btn xs" @click="downloadPack(p)">下载</button>
                  <button class="btn xs" v-if="!p.builtin && packMgmt" @click="delPack(p)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else text="暂无模板包(使用内置默认模板)"></Empty>

        <div v-if="packMgmt">
          <div class="block-title">新建 / 更新模板包</div>
          <div class="form-grid">
            <label>ID(目录名)<input class="input mono" v-model.trim="packForm.id" placeholder="client-a"></label>
            <label>名称<input class="input" v-model.trim="packForm.name" placeholder="客户 A 报告模板"></label>
            <label>客户名<input class="input" v-model.trim="packForm.client" placeholder="某某科技有限公司"></label>
            <label>主题色<input class="input" v-model.trim="packForm.accent" placeholder="#0f766e"></label>
          </div>
          <div class="form-grid">
            <label class="wide">页脚<input class="input" v-model.trim="packForm.footer" placeholder="报告页脚文案"></label>
            <label>logo(png/jpg/svg)<input type="file" accept=".png,.jpg,.jpeg,.svg" @change="onPackLogo"></label>
            <label>Word 模板(.docx)<input type="file" accept=".docx" @change="onPackDocx"></label>
          </div>
          <label class="wide">HTML 模板(留空则用内置)
            <textarea class="input" rows="6" v-model="packForm.html" :placeholder="phTplVar"></textarea>
          </label>
          <p class="muted small">可用变量: {{ packVarHint }}</p>
          <div class="toolbar">
            <button class="btn primary" @click="savePack" :disabled="packBusy">保存模板包</button>
            <button class="btn" @click="resetPack">清空</button>
          </div>
        </div>
        <p class="muted small" v-else>
          模板管理未启用: 在 settings.json 的 report 节设置 templateManagement=true 后重启即可新建/删除模板包。
        </p>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import SevTag from '../components/SevTag.vue'
import Empty from '../components/Empty.vue'
import Modal from '../components/Modal.vue'
import { v2 } from '../api/http'
import { fmtDT } from '../utils'

const router = useRouter()
const tab = ref('gen')

// 模板管理页签默认隐藏: 进阶功能(自定义报告模板), 主流程"报告生成"里已有模板下拉,
// tab 常驻会干扰; 用户从"高级"开关打开后记忆选择, 下次直接可见。
const tplTabVisible = ref(localStorage.getItem('yugsight_report_tpl_tab') === '1')
function toggleTplTab() {
  tplTabVisible.value = !tplTabVisible.value
  try { localStorage.setItem('yugsight_report_tpl_tab', tplTabVisible.value ? '1' : '0') } catch (e) { /* 忽略 */ }
  if (!tplTabVisible.value && tab.value === 'tpl') tab.value = 'gen'
}
const status = ref(null)
const busy = ref(false)
const diffBusy = ref(false)
const previewURL = ref('')
const lastDiffID = ref('')

const options = ref({ nodes: [{ id: 'local', name: '中心本地' }] })
const templates = ref([])
// 模板包(二期): 目录式模板, 一个模板同时产出 HTML / Word / PDF
const packs = ref([])
const packMgmt = ref(false) // 服务端 report.templateManagement 开关
const packBusy = ref(false)
const packVars = ref([])
const packForm = reactive({ id: '', name: '', client: '', accent: '', footer: '', html: '', docx: '', logoB64: '', logoExt: '' })
const phTplVar = '<h1>{{.Title}}</h1>  {{range .Vulns}}...{{end}}'
const packVarHint = computed(() => {
  if (!packVars.value.length) return '.Title / .Vulns / .Assets / .Stats / .SevRows / .Targets'
  return packVars.value.map(x => x.key + '(' + x.desc + ')').join(' / ')
})
const archives = ref([])
const history = ref([])
const topoNodes = ref([])
const topoStats = ref(null)
const sel = ref(null)

const form = reactive({
  title: '', operator: '', format: 'html', templateId: '', packId: '',
  f: { severity: '', cidr: '', ip: '', cve: '', from: '', to: '', probeNode: '', onlyEvidence: false }
})
const topoFilter = reactive({ severity: '', cidr: '' })
const diffForm = reactive({ from: '', to: '', save: false })
const diff = ref(null)
const tpl = reactive({
  id: '', name: '', accent: '#4f46e5', subtitle: '',
  header: { headerLeft: '', headerCenter: '', headerRight: '', footerLeft: '', footerCenter: '', footerRight: '', disclaimer: '' }
})

// 占位符提示: 后端 /report/templates 返回 [{key, desc}], 这里渲染成
// "{{title}}(报告标题) / {{operator}}(操作者)" 便于用户直接照抄。
// 注意: 这些字符串不能在模板里字面量写, "{{...}}" 会被 Vue 当成插值解析而编译失败。
const placeholders = ref([])
const placeholderHint = computed(() => {
  const list = placeholders.value.length
    ? placeholders.value
    : [{ key: '{{title}}', desc: '报告标题' }, { key: '{{operator}}', desc: '操作者' },
       { key: '{{time}}', desc: '生成时间' }, { key: '{{tool}}', desc: '工具名与版本' }]
  return list.map(x => x.key + '(' + x.desc + ')').join(' / ')
})
const phTitle = '{{title}}'
const phTime = '{{time}}'
const phOperator = '{{operator}}'

function buildFilter() {
  const f = {}
  if (form.f.severity) f.severity = [form.f.severity]
  if (form.f.cidr) f.cidr = form.f.cidr
  if (form.f.ip) f.ip = form.f.ip
  if (form.f.cve) f.cve = form.f.cve
  if (form.f.from) f.from = form.f.from
  if (form.f.to) f.to = form.f.to
  if (form.f.probeNode) f.probeNode = form.f.probeNode
  if (form.f.onlyEvidence) f.onlyWithEvidence = true
  return f
}

function buildRequest() {
  const req = {
    title: form.title, operator: form.operator, format: form.format,
    templateId: form.templateId, filter: buildFilter()
  }
  // 模板包优先(二期主路径): 非空且非内置时后端走 pack 渲染, 否则沿用旧路径
  if (form.packId) req.packId = form.packId
  return req
}

async function loadPacks() {
  try {
    const d = await v2('/report/packs')
    packs.value = (d && d.list) || []
    packMgmt.value = !!(d && d.management)
    packVars.value = (d && d.variables) || []
    // 服务端开启模板管理 -> 页签自动可见(不写 localStorage: 开关是服务端事实)
    if (packMgmt.value) tplTabVisible.value = true
  } catch (e) { /* 列表失败不阻断报告生成 */ }
}

// file -> base64(去掉 data: 前缀, 后端只认裸 base64)
function fileToB64(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader()
    fr.onload = () => {
      const s = String(fr.result || '')
      const i = s.indexOf(',')
      resolve(i >= 0 ? s.slice(i + 1) : s)
    }
    fr.onerror = () => reject(new Error('读取失败'))
    fr.readAsDataURL(file)
  })
}

function onPackLogo(e) {
  const f = e.target.files && e.target.files[0]
  if (!f) return
  fileToB64(f).then(b => {
    packForm.logoB64 = b
    const n = f.name.toLowerCase()
    packForm.logoExt = n.endsWith('.png') ? 'png' : (n.endsWith('.svg') ? 'svg' : 'jpg')
  }).catch(() => {})
}

function onPackDocx(e) {
  const f = e.target.files && e.target.files[0]
  if (!f) return
  fileToB64(f).then(b => { packForm.docx = b }).catch(() => {})
}

async function savePack() {
  if (!packForm.id) { window.alert('请填写模板 ID(目录名)'); return }
  packBusy.value = true
  try {
    await v2('/report/packs', {
      method: 'POST',
      body: JSON.stringify({
        id: packForm.id, name: packForm.name, html: packForm.html,
        docx: packForm.docx, logoB64: packForm.logoB64, logoExt: packForm.logoExt,
        config: { client: packForm.client, accent: packForm.accent, footer: packForm.footer }
      })
    })
    resetPack()
    loadPacks()
  } finally { packBusy.value = false }
}

function resetPack() {
  Object.assign(packForm, { id: '', name: '', client: '', accent: '', footer: '', html: '', docx: '', logoB64: '', logoExt: '' })
}

async function delPack(p) {
  if (!window.confirm('删除模板包 ' + p.name + ' ? 目录将被移除。')) return
  try {
    await v2('/report/packs/' + encodeURIComponent(p.id), { method: 'DELETE' })
    loadPacks()
  } catch (e) { /* 失败提示由 http.js 统一处理 */ }
}

function downloadPack(p) {
  // 同源 cookie 鉴权, 直接跳转即可(拼 URL 不需要 token)
  window.location.href = '/api/v2/report/packs/' + encodeURIComponent(p.id) + '/download?kind=zip'
}

async function loadStatus() {
  try {
    status.value = await v2('/report/status')
    if (status.value && status.value.enabled) {
      loadOptions()
      loadTemplates()
      loadPacks() // 模板包列表(生成页下拉 + 模板管理 tab 共用)
    }
  } catch (e) { status.value = { enabled: false, hint: e.message } }
}

async function loadOptions() {
  try { options.value = await v2('/report/options') } catch (e) { /* 降级: 保留默认节点 */ }
}

async function loadTemplates() {
  try {
    const d = await v2('/report/templates')
    templates.value = (d.list || []).filter(t => !t.builtin)
    if (d.headerPlaceholders && d.headerPlaceholders.length) placeholders.value = d.headerPlaceholders
  } catch (e) { templates.value = [] }
}

async function loadArchives() {
  try {
    const d = await v2('/report/list?size=200')
    archives.value = d.list || []
  } catch (e) { alert(e.message) }
}

async function loadHistory() {
  try {
    const d = await v2('/report/history')
    history.value = d.list || []
  } catch (e) { /* 无任务时静默 */ }
}

async function loadTopo() {
  const p = new URLSearchParams()
  if (topoFilter.severity) p.set('severity', topoFilter.severity)
  if (topoFilter.cidr) p.set('cidr', topoFilter.cidr)
  try {
    const d = await v2('/report/topology?' + p.toString())
    topoNodes.value = (d.topology && d.topology.nodes) || []
    topoStats.value = d.topology ? d.topology.stats : null
  } catch (e) { alert(e.message) }
}

// 预览: POST 返回 HTML, 用 Blob URL 交给 iframe(不能直接把 HTML 塞进 v-html,
// 报告自身带 <style>/<script> 且体积大, iframe 隔离更安全)
async function genPreview() {
  busy.value = true
  try {
    const r = await fetch('/api/v2/report/preview', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildRequest())
    })
    if (!r.ok) throw new Error('HTTP ' + r.status)
    const html = await r.text()
    closePreview()
    previewURL.value = URL.createObjectURL(new Blob([html], { type: 'text/html' }))
  } catch (e) { alert('预览失败: ' + e.message) } finally { busy.value = false }
}

function closePreview() {
  if (previewURL.value) URL.revokeObjectURL(previewURL.value)
  previewURL.value = ''
}

async function genDownload() {
  busy.value = true
  try {
    const d = await v2('/report/generate', { method: 'POST', body: { ...buildRequest(), archive: false } })
    downloadReport(d.report.id)
  } catch (e) { alert('生成失败: ' + e.message) } finally { busy.value = false }
}

async function genArchive() {
  busy.value = true
  try {
    const d = await v2('/report/generate', { method: 'POST', body: { ...buildRequest(), archive: true } })
    alert('报告已生成并归档')
    loadArchives()
    tab.value = 'arch'
    return d
  } catch (e) { alert('生成失败: ' + e.message) } finally { busy.value = false }
}

// 下载走浏览器原生下载(服务端已设置 Content-Disposition)
function downloadReport(id) {
  window.open('/api/v2/report/' + id + '/download', '_blank')
}

function download(a) { downloadReport(a.id) }

async function del(a) {
  if (!confirm('确认删除报告「' + a.title + '」?')) return
  try {
    await v2('/report/' + a.id, { method: 'DELETE' })
    loadArchives()
    if (status.value) status.value.archiveCount = archives.value.length
  } catch (e) { alert(e.message) }
}

async function runDiff() {
  if (!diffForm.from && !diffForm.to) { alert('请至少选择目标轮次的时间范围'); return }
  diffBusy.value = true
  try {
    const d = await v2('/report/compare', {
      method: 'POST',
      body: { from: diffForm.from, to: diffForm.to, save: diffForm.save, title: '扫描对比 ' + (diffForm.from || '') + '~' + (diffForm.to || '') }
    })
    diff.value = d.diff
    lastDiffID.value = d.archiveId || ''
  } catch (e) { alert('对比失败: ' + e.message) } finally { diffBusy.value = false }
}

function diffPreview() {
  if (lastDiffID.value) downloadReport(lastDiffID.value)
}

function onNodeClick(n) { sel.value = n }

function viewVulns(n) {
  sel.value = null
  router.push({ path: '/vulns', query: { ip: n.ip } })
}

function nodeKindName(k) {
  return { asset: '资产', port: '端口', service: '服务' }[k] || k
}

function scoreCls(stats) {
  if (!stats) return ''
  const s = stats.riskScore || 0
  if (s >= 70) return 'bad'
  if (s >= 40) return 'warn'
  return 'ok'
}

async function saveTpl() {
  if (!tpl.name) { alert('请填写模板名称'); return }
  try {
    const body = { name: tpl.name, accent: tpl.accent, subtitle: tpl.subtitle, header: { ...tpl.header } }
    if (tpl.id) body.id = tpl.id
    await v2('/report/templates', { method: 'POST', body })
    resetTpl()
    loadTemplates()
  } catch (e) { alert(e.message) }
}

function editTpl(t) {
  tpl.id = t.id
  tpl.name = t.name || ''
  tpl.accent = t.accent || '#4f46e5'
  tpl.subtitle = t.subtitle || ''
  Object.assign(tpl.header, {
    headerLeft: '', headerCenter: '', headerRight: '',
    footerLeft: '', footerCenter: '', footerRight: '', disclaimer: '',
    ...(t.header || {})
  })
}

function resetTpl() {
  tpl.id = ''
  tpl.name = ''
  tpl.accent = '#4f46e5'
  tpl.subtitle = ''
  Object.assign(tpl.header, {
    headerLeft: '', headerCenter: '', headerRight: '',
    footerLeft: '', footerCenter: '', footerRight: '', disclaimer: ''
  })
}

async function delTpl(t) {
  if (!confirm('确认删除模板「' + t.name + '」?')) return
  try {
    await v2('/report/templates/' + t.id, { method: 'DELETE' })
    loadTemplates()
  } catch (e) { alert(e.message) }
}

// ===== 原始报告(二期) =====
// 数据源: 四大业务模块执行完成后的原始结构化结果(只存不加工, AI 字段预留)。
const rawList = ref([])
const rawTotal = ref(0)
const rawOptions = ref({ modules: [], tags: [], assets: [], dateRange: { from: '', to: '' } })
const rawF = reactive({ module: '', tag: '', asset: '', from: '', to: '', keyword: '' })
const rawSel = ref([])
const rawDetail = ref(null)
const rawBusy = ref(false)
const mergeForm = reactive({ title: '', tags: '' })

// 来源模块展示(与后端 report.RawModules 同口径, 未知模块原样回显)
const RAW_MOD = { capture: '实时抓包', scan: '扫描作业', weakpass: '弱口令', monitor: '节点监控', merged: '合并报告' }
function rawModLabel(m) { return RAW_MOD[m] || m }
function rawModKey(m) { return RAW_MOD[m] ? m : 'other' }

// 关键统计列: 各模块的条目数口径不同, 按模块拼一行
function rawStatsText(r) {
  const s = r.stats || {}
  const ex = s.extra || {}
  switch (r.module) {
    case 'capture': return s.items != null ? s.items + ' 报文' : '-'
    case 'scan': return s.items != null ? s.items + ' 漏洞' + (ex.assets != null ? ' / ' + ex.assets + ' 资产' : '') + (ex.alive != null ? ' / ' + ex.alive + ' 存活' : '') : '-'
    case 'weakpass': return s.items != null ? s.items + ' 目标' + (ex.found != null ? ' / 命中 ' + ex.found : '') : '-'
    case 'monitor': return s.items != null ? s.items + ' 目标' + (ex.online != null ? ' / 在线 ' + ex.online : '') + (ex.ok != null ? ' / 成功 ' + ex.ok : '') : '-'
    case 'merged': return s.items != null ? '合计 ' + s.items + ' 项' : '-'
    default: return '-'
  }
}

async function loadRaw() {
  const p = new URLSearchParams({ page: '1', size: '200' })
  if (rawF.module) p.set('module', rawF.module)
  if (rawF.tag) p.set('tag', rawF.tag)
  if (rawF.asset) p.set('asset', rawF.asset)
  if (rawF.from) p.set('from', rawF.from)
  if (rawF.to) p.set('to', rawF.to)
  if (rawF.keyword) p.set('keyword', rawF.keyword)
  try {
    const d = await v2('/raw/list?' + p.toString())
    rawList.value = (d && d.list) || []
    rawTotal.value = (d && d.total) || 0
    // 筛选变化后清掉已不在列表里的选中项(避免合并到查不到的 ID)
    rawSel.value = rawSel.value.filter(id => rawList.value.some(r => r.id === id))
  } catch (e) {
    rawList.value = []
    rawTotal.value = 0
  }
  loadRawOptions()
}

async function loadRawOptions() {
  try {
    const d = await v2('/raw/options')
    if (d) {
      rawOptions.value = {
        modules: d.modules || [],
        tags: d.tags || [],
        assets: d.assets || [],
        dateRange: d.dateRange || { from: '', to: '' }
      }
    }
  } catch (e) { /* 选项失败不影响列表 */ }
}

function resetRawFilter() {
  Object.assign(rawF, { module: '', tag: '', asset: '', from: '', to: '', keyword: '' })
  loadRaw()
}

function toggleRawSel(id) {
  const i = rawSel.value.indexOf(id)
  if (i >= 0) rawSel.value.splice(i, 1)
  else rawSel.value.push(id)
}
const allRawSelected = computed(() => rawList.value.length > 0 && rawSel.value.length === rawList.value.length)
function toggleAllRaw() {
  rawSel.value = allRawSelected.value ? [] : rawList.value.map(r => r.id)
}

async function viewRaw(r) {
  try {
    rawDetail.value = await v2('/raw/' + r.id)
  } catch (e) { alert(e.message) }
}

async function delRaw(r) {
  if (!confirm('确认删除原始报告「' + r.title + '」?')) return
  try {
    await v2('/raw/' + r.id, { method: 'DELETE' })
    rawSel.value = rawSel.value.filter(id => id !== r.id)
    loadRaw()
  } catch (e) { alert(e.message) }
}

async function mergeRaw() {
  if (rawSel.value.length < 2) { alert('至少选择 2 份原始报告'); return }
  rawBusy.value = true
  try {
    const tags = mergeForm.tags
      ? mergeForm.tags.split(/[,，]/).map(s => s.trim()).filter(Boolean)
      : []
    const d = await v2('/raw/merge', {
      method: 'POST',
      body: { ids: rawSel.value, title: mergeForm.title, tags }
    })
    rawSel.value = []
    mergeForm.title = ''
    mergeForm.tags = ''
    loadRaw()
    if (d && d.id) viewRaw({ id: d.id })
  } catch (e) { alert(e.message) } finally { rawBusy.value = false }
}

// 详情里的原始 JSON: payload 是 JSON 对象, 格式化 + 大正文截断(渲染 200KB 会卡)
function prettyPayload() {
  const d = rawDetail.value
  if (!d || !d.payload) return '(无正文)'
  const p = typeof d.payload === 'string' ? JSON.parse(d.payload) : d.payload
  const s = JSON.stringify(p, null, 2)
  return s.length > 200000 ? s.slice(0, 200000) + '\n... (内容过大, 已截断)' : s
}

function copyPayload() {
  const text = prettyPayload()
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => {})
  }
}

// 详情弹窗的按模块摘要(从 payload 取原始结构, 不做任何加工)
const rawP = computed(() => {
  const d = rawDetail.value
  if (!d || !d.payload) return null
  try {
    return typeof d.payload === 'string' ? JSON.parse(d.payload) : d.payload
  } catch (e) { return null }
})
const rawScanFindings = computed(() => (rawP.value && rawP.value.findings) || [])
const rawWpResults = computed(() => (rawP.value && rawP.value.results) || [])
const rawPkts = computed(() => ((rawP.value && rawP.value.packets) || []).slice(0, 100))
const rawMonTargets = computed(() => (rawP.value && rawP.value.targets) || [])
const rawSections = computed(() => (rawP.value && rawP.value.sections) || [])
const rawMergedFrom = computed(() => (rawP.value && rawP.value.mergedFrom) || [])
// 报告级 AI 元数据(aiData 是后端 json.RawMessage → 前端拿到的是 JSON 串)
const rawAiData = computed(() => {
  const d = rawDetail.value && rawDetail.value.aiData
  if (!d) return {}
  try { return typeof d === 'string' ? JSON.parse(d) : d } catch (e) { return {} }
})

// 默认时间窗: 今天一天(用户最常用"看看今天扫出什么")
function initDates() {
  const d = new Date()
  const iso = (x) => x.toISOString().slice(0, 10)
  diffForm.from = iso(d)
  diffForm.to = iso(d)
  form.f.from = iso(new Date(d.getTime() - 6 * 86400000))
  form.f.to = iso(d)
}

onMounted(() => {
  initDates()
  loadStatus()
})

onBeforeUnmount(closePreview)
</script>

<style scoped>
.tabs { display: flex; gap: 6px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
.tab { background: var(--panel); border: 1px solid var(--line); color: var(--muted);
  padding: 7px 16px; border-radius: 8px; cursor: pointer; font-size: 13px; }
.tab.on { background: var(--accent); border-color: var(--accent); color: #fff; }
.adv-toggle { font-size: 12px; color: var(--muted); text-decoration: none; cursor: pointer; }
.adv-toggle:hover { color: var(--accent); }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 10px 16px; }
.form-grid label { display: flex; flex-direction: column; gap: 4px; font-size: 12.5px; color: var(--muted); }
.form-grid label.wide { grid-column: 1 / -1; }
.form-grid label.chk { flex-direction: row; align-items: center; gap: 6px; padding-top: 20px; }
.block-title { font-size: 13px; font-weight: 600; margin: 18px 0 10px; padding-left: 9px;
  border-left: 3px solid var(--accent); }
.preview-frame { margin-top: 16px; border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.preview-frame iframe { width: 100%; height: 640px; border: 0; background: #fff; }
.empty-hint { padding: 26px; text-align: center; }
.empty-hint b { font-size: 15px; }
.stat-row { display: flex; gap: 10px; flex-wrap: wrap; }
.stat { flex: 1; min-width: 130px; border: 1px solid var(--line); border-radius: 10px;
  padding: 12px; text-align: center; background: var(--panel); }
.stat b { display: block; font-size: 24px; }
.stat span { font-size: 12px; color: var(--muted); }
.stat.new b { color: #ef4444; }
.stat.fixed b { color: #22c55e; }
.stat.keep b { color: #f59e0b; }
.stat.crit b { color: #dc2626; }
.score { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }
.score.bad { background: rgba(239,68,68,.16); color: #f87171; }
.score.warn { background: rgba(245,158,11,.16); color: #fbbf24; }
.score.ok { background: rgba(34,197,94,.16); color: #4ade80; }
.legend { display: flex; gap: 14px; flex-wrap: wrap; margin: 10px 0; font-size: 12px; color: var(--muted); }
.lg { display: inline-flex; align-items: center; gap: 5px; }
.dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
.dot.critical { background: #dc2626; } .dot.high { background: #ef4444; }
.dot.medium { background: #f59e0b; } .dot.low { background: #eab308; }
.dot.none { background: #64748b; } .dot.offline { background: #475569; border: 1px dashed #94a3b8; }
.topo-wrap { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; }
.topo-node { border: 1px solid var(--line); border-left-width: 4px; border-radius: 8px;
  padding: 10px 12px; background: var(--panel); cursor: pointer; transition: transform .12s; }
.topo-node:hover { transform: translateY(-2px); border-color: var(--accent); }
.topo-node.risk-critical { border-left-color: #dc2626; }
.topo-node.risk-high { border-left-color: #ef4444; }
.topo-node.risk-medium { border-left-color: #f59e0b; }
.topo-node.risk-low { border-left-color: #eab308; }
.topo-node.risk-none, .topo-node.risk-info { border-left-color: #64748b; }
.topo-node.dim { opacity: .6; }
.tn-head { display: flex; justify-content: space-between; font-size: 11px; color: var(--muted); }
.tn-label { font-size: 13px; font-weight: 600; margin: 4px 0; word-break: break-all; }
.tn-meta { font-size: 11.5px; color: var(--muted); }
.swatch { display: inline-block; width: 12px; height: 12px; border-radius: 3px; margin-right: 6px; vertical-align: middle; }
/* 模板包表格里的"内置"角标 */
.tag-mini { display: inline-block; margin-left: 6px; padding: 0 6px; border-radius: 8px;
  background: rgba(79, 70, 229, .16); color: #a5b4fc; font-size: 11px; line-height: 16px; }
textarea.input { min-height: 90px; font-family: ui-monospace, Consolas, "Courier New", monospace; font-size: 12px; line-height: 1.5; }
.kv { width: 100%; font-size: 12.5px; }
.kv td { padding: 5px 8px; border-bottom: 1px solid var(--line); }
.kv td:first-child { color: var(--muted); width: 104px; }

/* ===== 原始报告(二期) ===== */
.raw-mergebar {
  display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
  margin: 10px 0; padding: 10px 12px; border: 1px dashed var(--border2);
  border-radius: 8px; background: var(--panel2);
}
.raw-mergebar .input { width: 220px; }
/* 来源模块徽章配色(与 sev-* 同一语义: 一眼区分来源模块) */
.badge.mod-capture { color: #67e8f9; border-color: rgba(103, 232, 249, .5); background: rgba(103, 232, 249, .1); }
.badge.mod-scan { color: #93c5fd; border-color: rgba(147, 197, 253, .5); background: rgba(147, 197, 253, .1); }
.badge.mod-weakpass { color: #fcd34d; border-color: rgba(252, 211, 77, .5); background: rgba(252, 211, 77, .1); }
.badge.mod-monitor { color: #86efac; border-color: rgba(134, 239, 172, .5); background: rgba(134, 239, 172, .1); }
.badge.mod-merged { color: #d8b4fe; border-color: rgba(216, 180, 254, .5); background: rgba(216, 180, 254, .1); }
.badge.mod-other { color: var(--muted); }
.raw-json { margin-top: 12px; }
.raw-json summary { cursor: pointer; color: var(--muted); font-size: 12.5px; user-select: none; }
.raw-json pre {
  margin-top: 8px; padding: 10px; border: 1px solid var(--line); border-radius: 8px;
  background: #0b1020; font-size: 11.5px; line-height: 1.55;
  max-height: 340px; overflow: auto; white-space: pre-wrap; word-break: break-all;
}
/* 阶段 3: AI 分析徽标与研判内容 */
.badge.ai-badge {
  margin-left: 6px; color: #c4b5fd; border: 1px solid rgba(196, 181, 253, .5);
  background: rgba(196, 181, 253, .12); border-radius: 4px; padding: 1px 6px;
  font-size: 10.5px; font-weight: 600;
}
.raw-ai-note {
  margin: 8px 0; padding: 10px 12px; border: 1px solid var(--line); border-radius: 8px;
  background: rgba(196, 181, 253, .05); font-size: 13px; line-height: 1.75;
  white-space: pre-wrap; word-break: break-word; max-height: 420px; overflow: auto;
}
.raw-ai-src { margin-top: 6px; }
.raw-ai-src summary { cursor: pointer; user-select: none; }
</style>

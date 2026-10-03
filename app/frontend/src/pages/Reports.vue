<template>
  <div>
    <PageHeader :title="t('rp.title')" :desc="t('rp.desc')"></PageHeader>

    <!-- 未启用引导 -->
    <div class="card" v-if="status && !status.enabled">
      <div class="empty-hint">
        <b>{{ t('rp.disabled') }}</b>
        <p class="muted small">{{ status.hint || t('rp.disabledHint') }}</p>
        <p class="muted small mono">{{ t('rp.cfgFile') }}: {{ status.configPath }}</p>
      </div>
    </div>

    <template v-else>
      <div class="tabs">
        <button class="tab" :class="{ on: tab === 'gen' }" @click="tab = 'gen'">{{ t('rp.tabGen') }}</button>
        <button class="tab" :class="{ on: tab === 'raw' }" @click="tab = 'raw'; loadRaw()">{{ t('rp.tabRaw') }}</button>
        <button class="tab" :class="{ on: tab === 'arch' }" @click="tab = 'arch'; loadArchives()">{{ t('rp.tabArch') }}</button>
        <button class="tab" :class="{ on: tab === 'diff' }" @click="tab = 'diff'; loadHistory(); loadArchives()">{{ t('rp.tabDiff') }}</button>
        <div class="spacer"></div>
        <span class="muted small" v-if="status && status.rawCount != null">{{ t('rp.rawCount', { n: status.rawCount }) }}</span>
        <span class="muted small" v-if="status && status.archiveCount != null">{{ t('rp.archCount', { n: status.archiveCount }) }}</span>
      </div>
      <!-- 2026-09-25 用户口径调整:
           ① "资产拓扑"不再是独立页签 —— 拓扑只是原始报告内容的列表化, 随原始报告
             详情展示(原始报告页签内的子表);
           ② "模板管理"页签并入"报告生成" —— 生成页本身就是 WPS 式模板编辑器
             (编辑排版 → 保存模板 → 三个按钮出报告), 不再分两个页签。 -->

      <!-- ===== 报告生成(2026-09-25 三轮: 浮窗编辑) =====
           用户口径: 点"编辑/新建"弹出浮窗, 在浮窗里像 Word 一样改
           (标题1/副标题/客户/报告人/检测工具/生成时间/页眉/页脚/免责声明/
           版权信息, 支持字体颜色/底色/加粗等格式, 可删), 浮窗底部保存。
           模板落 data/outp; 下面三个按钮出报告, 模板用于后续报告存档。 -->
      <div class="card" v-show="tab === 'gen'">
        <div class="block-title">{{ t('rp.tplBlock') }}</div>
        <p class="muted small" style="margin:0 0 10px">{{ t('rp.tplHint') }}</p>
        <div class="toolbar" style="margin-bottom:8px">
          <button class="btn primary" @click="openTplModal('')">{{ t('rp.newTpl') }}</button>
          <span class="muted small" v-if="tplSavedMsg" style="color:var(--ok,#16a34a)">{{ tplSavedMsg }}</span>
        </div>
        <div class="table-wrap" v-if="wordTpls.length">
          <table class="table">
            <thead><tr><th>{{ t('rp.colName') }}</th><th>{{ t('rp.colType') }}</th><th>{{ t('rp.colUpdated') }}</th><th style="width:200px">{{ t('rp.colOp') }}</th></tr></thead>
            <tbody>
              <tr v-for="wp in wordTpls" :key="wp.name">
                <td class="small">{{ wp.name }}<span class="tag-mini" v-if="wp.logo">logo</span></td>
                <td class="small muted">{{ (wp.builtin || wp.name === 'default') ? t('rp.tplBuiltin') : (wp.visual ? t('rp.tplVisual') : t('rp.tplWord')) }}</td>
                <td class="muted small mono">{{ wp.updated || '-' }}</td>
                <td>
                  <button class="btn xs" :disabled="wp.name === 'default'" :title="wp.name === 'default' ? t('rp.builtinNoEdit') : ''" @click="openTplModal(wp.name)">{{ t('rp.edit') }}</button>
                  <button class="btn xs" @click="previewWordTpl(wp.name)">{{ t('rp.preview') }}</button>
                  <button class="btn xs" v-if="!wp.builtin" :disabled="wp.name === 'default'" :title="wp.name === 'default' ? t('rp.builtinNoDel') : ''" @click="delWordTpl(wp)">{{ t('rp.del') }}</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="muted small" v-else style="margin:6px 0 0">{{ t('rp.noTpl') }}</p>

        <div class="block-title">{{ t('rp.genBlock') }}</div>
        <!-- 2026-09-26: 生成报告只突出三项(选模板 + 选任务 + 选格式), 7 个漏洞
             范围筛选项收进下方默认收起的"高级筛选"。任务可多选(取并集)。 -->
        <div class="form-grid" style="margin-bottom:12px">
          <label>{{ t('rp.tplLabel') }}
            <select class="select" v-model="form.f.template">
              <option value="builtin">{{ t('rp.builtinLayout') }}</option>
              <option v-for="gp in genTplOptions" :key="gp.name" :value="gp.name">{{ gp.name }}</option>
            </select>
          </label>
          <label>{{ t('rp.jobLabel') }}
            <select class="select" v-model="jobPicker" @change="addJob()">
              <option value="" disabled>{{ t('rp.jobPh') }}</option>
              <option v-for="j in jobList" :key="j.id" :value="j.id">{{ j.name }} · {{ j.target }}</option>
            </select>
            <div class="job-chips" v-if="form.f.jobIds.length">
              <span class="chip" v-for="id in form.f.jobIds" :key="id">
                {{ jobNameOfId(id) }}
                <a class="chip-x" href="javascript:void(0)" @click="removeJob(id)">×</a>
              </span>
            </div>
            <div class="muted small" v-else>{{ t('rp.jobEmpty') }}</div>
          </label>
          <label>{{ t('rp.fmtLabel') }}
            <select class="select" v-model="form.f.format">
              <option value="word">Word (.docx)</option>
              <option value="html">{{ t('rp.fmtHtml') }}</option>
              <option value="pdf">{{ t('rp.fmtPdf') }}</option>
            </select>
          </label>
        </div>

        <details class="gen-filter">
          <summary>{{ t('rp.advFilter') }}</summary>
          <div class="form-grid">
            <label>{{ t('rp.sevLabel') }}
              <!-- 2026-10-02 用户口径: 风险等级选项 = 漏洞库中真实存在的等级
                   (后端 /report/options 按存量聚合; 之前固定 5 级全量) -->
              <select class="select" v-model="form.f.severity">
                <option value="">{{ t('rp.allSev') }}</option>
                <option v-for="s in options.severities" :key="s" :value="s">{{ t('sev.' + s) }}</option>
              </select>
            </label>
            <label>{{ t('rp.cidr') }}<input class="input mono" v-model.trim="form.f.cidr" placeholder="192.168.1.0/24"></label>
            <label>{{ t('rp.assetIp') }}<input class="input mono" v-model.trim="form.f.ip" :placeholder="t('rp.exact')"></label>
            <label>CVE<input class="input mono" v-model.trim="form.f.cve" :placeholder="t('rp.cvePh')"></label>
            <label>{{ t('rp.from') }}<input class="input" type="date" v-model="form.f.from"></label>
            <label>{{ t('rp.to') }}<input class="input" type="date" v-model="form.f.to"></label>
            <label>{{ t('rp.probeNode') }}
              <select class="select" v-model="form.f.probeNode">
                <option value="">{{ t('rp.allNodes') }}</option>
                <option v-for="n in options.nodes" :key="n.id" :value="n.id">{{ n.name }}</option>
              </select>
            </label>
            <label class="chk"><input type="checkbox" v-model="form.f.onlyEvidence"> {{ t('rp.onlyEvidence') }}</label>
          </div>
        </details>

        <div class="toolbar" style="margin-top:14px">
          <!-- 选了任务时高亮提示: 报告只含所选任务并集数据, 标题默认取任务名 -->
          <span class="chip blue" v-if="jobNameOf" :title="t('rp.jobScopeTitle', { name: jobNameOf })">
            {{ t('rp.genByJob') }}: {{ jobNameOf }}
          </span>
          <div class="spacer"></div>
          <!-- 预览=HTML 抽屉内查看(可打印成 PDF); 下载/存档=所选格式(按所选模板版式) -->
          <button class="btn" @click="genPreview" :disabled="busy || !form.f.jobIds.length">{{ t('rp.previewReport') }}</button>
          <button class="btn primary" @click="genDownload" :disabled="busy || !form.f.jobIds.length">{{ t('rp.genDownload') }}</button>
          <button class="btn" @click="genArchive" :disabled="busy || !form.f.jobIds.length">{{ t('rp.genArchive') }}</button>
          <span class="muted small" v-if="busy">{{ t('rp.processing') }}</span>
        </div>
      </div>

      <!-- ===== 原始报告(二期: 业务模块执行后的原始结构化结果) ===== -->
      <div class="card" v-show="tab === 'raw'">
        <p class="muted small" style="margin:0 0 10px">{{ t('rp.rawHint') }}</p>
        <div class="toolbar">
          <!-- 按扫描作业(任务名)分类: 选某任务名只看该作业的原始报告(用户要求"按任务名分类进子表") -->
          <select class="select" v-model="rawF.job" @change="loadRaw()">
            <option value="">{{ t('rp.allJobs') }}</option>
            <option v-for="j in rawOptions.jobs" :key="j" :value="j">{{ j }}</option>
          </select>
          <select class="select" v-model="rawF.module" @change="loadRaw()">
            <option value="">{{ t('rp.allSrc') }}</option>
            <option v-for="m in rawOptions.modules" :key="m.id" :value="m.id">{{ m.label }} ({{ m.count }})</option>
          </select>
          <select class="select" v-model="rawF.tag" @change="loadRaw()">
            <option value="">{{ t('rp.allTags') }}</option>
            <option v-for="tg in rawOptions.tags" :key="tg" :value="tg">{{ tg }}</option>
          </select>
          <input class="input mono" v-model.trim="rawF.asset" :placeholder="t('rp.assetPh')" @keyup.enter="loadRaw()">
          <input class="input" type="date" v-model="rawF.from" :title="t('rp.dateFrom')">
          <span class="muted">~</span>
          <input class="input" type="date" v-model="rawF.to" :title="t('rp.dateTo')">
          <input class="input" v-model.trim="rawF.keyword" :placeholder="t('rp.kwPh')" @keyup.enter="loadRaw()">
          <button class="btn sm" @click="loadRaw()">{{ t('rp.query') }}</button>
          <button class="btn xs" @click="resetRawFilter">{{ t('rp.reset') }}</button>
          <div class="spacer"></div>
          <span class="muted small">{{ t('rp.totalN', { n: rawTotal }) }}</span>
        </div>

        <!-- 合并栏: 选中 >=1 份时出现 -->
        <div class="raw-mergebar" v-if="rawSel.length">
          <span>{{ t('rp.selectedN', { n: rawSel.length }) }}</span>
          <input class="input" v-model.trim="mergeForm.title" :placeholder="t('rp.mergeTitlePh')">
          <input class="input" v-model.trim="mergeForm.tags" :placeholder="t('rp.tagsPh')">
          <button class="btn primary sm" @click="mergeRaw" :disabled="rawBusy || rawSel.length < 2">
            {{ rawBusy ? t('rp.merging') : t('rp.mergeBtn') }}
          </button>
          <!-- 2026-09-26: 删除选中(批量, 走 /raw/batch-delete) -->
          <button class="btn danger sm" @click="rawBatchDel" :disabled="rawBusy || !rawSel.length">{{ t('rp.delSel') }}</button>
          <button class="btn xs" @click="rawSel = []">{{ t('rp.clearSel') }}</button>
          <span class="muted small" v-if="rawSel.length === 1">{{ t('rp.need2Merge') }}</span>
        </div>

        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th style="width:30px"><input type="checkbox" :checked="allRawSelected" @change="toggleAllRaw"></th>
                <th>{{ t('rp.colReport') }}</th>
                <th>{{ t('rp.colModule') }}</th>
                <th>{{ t('rp.colJob') }}</th>
                <th>{{ t('rp.colSource') }}</th>
                <th>{{ t('rp.colAsset') }}</th>
                <th>{{ t('rp.colStats') }}</th>
                <th>{{ t('rp.colTag') }}</th>
                <th>{{ t('rp.colCreatedAt') }}</th>
                <th style="width:110px">{{ t('rp.colOp') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in rawList" :key="r.id">
                <td><input type="checkbox" :checked="rawSel.includes(r.id)" @change="toggleRawSel(r.id)"></td>
                <td>
                  <b class="small">{{ r.title }}</b>
                  <span class="badge ai-badge" v-if="r.aiAnalyzedAt" :title="t('rp.aiAt', { at: fmtDT(r.aiAnalyzedAt) })">AI</span>
                  <div class="muted small" v-if="r.summary">{{ r.summary }}</div>
                </td>
                <td><span class="badge" :class="'mod-' + rawModKey(r.module)">{{ rawModLabel(r.module) }}</span></td>
                <td class="small" :title="r.job || t('rp.standalone')">
                  <template v-if="r.job">{{ r.job }}</template>
                  <span v-else class="muted">-</span>
                </td>
                <td class="mono small">{{ r.source || '-' }}<template v-if="r.operator"> / {{ r.operator }}</template></td>
                <td class="mono small">
                  <template v-if="r.assets && r.assets.length">
                    {{ r.assets.slice(0, 3).join(', ') }}<span v-if="r.assets.length > 3"> …{{ t('rp.assetsMore', { n: r.assets.length }) }}</span>
                  </template>
                  <span v-else class="muted">-</span>
                </td>
                <td class="mono small">{{ rawStatsText(r) }}</td>
                <td><span class="tag-mini" v-for="tg in (r.tags || [])" :key="tg">{{ tg }}</span></td>
                <td class="muted small mono">{{ fmtDT(r.createdAt) }}</td>
                <td>
                  <button class="btn xs" @click="viewRaw(r)">{{ t('rp.view') }}</button>
                  <button class="btn xs" @click="delRaw(r)">{{ t('rp.del') }}</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-if="!rawList.length" :text="t('rp.noRaw')"></Empty>

        <!-- 原始报告详情 -->
        <Modal v-if="rawDetail" :title="rawDetail.title" @close="rawDetail = null">
          <table class="kv">
            <tr><td>{{ t('rp.colModule') }}</td><td><span class="badge" :class="'mod-' + rawModKey(rawDetail.module)">{{ rawModLabel(rawDetail.module) }}</span></td></tr>
            <tr><td>{{ t('rp.colSource') }}</td><td class="mono">{{ rawDetail.source || '-' }}<template v-if="rawDetail.operator"> / {{ rawDetail.operator }}</template></td></tr>
            <tr v-if="rawDetail.target"><td>{{ t('rp.colTarget') }}</td><td class="mono">{{ rawDetail.target }}</td></tr>
            <tr v-if="rawDetail.assets && rawDetail.assets.length"><td>{{ t('rp.assetsInvolved') }}</td><td class="mono small">{{ rawDetail.assets.join(', ') }}</td></tr>
            <tr v-if="rawDetail.tags && rawDetail.tags.length"><td>{{ t('rp.colTag') }}</td><td><span class="tag-mini" v-for="tg in rawDetail.tags" :key="tg">{{ tg }}</span></td></tr>
            <tr v-if="rawDetail.durationMs"><td>{{ t('rp.duration') }}</td><td class="mono">{{ (rawDetail.durationMs / 1000).toFixed(1) }} s</td></tr>
            <tr><td>{{ t('rp.colCreatedAt') }}</td><td class="mono">{{ fmtDT(rawDetail.createdAt) }}</td></tr>
          </table>
          <p class="muted small" v-if="rawDetail.summary" style="margin:8px 0 0">{{ rawDetail.summary }}</p>

          <!-- 按模块的摘要视图(只读原始结构化数据, 不做加工) -->
          <template v-if="rawDetail.module === 'scan' && rawScanFindings.length">
            <div class="block-title">{{ t('rp.findings', { n: rawScanFindings.length }) }}</div>
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>{{ t('rp.colLevel') }}</th><th>{{ t('rp.colTitle') }}</th><th>CVE</th><th>{{ t('rp.colAsset') }}</th><th>{{ t('rp.colPort') }}</th></tr></thead>
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
            <div class="block-title">{{ t('rp.wpResults', { n: rawWpResults.length }) }}</div>
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>{{ t('rp.colTarget') }}</th><th>{{ t('rp.colService') }}</th><th>{{ t('rp.colResult') }}</th><th>{{ t('rp.hitPass') }}</th><th>{{ t('rp.colNote') }}</th></tr></thead>
                <tbody>
                  <tr v-for="(r, i) in rawWpResults" :key="i">
                    <td class="mono small">{{ r.host }}:{{ r.port }}</td>
                    <td class="mono small">{{ r.service }}</td>
                    <td>
                      <span class="badge" :class="r.ok ? 'mod-weakpass' : 'mod-other'">{{ r.ok ? t('rp.hit') : t('rp.miss') }}</span>
                      <span class="muted small" v-if="r.emptyPass && r.ok">{{ t('rp.emptyPass') }}</span>
                    </td>
                    <td class="mono small">{{ r.password || '-' }}</td>
                    <td class="small muted">{{ r.stopped || r.error || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>

          <template v-if="rawDetail.module === 'capture' && rawPkts.length">
            <div class="block-title">{{ t('rp.pkts', { n: rawDetail.payload && rawDetail.payload.packets ? rawDetail.payload.packets.length : 0, m: rawPkts.length }) }}</div>
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>{{ t('rp.colTime') }}</th><th>{{ t('rp.colProto') }}</th><th>{{ t('rp.colSrc') }}</th><th>{{ t('rp.colDst') }}</th><th>{{ t('rp.colLen') }}</th><th>{{ t('rp.colSummary') }}</th></tr></thead>
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
            <div class="block-title">{{ t('rp.monTargets', { n: rawMonTargets.length }) }}</div>
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>{{ t('rp.colName') }}</th><th>{{ t('rp.colAddr') }}</th><th>{{ t('rp.colVer') }}</th><th>{{ t('rp.colStatus') }}</th><th>{{ t('rp.uptime') }}</th><th>CPU</th><th>{{ t('rp.colMem') }}</th><th>{{ t('rp.ifCount') }}</th></tr></thead>
                <tbody>
                  <tr v-for="mt in rawMonTargets" :key="mt.id">
                    <td class="small">{{ mt.name || mt.id }}</td>
                    <td class="mono small">{{ mt.addr }}</td>
                    <td class="mono small">{{ mt.version }}</td>
                    <td>
                      <span v-if="mt.sample" class="badge" :class="mt.sample.ok ? 'mod-scan' : 'mod-other'">{{ mt.sample.ok ? t('rp.online') : t('rp.offline') }}</span>
                      <span v-else class="muted small">{{ t('rp.notCollected') }}</span>
                    </td>
                    <td class="mono small">{{ mt.sample && mt.sample.uptimeSec ? (mt.sample.uptimeSec / 3600).toFixed(1) + ' h' : '-' }}</td>
                    <td class="mono small">{{ mt.sample && mt.sample.cpuLoad ? mt.sample.cpuLoad + '%' : '-' }}</td>
                    <td class="mono small">{{ mt.sample && mt.sample.memTotal ? (mt.sample.memUsed / 1048576).toFixed(0) + '/' + (mt.sample.memTotal / 1048576).toFixed(0) + ' MB' : '-' }}</td>
                    <td class="mono small">{{ mt.sample && mt.sample.ifNumber || '-' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>

          <template v-if="rawDetail.module === 'merged' && rawSections.length">
            <div class="block-title">{{ t('rp.sections') }}</div>
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>{{ t('rp.colModule') }}</th><th>{{ t('rp.reportCount') }}</th></tr></thead>
                <tbody>
                  <tr v-for="s in rawSections" :key="s.module">
                    <td><span class="badge" :class="'mod-' + rawModKey(s.module)">{{ rawModLabel(s.module) }}</span></td>
                    <td class="mono small">{{ s.count }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="block-title" v-if="rawMergedFrom.length">{{ t('rp.srcReports', { n: rawMergedFrom.length }) }}</div>
            <div class="table-wrap" v-if="rawMergedFrom.length">
              <table class="table">
                <thead><tr><th>ID</th><th>{{ t('rp.colTitle') }}</th><th>{{ t('rp.colSource') }}</th><th>{{ t('rp.colTime') }}</th><th>AI</th></tr></thead>
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
              <summary class="muted small">{{ t('rp.viewAi', { title: m.title }) }}</summary>
              <pre class="raw-ai-note">{{ m.ai.aiNote }}</pre>
            </details>
          </template>

          <!-- 资产拓扑(2026-09-25 用户口径: 拓扑就是原始报告里资产信息的列表化,
               只做子表, 不做独立页签/画布): 资产 -> 开放端口 -> 关联漏洞数 -->
          <template v-if="rawTopo.length">
            <div class="block-title">{{ t('rp.topoList', { n: rawTopo.length }) }}</div>
            <div class="table-wrap">
              <table class="table">
                <thead><tr><th>{{ t('rp.colAsset') }}</th><th>{{ t('rp.hostname') }}</th><th>{{ t('rp.osCol') }}</th><th>{{ t('rp.openPorts') }}</th><th>{{ t('rp.relatedVulns') }}</th></tr></thead>
                <tbody>
                  <tr v-for="tp in rawTopo" :key="tp.ip">
                    <td class="mono small">{{ tp.ip }}</td>
                    <td class="small">{{ tp.hostname || '-' }}</td>
                    <td class="small">{{ tp.os || '-' }}</td>
                    <td class="mono small">
                      <template v-if="tp.ports && tp.ports.length">
                        <span class="tag-mini" v-for="p in tp.ports" :key="p">{{ p }}</span>
                      </template>
                      <span v-else class="muted">-</span>
                    </td>
                    <td class="mono small">
                      <span v-if="tp.vulns > 0" class="score warn">{{ tp.vulns }}</span>
                      <span v-else class="muted">0</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>

          <!-- AI 分析(阶段 3): 业务页触发的研判结果挂在本报告下; 也可在此直接(重新)分析 -->
          <div class="block-title" style="display:flex; align-items:center; justify-content:space-between; gap:12px">
            <span>{{ t('rp.aiTitle') }}</span>
            <AiAnalyzeButton :module="rawDetail.module" :reportId="rawDetail.id"
                             :label="rawDetail.aiAnalyzedAt ? t('rp.reanalyze') : t('rp.analyze')" />
          </div>
          <p class="muted small" v-if="!rawDetail.aiAnalyzedAt">{{ t('rp.aiHint') }}</p>
          <div v-else>
            <p class="muted small mono">
              {{ t('rp.aiTime') }}: {{ fmtDT(rawDetail.aiAnalyzedAt) }}
              <template v-if="rawAiData.model"> · {{ t('rp.aiModel') }}: {{ rawAiData.model }}</template>
              <template v-if="rawAiData.template"> · {{ rawAiData.template }}</template>
              <template v-if="rawAiData.ragHits"> · {{ t('rp.ragHits', { n: rawAiData.ragHits }) }}</template>
              <template v-if="rawAiData.memoryItems"> · {{ t('rp.memItems', { n: rawAiData.memoryItems }) }}</template>
              <template v-if="rawAiData.elapsedMs"> · {{ t('rp.aiElapsed') }} {{ (rawAiData.elapsedMs / 1000).toFixed(1) }}s</template>
            </p>
            <pre class="raw-ai-note">{{ rawDetail.aiNote }}</pre>
          </div>

          <!-- 原始 JSON(可折叠, 大正文截断展示) -->
          <details class="raw-json">
            <summary>{{ t('rp.rawJson') }}</summary>
            <pre class="mono small">{{ prettyPayload() }}</pre>
          </details>
          <template #footer>
            <button class="btn sm" @click="copyPayload">{{ t('rp.copyJson') }}</button>
            <button class="btn sm" @click="rawDetail = null">{{ t('rp.close') }}</button>
          </template>
        </Modal>
      </div>

      <!-- ===== 报告存档 ===== -->
      <div class="card" v-show="tab === 'arch'">
        <div class="toolbar">
          <button class="btn sm" @click="loadArchives">{{ t('rp.refresh') }}</button>
          <div class="spacer"></div>
          <span class="muted small">{{ t('rp.totalN', { n: archives.length }) }}</span>
        </div>
        <div class="table-wrap" v-if="archives.length">
          <table class="table">
            <thead>
              <tr><th>{{ t('rp.colTitle') }}</th><th>{{ t('rp.colFormat') }}</th><th>{{ t('rp.colVulns') }}</th><th>{{ t('rp.colAsset') }}</th><th>{{ t('rp.riskScore') }}</th><th>{{ t('rp.operator') }}</th><th>{{ t('rp.colCreatedAt') }}</th><th style="width:150px">{{ t('rp.colOp') }}</th></tr>
            </thead>
            <tbody>
              <tr v-for="a in archives" :key="a.id">
                <td>
                  <b style="font-size:12.5px">{{ a.title }}</b>
                  <span class="badge" v-if="a.kind === 'diff'" style="margin-left:6px">{{ t('rp.diffBadge') }}</span>
                </td>
                <td class="mono small">{{ (a.format || 'html').toUpperCase() }}</td>
                <td class="mono small">{{ a.stats ? a.stats.vulnTotal : '-' }}</td>
                <td class="mono small">{{ a.stats ? a.stats.assetTotal : '-' }}</td>
                <td><span class="score" :class="scoreCls(a.stats)">{{ a.stats ? a.stats.riskScore : '-' }}</span></td>
                <td class="small muted">{{ a.operator || '-' }}</td>
                <td class="muted small mono">{{ fmtDT(a.createdAt) }}</td>
                <td>
                  <button class="btn xs" @click="previewArchive(a)">{{ t('rp.preview') }}</button>
                  <button class="btn xs" @click="download(a)">{{ t('rp.download') }}</button>
                  <button class="btn xs" @click="del(a)">{{ t('rp.del') }}</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="t('rp.noArch')"></Empty>
        <!-- 预览统一走右侧抽屉(2026-09-25 二轮: "像抽屉一样打开页面看"):
             Word 存档由服务端转 HTML(X-Yugsight-Preview: word-html), 所有格式
             都能在抽屉 iframe 里直接看, 不再"必须下载"。 -->
      </div>

      <!-- ===== 历史对比 ===== -->
      <div class="card" v-show="tab === 'diff'">
        <div class="block-title">{{ t('rp.diffBlock') }}</div>
        <!-- 2026-09-26: 历史对比主入口 = 选两份报告存档对比(按各自筛选条件重建
             漏洞明细), 而非无根据的时间窗; 时间窗对比降为下方备选。 -->
        <div class="form-grid" style="margin-bottom:10px">
          <label>{{ t('rp.baseArch') }}
            <select class="select" v-model="diffForm.baseId">
              <option value="">{{ t('rp.select') }}</option>
              <option v-for="a in archives" :key="a.id" :value="a.id">{{ a.title }} · {{ fmtDT(a.createdAt) }}</option>
            </select>
          </label>
          <label>{{ t('rp.targetArch') }}
            <select class="select" v-model="diffForm.targetId">
              <option value="">{{ t('rp.select') }}</option>
              <option v-for="a in archives" :key="a.id" :value="a.id">{{ a.title }} · {{ fmtDT(a.createdAt) }}</option>
            </select>
          </label>
        </div>
        <div class="toolbar">
          <button class="btn primary sm" @click="runDiff" :disabled="diffBusy">{{ t('rp.runDiff') }}</button>
          <span class="muted small" v-if="diffBusy">{{ t('rp.diffing') }}</span>
          <div class="spacer"></div>
          <label class="chk small"><input type="checkbox" v-model="diffForm.save"> {{ t('rp.saveDiff') }}</label>
        </div>
        <p class="muted small" style="margin:6px 0 0">{{ t('rp.diffHint') }}</p>
        <details class="gen-filter" style="margin-top:10px">
          <summary>{{ t('rp.winDiffSummary') }}</summary>
          <div class="toolbar">
            <span class="small muted">{{ t('rp.winLabel') }}</span>
            <input class="input" type="date" v-model="diffForm.from">
            <span class="muted">~</span>
            <input class="input" type="date" v-model="diffForm.to">
            <button class="btn sm" @click="runWindowDiff" :disabled="diffBusy">{{ t('rp.runWinDiff') }}</button>
          </div>
          <p class="muted small" style="margin:6px 0 0">{{ t('rp.winHint') }}</p>
        </details>

        <div v-if="diff">
          <div class="block-title">{{ t('rp.diffOverview') }}</div>
          <div class="stat-row">
            <div class="stat new"><b>{{ diff.stats.newCount }}</b><span>{{ t('rp.newVulnsShort') }}</span></div>
            <div class="stat fixed"><b>{{ diff.stats.fixedCount }}</b><span>{{ t('rp.fixedShort') }}</span></div>
            <div class="stat keep"><b>{{ diff.stats.persistedCount }}</b><span>{{ t('rp.persistShort') }}</span></div>
            <div class="stat delta"><b>{{ diff.stats.delta }}</b><span>{{ t('rp.deltaShort') }}</span></div>
            <div class="stat crit"><b>{{ diff.stats.newCritical }}</b><span>{{ t('rp.newCritShort') }}</span></div>
          </div>

          <div class="block-title">{{ t('rp.newVulns', { n: diff.stats.newCount }) }}</div>
          <div class="table-wrap" v-if="diff.new && diff.new.length">
            <table class="table">
              <thead><tr><th>{{ t('rp.colLevel') }}</th><th>{{ t('rp.colTitle') }}</th><th>CVE</th><th>{{ t('rp.colAsset') }}</th><th>{{ t('rp.colPort') }}</th></tr></thead>
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
          <Empty v-else :text="t('rp.noNew')"></Empty>

          <div class="block-title">{{ t('rp.fixedVulns', { n: diff.stats.fixedCount }) }}</div>
          <div class="table-wrap" v-if="diff.fixed && diff.fixed.length">
          <table class="table">
            <thead><tr><th>{{ t('rp.colLvOrig') }}</th><th>{{ t('rp.colTitle') }}</th><th>CVE</th><th>{{ t('rp.colAsset') }}</th><th>{{ t('rp.colPort') }}</th></tr></thead>
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
          <Empty v-else :text="t('rp.noFixed')"></Empty>

          <div class="block-title">{{ t('rp.persistVulns', { n: diff.stats.persistedCount }) }}</div>
          <div class="table-wrap" v-if="diff.persisted && diff.persisted.length">
            <table class="table">
              <thead><tr><th>{{ t('rp.colLevel') }}</th><th>{{ t('rp.colTitle') }}</th><th>CVE</th><th>{{ t('rp.colAsset') }}</th><th>{{ t('rp.colPort') }}</th><th>{{ t('rp.sevChange') }}</th></tr></thead>
              <tbody>
                <tr v-for="(d, i) in diff.persisted" :key="i">
                  <td><SevTag :sev="d.targetSeverity" /></td>
                  <td class="small">{{ d.title }}</td>
                  <td class="mono small">{{ d.cve || '-' }}</td>
                  <td class="mono small">{{ d.assetIp }}</td>
                  <td class="mono small">{{ d.port || '-' }}</td>
                  <td class="small muted">{{ d.severityChange || t('rp.unchanged') }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <Empty v-else :text="t('rp.noPersist')"></Empty>

          <div class="toolbar" style="margin-top:12px">
            <button class="btn sm" @click="diffPreview" v-if="lastDiffID">{{ t('rp.viewDiff') }}</button>
          </div>
        </div>

        <div class="block-title">{{ t('rp.historyBlock') }}</div>
        <div class="table-wrap" v-if="history.length">
          <table class="table">
            <thead><tr><th>{{ t('rp.colTaskId') }}</th><th>{{ t('rp.colType') }}</th><th>{{ t('rp.colTarget') }}</th><th>{{ t('rp.colStatus') }}</th><th>{{ t('rp.probeNode') }}</th><th>{{ t('rp.colTime') }}</th></tr></thead>
            <tbody>
              <tr v-for="hTask in history" :key="hTask.id">
                <td class="mono small">{{ hTask.id }}</td>
                <td class="small">{{ hTask.type }}</td>
                <td class="mono small">{{ hTask.target }}</td>
                <td class="small">{{ hTask.status }}</td>
                <td class="mono small">{{ hTask.probeNode || t('rp.localNode') }}</td>
                <td class="muted small mono">{{ fmtDT(hTask.createdAt) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <Empty v-else :text="t('rp.noHistory')"></Empty>
      </div>

    </template>

    <!-- 报告预览抽屉(2026-09-25 二轮: "像抽屉一样打开页面看"):
         右侧全高抽屉 + iframe, "报告生成-预览"与"报告存档-预览"共用。
         存档预览直连 /preview 接口(Word 由服务端转 HTML); 生成预览是
         POST 回来的 HTML blob。Esc / 点遮罩关闭。 -->
    <div class="drawer-mask" v-if="drawer.url" @click.self="closeDrawer">
      <div class="drawer">
        <div class="drawer-head">
          <b class="drawer-title">{{ drawer.title || t('rp.previewTitle') }}</b>
          <div class="spacer"></div>
          <button class="btn xs" v-if="drawer.download" @click="window.open(drawer.download, '_blank')">{{ t('rp.downloadOrig') }}</button>
          <button class="btn xs" @click="closeDrawer">{{ t('rp.closeEsc') }}</button>
        </div>
        <div class="drawer-body">
          <iframe :src="drawer.url" :title="t('rp.previewTitle')"></iframe>
        </div>
      </div>
    </div>

    <!-- 模板编辑浮窗(2026-09-25 三轮: "点击编辑时是浮窗并有保存功能";
         2026-09-26 四轮改版: 不再是"左侧一堆输入框 + 右侧只读预览", 而是
         顶部工具条 + 右侧 A4 版面就地编辑(Editable 块), 左侧只留模板属性与
         章节结构; 底部 保存/取消。Esc 关闭。 -->
    <div class="tpl-mask" v-if="tplModal" @click.self="closeTplModal">
      <div class="tpl-modal" @click="closePops">
        <div class="tpl-head">
          <b>{{ t('rp.editTpl') }}</b>
          <label class="head-field">{{ t('rp.name') }}
            <input class="input xs" v-model.trim="vis.name" :placeholder="t('rp.namePh')">
          </label>
          <!-- 主题色: 顶栏只放一个色块入口, 点开才是色板(2026-09-26 深色化: 少控件、少亮色块) -->
          <div class="head-accent">
            <button class="accent-btn" type="button" :style="{ background: vis.accent }"
                    :title="t('rp.accentTitle')" @click.stop="accentOpen = !accentOpen"></button>
            <div class="pop" v-if="accentOpen" @click.stop>
              <div class="pop-title">{{ t('rp.accent') }}</div>
              <div class="swatches">
                <button v-for="c in ACCENTS" :key="c.hex" type="button" class="sw"
                        :class="{ on: vis.accent.toLowerCase() === c.hex.toLowerCase() }"
                        :style="{ background: c.hex }" :title="t(c.name)"
                        @click="vis.accent = c.hex; accentOpen = false"></button>
              </div>
              <label class="pop-custom">{{ t('rp.custom') }}
                <input type="color" v-model="vis.accent">
                <span class="mono small muted">{{ vis.accent }}</span>
              </label>
            </div>
          </div>
          <label class="chk"><input type="checkbox" v-model="vis.cover"> {{ t('rp.cover') }}</label>
          <button class="btn xs" @click="pickLogo">{{ visLogo ? t('rp.logoChange') : t('rp.logoUpload') }}</button>
          <button class="btn xs" v-if="visLogo" @click="delLogo">{{ t('rp.logoRemove') }}</button>
          <input type="file" ref="logoInput" accept="image/png,image/jpeg,image/gif"
                 style="display:none" @change="onLogoFile">
          <div class="spacer"></div>
          <span class="muted small" v-if="visBusy">{{ t('rp.saving') }}</span>
          <button class="btn xs" @click="resetVis">{{ t('rp.reset') }}</button>
          <button class="btn xs" @click="closeTplModal">{{ t('rp.cancel') }}</button>
          <button class="btn xs primary" @click="saveVisualTpl" :disabled="visBusy">{{ t('rp.save') }}</button>
        </div>
        <!-- 2026-09-26 用户: 字符格式工具条(样式/BIU/字色/底色/字号/清格式)在画布上"点了没反应",
             直接删除; 配色改由左侧「风格预设」一键套用, 版权信息由下方文案字段 + 章节勾选控制。 -->

        <div class="tpl-body">
          <!-- 侧栏(窄, 视觉上在右, 见 CSS order): 只留"要插入的章节结构"与生成时间。
               字段类配置全部上移到顶栏/页面就地编辑 —— 用户口径: 不要挨个自定义。 -->
          <div class="tpl-left">
          <div class="tpl-field">
            <div class="tpl-field-label">{{ t('rp.genTime') }}</div>
            <div class="tpl-time">
              <label class="chk"><input type="radio" value="auto" v-model="vis.timeMode"> {{ t('rp.timeAuto') }}</label>
              <label class="chk"><input type="radio" value="custom" v-model="vis.timeMode"> {{ t('rp.custom') }}</label>
            </div>
            <!-- 自定义时直接在此处填(与封面同步); 以前输入框只藏在右侧页面里, 用户找不到 -->
            <input class="input xs" v-model.trim="vis.timeText" :placeholder="t('rp.timePh')"
                   :disabled="vis.timeMode !== 'custom'" style="margin-top:6px; width:100%">
          </div>

          <!-- 风格预设(2026-09-26 四轮补刀: 用户"好亮好闪、不要挨个挨个自定义";
               改为 WPS 式整套配色一键套用, 而非逐章节堆一堆亮色块) -->
          <div class="tpl-field">
            <div class="tpl-field-label">{{ t('rp.stylePreset') }}</div>
            <div class="style-presets">
              <button v-for="p in STYLE_PRESETS_THEME" :key="p.key" type="button"
                      class="style-sw" :class="{ on: stylePreset === p.key }"
                      :title="t(p.name)" @click="applyStylePreset(p.key)">
                <span class="style-sw-bar" :style="{ background: p.accent }"></span>
                <span class="style-sw-name">{{ t(p.name) }}</span>
              </button>
            </div>
            <p class="muted small" style="margin:7px 0 0; line-height:1.6">{{ t('rp.styleHint') }}</p>
          </div>

          <div class="tpl-field">
            <div class="tpl-field-label">{{ t('rp.secStruct') }}</div>
            <div class="vis-sec-list">
              <!-- 点行/点画布章节互相选中(activeSec): 版面编辑模式下"选中谁改谁" -->
              <div class="vis-sec-row" v-for="(k, i) in vis.sections" :key="k"
                   :class="{ 'row-on': activeSec === k }" @click="activeSec = k">
                <div class="vis-sec-main">
                  <span class="mono small muted">{{ String(i + 1).padStart(2, '0') }}</span>
                  <input type="checkbox"
                    :checked="k === 'copyright' ? vis.copyrightOn : visEnabled[k]"
                    :disabled="k === 'copyright' ? false : !secOptional(k)"
                    @change="k === 'copyright' ? toggleCopyright() : toggleVisSec(k)">
                  <span class="small">{{ secTitle(k) }}</span>
                  <span class="muted small" v-if="k === 'copyright'">{{ t('rp.copyrightHint') }}</span>
                  <span class="muted small" v-else-if="!secOptional(k)">{{ t('rp.coreSec') }}</span>
                  <span class="muted small" v-else-if="visEnabled[k] === false">{{ t('rp.optionalSec') }}</span>
                  <div class="spacer"></div>
                  <button class="btn xs" @click="moveVisSec(i, -1)" :disabled="i === 0">{{ t('rp.moveUp') }}</button>
                  <button class="btn xs" @click="moveVisSec(i, 1)" :disabled="i === vis.sections.length - 1">{{ t('rp.moveDown') }}</button>
                </div>
              </div>
            </div>
          </div>
          </div><!-- /tpl-left -->

          <!-- 版面编辑(2026-09-26): 不再是只读预览 —— 页面上的文字点哪改哪,
               改完即时进 vis 并最终落到报告。灰色占位条 = 扫描数据自动填充(不可改)。 -->
          <div class="tpl-preview-wrap">
            <div class="tpl-preview-title muted small">{{ t('rp.layoutEdit') }}</div>
            <div class="tpl-page" :style="{ '--tp-accent': vis.accent }">
              <!-- 封面(就地编辑) -->
              <div class="tp-cover" v-if="vis.cover">
                <div class="tp-logo" v-if="visLogo"><img :src="visLogo" alt="logo"></div>
                <Editable class="tp-title" v-model="vis.title" :placeholder="t('rp.titlePh')" />
                <Editable class="tp-sub" v-model="vis.subtitle" :placeholder="t('rp.subtitle')" />
                <Editable class="tp-client" v-model="vis.client" :placeholder="t('rp.clientPh')" />
                <div class="tp-risk">{{ t('rp.overallRisk') }}: <b>{{ t('rp.autoFill') }}</b></div>
                <div class="tp-meta">
                  <div>{{ t('rp.operator') }}: <Editable class="tp-inline" v-model="vis.operator" :placeholder="t('rp.operatorPh')" /></div>
                  <div>{{ t('rp.tool') }}: <Editable class="tp-inline" v-model="vis.tool" :placeholder="t('rp.toolPh')" /></div>
                  <div v-if="vis.timeMode === 'custom'">{{ t('rp.genTime') }}: <Editable class="tp-inline" v-model="vis.timeText" :placeholder="t('rp.timeShort')" /></div>
                  <div v-else>{{ t('rp.genTime') }}: <span class="muted">{{ t('rp.timeAuto') }}</span></div>
                </div>
              </div>
              <!-- 封面关闭时字段仍要给编辑入口: 否则这些值再也改不动 -->
              <div class="tp-cover-off" v-else>
                <div class="muted small">{{ t('rp.coverOff') }}</div>
                <div>{{ t('rp.titleCol') }} <Editable class="tp-inline" v-model="vis.title" :placeholder="t('rp.titleCol')" /></div>
                <div>{{ t('rp.subtitle') }} <Editable class="tp-inline" v-model="vis.subtitle" :placeholder="t('rp.subtitle')" /></div>
                <div>{{ t('rp.client') }} <Editable class="tp-inline" v-model="vis.client" :placeholder="t('rp.client')" /></div>
              </div>
              <!-- 正文页: 页眉 + 章节(可点选 → 左侧改样式) + 免责/版权 + 页脚 -->
              <div class="tp-body">
                <div class="tp-header">{{ t('rp.header') }} <Editable class="tp-inline" v-model="vis.header" :placeholder="t('rp.defaultPh')" /></div>
                <div class="tp-sec" v-for="(k, i) in previewSections" :key="k"
                     :class="{ 'sec-on': activeSec === k }" @click="activeSec = k"
                     :title="t('rp.secClick', { name: secTitle(k) })">
                  <div class="tp-sec-title" :style="tpTitleStyle(k)">
                    <span class="tp-sec-no">{{ String(i + 1).padStart(2, '0') }}</span>
                    <span v-html="secTitle(k)"></span>
                  </div>
                  <div class="tp-sec-body" :style="tpBodyStyle(k)">
                    <div class="tp-line" v-for="n in 3" :key="n"></div>
                    <div class="tp-note muted small">{{ t('rp.bodyAuto') }}</div>
                  </div>
                </div>
                <!-- 免责/版权在底部单独呈现并可就地编辑文案; 与"未勾选不显示"同口径:
                     在右侧章节结构里勾上才显示, 取消勾选这里即不显示。文案留空 = 用内置默认。 -->
                <div class="tp-tail" v-if="visEnabled.disclaimer">{{ t('rp.disclaimer') }} <Editable class="tp-inline" v-model="vis.disclaimer" :placeholder="t('rp.defaultTextPh')" /></div>
                <div class="tp-tail" v-if="vis.copyrightOn">{{ t('rp.copyright') }} <Editable class="tp-inline" v-model="vis.copyright" :placeholder="t('rp.defaultTextPh')" /></div>
                <div class="tp-footer">{{ t('rp.footer') }} <Editable class="tp-inline" v-model="vis.footer" :placeholder="t('rp.footerPh')" /></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { useRoute } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import SevTag from '../components/SevTag.vue'
import Empty from '../components/Empty.vue'
import Modal from '../components/Modal.vue'
// AiAnalyzeButton: 原始报告详情里可直接(重新)触发 AI 分析, 回写到本报告
import AiAnalyzeButton from '../components/AiAnalyzeButton.vue'
// Editable: 就地编辑块(2026-09-26 —— 版面直接编辑, 取代原先那排 RichText 输入框)
import Editable from '../components/Editable.vue'
import { v2 } from '../api/http'
import { fmtDT } from '../utils'
import { t } from '../i18n'

const route = useRoute()
// tab 支持 URL query 驱动(如 /reports?tab=gen&job=<id>, 从"扫描作业"页跳来直接
// 落在报告生成并预选该作业); 默认 gen
const tab = ref(['gen', 'raw', 'arch', 'diff'].includes(route.query.tab) ? route.query.tab : 'gen')

const status = ref(null)
const busy = ref(false)
const diffBusy = ref(false)
// 预览抽屉(2026-09-25 二轮: "像抽屉一样打开页面看"): url 是接口地址(存档)或
// blob URL(生成预览), download 是可选的"下载原件"直链。
const drawer = ref({ url: '', title: '', download: '' })
const lastDiffID = ref('')

const options = ref({ nodes: [{ id: 'local', name: t('rp.localNode') }] })
// Word 模板列表(可视化排版 + 手动导入的 .docx; builtin 不在列表里展示)
const wordTpls = ref([])
// 可视化排版编辑器状态(2026-09-25 起它就是"报告生成"页本体)
const visBusy = ref(false)
const visSectionsMeta = ref([]) // [{key, title, optional}] 来自 /word/templates/sections
const visEnabled = ref({}) // key -> bool
// 模板字段(2026-09-25 二轮用户清单): 页眉/页脚/标题1/版权/检测工具/免责声明/
// 报告人/生成时间 均可编辑可删除; 富文本字段存"白名单 HTML 片段"(RichText 组件
// 产出, 后端再清洗一次)。空值 = 该处按内置占位符走(报告数据自动填充)。
const vis = reactive({
  name: '', title: '', header: '', client: '', subtitle: '',
  operator: '', tool: '', timeMode: 'auto', timeText: '',
  footer: '', copyright: '', copyrightOn: true, disclaimer: '',
  accent: '#1F3A5F', cover: true, sections: [],
  // sectionStyles: 章节 key -> {titleColor,titleBg,fontColor,bg,bold,size}
  // (2026-09-25 三轮: 逐章节字体颜色/底色/格式, 内容不可改; 颜色本地存 #rrggbb,
  // 提交/回显时去掉 #)
  sectionStyles: {}
})
// 版权默认文案(与后端 report.CopyrightLine 口径一致; 预填进编辑器,
// 用户清空 = 报告不出版权章)
// 2026-10-04 i18n: 默认版权文案键值化(运行时取, 跟随语言)
function dftCopyright() { return t('rp.dftCopyright') }
// 模板编辑浮窗(2026-09-25 三轮: "点击编辑时是浮窗并有保存功能")
const tplModal = ref(false)
// 封面 logo(2026-09-25 用户要求"模板能放 logo"): visLogo 是预览用 data URL,
// 上传/删除走后端接口(落 data/outp/logos/, 与模板 .docx 同树)
const visLogo = ref('')
const logoBusy = ref(false)
const tplSavedMsg = ref('')
const archives = ref([])
const history = ref([])

// ===== 模板编辑浮窗(2026-09-25 三轮: "点击编辑时是浮窗并有保存功能") =====
// 富文本字段由 RichText 组件承载(组件内 contenteditable 单向同步, 与旧白纸区
// 同口径: DOM 是编辑源, 不绑 Vue 文本插值)。浮窗打开时才挂载编辑器, 初始
// 内容由组件挂载时写入 —— 换模板/重开浮窗自然重新填充。
const logoInput = ref(null)
function pickLogo() {
  if (logoInput.value) logoInput.value.click()
}

// 打开编辑浮窗: name 空 = 新建(默认文案); 否则载入已有模板配置 + logo
async function openTplModal(name) {
  if (name) {
    await loadVisualTpl(name)
    await loadLogoPreview(name)
  } else {
    resetVis()
    visLogo.value = ''
  }
  activeSec.value = '' // 打开时不预选章节(避免误改到上一个模板选中的章节样式)
  tplModal.value = true
}
function closeTplModal() {
  tplModal.value = false
}

const form = reactive({
  // 2026-09-26 重构: 生成报告 = 选模板 + 选任务(可多选) + 选格式(word/html/pdf)。
  // 标题按时间自动命名, 报告人取登录用户; 7 个漏洞范围筛选项收进"高级筛选"(默认收起)。
  // template: 报告模板名(builtin=内置版式 / 自定义名); jobIds: 选中的扫描任务名(多选, 空=全部);
  // format: 下载/存档格式(word/html/pdf), 预览固定 html(可在浏览器打印成 PDF)。
  f: { template: 'builtin', jobIds: [], format: 'word', severity: '', cidr: '', ip: '', cve: '', from: '', to: '', probeNode: '', onlyEvidence: false }
})
// diffForm: 历史对比主入口 = 选两份存档对比(baseId/targetId); from/to 仅作"按时间窗"备选
const diffForm = reactive({ baseId: '', targetId: '', from: '', to: '', save: false })
const diff = ref(null)

function buildFilter() {
  const f = {}
  if (form.f.severity) f.severity = [form.f.severity]
  if (form.f.cidr) f.cidr = form.f.cidr
  if (form.f.ip) f.ip = form.f.ip
  if (form.f.cve) f.cve = form.f.cve
  // 时间窗: 后端 Filter 的 json tag 是 timeFrom/timeTo(不是 from/to; 之前发
  // from/to 被静默丢弃不生效 —— 2026-09-26 修)
  if (form.f.from) f.timeFrom = form.f.from
  if (form.f.to) f.timeTo = form.f.to
  if (form.f.probeNode) f.probeNode = form.f.probeNode
  if (form.f.onlyEvidence) f.onlyWithEvidence = true
  return f
}

function buildRequest(format) {
  const req = { format: format || form.f.format || 'word', filter: buildFilter() }
  // 报告模板: 下拉选定的模板名(builtin=内置版式); 标题/报告人由后端按时间/登录用户生成
  req.wordTemplate = form.f.template || 'builtin'
  // 扫描任务多选: 选中的任务名取并集(空 = 全部数据)
  if (form.f.jobIds && form.f.jobIds.length) req.jobIds = form.f.jobIds
  return req
}

// ===== 扫描作业(任务名)下拉: 报告按作业生成 / 原始报告按作业分类共用 =====
const jobList = ref([]) // {id, name, target, status, running}
async function loadJobList() {
  try {
    const d = await v2('/jobs')
    jobList.value = (d && d.jobs) || []
  } catch (e) { jobList.value = [] }
}
// 报告标题的"按作业"提示: 选了任务就显示任务名(多选用"、"拼接), 便于确认生成的是哪份
const jobNameOf = computed(() => {
  if (!form.f.jobIds || !form.f.jobIds.length) return ''
  return form.f.jobIds.map(id => {
    const j = jobList.value.find(x => x.id === id)
    return j ? j.name : id
  }).join('、')
})

async function loadWordTpls() {
  try {
    const d = await v2('/report/word/templates')
    wordTpls.value = ((d && d.list) || []).filter(t => !t.builtin)
  } catch (e) { wordTpls.value = [] }
  loadVisSections()
}

// ===== 扫描任务选择(2026-09-26: 下拉必选 + 可多选, 选中以 chip 展示, 不可留空) =====
const jobPicker = ref('')
function addJob() {
  if (!jobPicker.value) return
  if (!form.f.jobIds.includes(jobPicker.value)) form.f.jobIds.push(jobPicker.value)
  jobPicker.value = '' // 重置, 便于继续选下一个
}
function removeJob(id) { form.f.jobIds = form.f.jobIds.filter(x => x !== id) }
function jobNameOfId(id) { const j = jobList.value.find(x => x.id === id); return j ? j.name : id }
// 报告生成下拉的模板选项: 排除 default(内置默认模板, 受保护仅展示; 报告生成直接用"内置版式"builtin)
const genTplOptions = computed(() => (wordTpls.value || []).filter(t => t.name !== 'default'))

// ===== 可视化排版编辑器 =====

async function loadVisSections() {
  try {
    const d = await v2('/report/word/templates/sections')
    visSectionsMeta.value = (d && d.list) || []
    if (vis.sections.length === 0) resetVis()
  } catch (e) { /* 失败时编辑器章节行空, 不影响模板列表 */ }
}

function secTitle(key) {
  const m = visSectionsMeta.value.find(x => x.key === key)
  return m ? m.title : key
}
function secOptional(key) {
  const m = visSectionsMeta.value.find(x => x.key === key)
  return !!(m && m.optional)
}
function toggleVisSec(key) {
  visEnabled.value[key] = !(visEnabled.value[key] ?? true)
}
// 版权信息勾选: 开 = 带版权章(文案空则回退默认); 关 = 保存时空串 → 后端跳过该章
function toggleCopyright() {
  vis.copyrightOn = !vis.copyrightOn
  if (vis.copyrightOn && !vis.copyright) vis.copyright = DEFAULT_COPYRIGHT
}
function moveVisSec(i, dir) {
  const s = vis.sections
  const j = i + dir
  if (j < 0 || j >= s.length) return
  const t = s[i]; s[i] = s[j]; s[j] = t
}

// 版面预览用: 当前勾选(启用)的"普通正文章节", 按当前顺序 —— 与报告实际章节编号
// 口径一致(SectionBlocksWithOptions 连续编号, 未勾选的跳过)。
// 免责声明/版权信息不混进编号章节序列: 它们在页面底部 tp-tail 单独呈现并可就地
// 编辑文案, 若再进这里会同屏重复且编号错乱(取消勾选时也藏不掉)。
const previewSections = computed(() =>
  vis.sections.filter(k => (visEnabled.value[k] ?? true) && k !== 'disclaimer' && k !== 'copyright')
)

// ===== 主题色预设(2026-09-26 用户: 默认色太亮眼, 给一组沉稳的商务色) =====
const ACCENTS = [
  { hex: '#1F3A5F', name: 'rp.accDeep' },
  { hex: '#374151', name: 'rp.accInk' },
  { hex: '#0F766E', name: 'rp.accTeal' },
  { hex: '#065F46', name: 'rp.accGreen' },
  { hex: '#7F1D1D', name: 'rp.accRed' },
  { hex: '#1E3A8A', name: 'rp.accNavy' },
  { hex: '#4B5563', name: 'rp.accGraphite' },
  { hex: '#5B4B8A', name: 'rp.accViolet' },
  { hex: '#B45309', name: 'rp.accOchre' },
  { hex: '#4F46E5', name: 'rp.accIndigo' }
]

// ===== 风格预设(2026-09-26 四轮补刀: 取代"逐章节一堆亮色块"的挨个自定义)。
//   每套是协调好的整套配色(accent + 各章节标题色/底色/正文字色), 一键套用到全部章节,
//   像 WPS 选模板。颜色都取沉稳系, 不刺眼。 =====
const STYLE_PRESETS_THEME = [
  { key: 'biz',   name: 'rp.spBiz',   accent: '#1F3A5F', titleColor: '#1F3A5F', titleBg: '#EAF0F7', fontColor: '#1F2937', bg: '#FFFFFF' },
  { key: 'gray',  name: 'rp.spGray',  accent: '#374151', titleColor: '#374151', titleBg: '#F3F4F6', fontColor: '#1F2937', bg: '#FFFFFF' },
  { key: 'gov',   name: 'rp.spGov',   accent: '#9B2C2C', titleColor: '#9B2C2C', titleBg: '#FBEAEA', fontColor: '#1F2937', bg: '#FFFFFF' },
  { key: 'teal',  name: 'rp.spTeal',  accent: '#0F766E', titleColor: '#0F766E', titleBg: '#E0F2FE', fontColor: '#1F2937', bg: '#FFFFFF' },
  { key: 'green', name: 'rp.spGreen', accent: '#166534', titleColor: '#166534', titleBg: '#DCFCE7', fontColor: '#1F2937', bg: '#FFFFFF' }
]

// ===== 版面就地编辑状态(2026-09-26 四轮: 形态对齐 WPS —— 风格预设 + 画布点选高亮) =====
const activeSec = ref('') // 画布上点选的章节(与侧栏章节列表联动, 仅用于高亮, 不再逐章改样式)
const stylePreset = ref('') // 当前套用的风格预设 key(空 = 未套用/自定义)
// 顶栏主题色 popover 开关; 点弹窗任意空白统一关掉
const accentOpen = ref(false)
function closePops() {
  accentOpen.value = false
}


// ===== 风格预设: 一键套用整套协调配色到全部章节(取代逐章节手动调) =====
function applyStylePreset(key) {
  const p = STYLE_PRESETS_THEME.find(x => x.key === key)
  if (!p) return
  vis.accent = p.accent // 封面标题 / 章节标题条主色
  const m = {}
  for (const k of vis.sections) {
    m[k] = { titleColor: p.titleColor, titleBg: p.titleBg, fontColor: p.fontColor, bg: p.bg, bold: false, size: 0 }
  }
  vis.sectionStyles = m // 整模板统一一套观感, 后端按章节存储但值相同
  stylePreset.value = key
}

// ===== 逐章节字体样式(2026-09-25 三轮: 字体颜色/底色/格式, 内容不可改) =====
// 本地存 #rrggbb(原生 color 输入框口径); 提交/回显时后端口径是 6 位 hex 不带 #
const EMPTY_SEC_STYLE = { titleColor: '', titleBg: '', fontColor: '', bg: '', bold: false, size: 0 }
function secStyle(k) {
  return vis.sectionStyles[k] || EMPTY_SEC_STYLE
}
function hasSecStyle(k) {
  const s = secStyle(k)
  return !!(s.titleColor || s.titleBg || s.fontColor || s.bg || s.bold || s.size)
}
function setSecStyleColor(k, field, val) {
  ensureSecStyle(k)[field] = val // val '' = 恢复默认(原生 input 只会回 #rrggbb)
}
function setSecStyleBool(k, field, val) {
  ensureSecStyle(k)[field] = !!val
}
function setSecStyleSize(k, val) {
  ensureSecStyle(k).size = Number(val) || 0
}
function ensureSecStyle(k) {
  if (!vis.sectionStyles[k]) vis.sectionStyles[k] = { ...EMPTY_SEC_STYLE }
  return vis.sectionStyles[k]
}
function resetSecStyle(k) {
  vis.sectionStyles[k] = { ...EMPTY_SEC_STYLE }
}
// 版面预览: 标题/正文的实时样式(与报告渲染同语义 —— 后端 styleSectionBody)
function tpTitleStyle(k) {
  const s = secStyle(k)
  const st = {}
  if (s.titleColor) st.color = s.titleColor
  if (s.titleBg) st.background = s.titleBg
  return st
}
function tpBodyStyle(k) {
  const s = secStyle(k)
  const st = {}
  if (s.bg) st.background = s.bg
  if (s.fontColor) st.color = s.fontColor
  if (s.size) st.fontSize = (s.size / 2) + 'px' // 半点 -> px
  if (s.bold) st.fontWeight = 'bold'
  return st
}
// 提交前清洗: 只保留非空项, 颜色去 #(后端 6 位 hex 口径); 无任何样式的章节不带 key
function cleanSecStyles() {
  const m = {}
  for (const k of vis.sections) {
    const s = vis.sectionStyles[k]
    if (!s) continue
    const e = {}
    if (s.titleColor) e.titleColor = s.titleColor.replace('#', '')
    if (s.titleBg) e.titleBg = s.titleBg.replace('#', '')
    if (s.fontColor) e.fontColor = s.fontColor.replace('#', '')
    if (s.bg) e.bg = s.bg.replace('#', '')
    if (s.bold) e.bold = true
    if (s.size) e.size = s.size
    if (Object.keys(e).length) m[k] = e
  }
  return m
}
// 回显: 后端 6 位 hex 不带 # → 本地 #rrggbb; 章节清单外的样式 key 丢弃
function loadSecStyles(d) {
  const m = {}
  for (const k of vis.sections) {
    const s = (d.sectionStyles && d.sectionStyles[k]) || {}
    const h = v => (v ? '#' + String(v).replace('#', '') : '')
    m[k] = {
      titleColor: h(s.titleColor), titleBg: h(s.titleBg),
      fontColor: h(s.fontColor), bg: h(s.bg),
      bold: !!s.bold, size: Number(s.size) || 0
    }
  }
  vis.sectionStyles = m
}

async function loadVisualTpl(name) {
  try {
    const d = await v2('/report/word/templates/visual?name=' + encodeURIComponent(name))
    if (!d) return
    vis.name = d.name || name
    vis.title = d.title || ''
    vis.header = d.header || ''
    vis.client = d.client || ''
    vis.subtitle = d.subtitle || ''
    vis.operator = d.operator || ''
    vis.tool = d.tool || ''
    vis.timeMode = d.timeMode === 'custom' ? 'custom' : 'auto'
    vis.timeText = d.timeText || ''
    vis.footer = d.footer || ''
    // 版权(2026-09-26 用户: "版权信息"勾要能选中/取消, 不能灰):
    //   "" = 用户明确关掉(不出该章) → 不勾;  null/undefined = 内置默认 → 勾+默认文案;
    //   非空 = 自定义文案 → 勾。勾选态单独存 copyrightOn, 与文案文本解耦。
    if (d.copyright === '') { vis.copyrightOn = false; vis.copyright = '' }
    else if (d.copyright == null) { vis.copyrightOn = true; vis.copyright = DEFAULT_COPYRIGHT }
    else { vis.copyrightOn = true; vis.copyright = d.copyright }
    vis.disclaimer = d.disclaimer || ''
    // 统一存带 # 的形式(input[type=color] 的口径; 后端保存时会去 #)。
    // 旧实现这里把 # 去掉了, 编辑已有模板时颜色控件会失效(值非法显示成黑)。
    vis.accent = '#' + String(d.accent || '1F3A5F').replace('#', '')
    vis.cover = d.cover !== false
    // 右侧"章节结构"始终显示 SectionList 全集(不因取消勾选而从列表消失): 取消勾选
    // 只让该章在版面预览里不显示、报告不出该章, 用户随时可重新勾回。旧模板可能缺
    // 后来新增的章节(如 disclaimer/copyright 是 2026-09-25 才加的), 按 SectionList
    // 顺序补在末尾; 已保存章节按保存顺序在前。勾选态 = 该 key 是否在已保存 sections 里。
    const fullKeys = visSectionsMeta.value.length
      ? visSectionsMeta.value.map(x => x.key)
      : ['summary', 'risk', 'assets', 'vulns', 'vulnfix', 'penta', 'scans', 'fix', 'disclaimer', 'copyright']
    const saved = (d.sections && d.sections.length) ? d.sections.slice() : fullKeys.slice()
    vis.sections = saved.concat(fullKeys.filter(k => !saved.includes(k)))
    const m = {}
    for (const k of vis.sections) m[k] = saved.includes(k)
    visEnabled.value = m
    visEnabled.value['copyright'] = vis.copyrightOn // 版权出章由 copyrightOn 决定, 对齐勾选态
    loadSecStyles(d) // 逐章节样式回显(旧模板无此键 = 全默认, 行为不变)
    stylePreset.value = '' // 载入既有模板: 不强行匹配预设(可能含自定义值)
  } catch (e) { /* http.js 统一提示 */ }
}

function resetVisEnabled() {
  const m = {}
  for (const k of vis.sections) m[k] = true
  visEnabled.value = m
}

async function saveVisualTpl() {
  if (!vis.name.trim()) { window.alert(t('rp.needTplName')); return false }
  visBusy.value = true
  try {
    // 只提交勾选的章节(顺序 = 当前排列); 版权信息由版权勾选(copyrightOn)决定:
    // 不勾 = 后端按 Copyright 空串跳过该章; 勾 = 用文案字段(空则回退默认文案)。
    // 注意: visEnabled 是 ref, 脚本里必须用 .value 取值(模板里 Vue 自动解包才可直接
    // 用)。漏了 .value 时 visEnabled[k] 恒为 undefined → !== false 恒真 → 未勾的
    // 章节也会被存进模板, 表现为"取消勾选保存后仍显示 / 重开仍勾选"。
    const secs = vis.sections.filter(k => visEnabled.value[k] !== false)
    await v2('/report/word/templates/visual', {
      method: 'POST',
      body: JSON.stringify({
        name: vis.name.trim(),
        title: vis.title, header: vis.header,
        client: vis.client, subtitle: vis.subtitle,
        operator: vis.operator, tool: vis.tool,
        timeMode: vis.timeMode, timeText: vis.timeMode === 'custom' ? vis.timeText : '',
        footer: vis.footer, copyright: vis.copyrightOn ? (vis.copyright || dftCopyright()) : '',
        disclaimer: vis.disclaimer,
        accent: vis.accent, cover: vis.cover, sections: secs,
        sectionStyles: cleanSecStyles() // 逐章节字体样式(空 = 不带, 旧模板零差异)
      })
    })
    tplSavedMsg.value = t('rp.savedTo', { name: vis.name.trim() })
    setTimeout(() => { tplSavedMsg.value = '' }, 4000)
    loadWordTpls()
    closeTplModal()
    return true
  } catch (e) {
    window.alert(t('rp.saveFail', { err: e.message || e }))
    return false
  } finally { visBusy.value = false }
}

function previewWordTpl(name) {
  window.open('/api/v2/report/word/templates/' + encodeURIComponent(name) + '/preview', '_blank')
}

function resetVis() {
  vis.name = ''
  vis.title = ''
  vis.header = ''
  vis.client = ''
  vis.subtitle = t('rp.dftSubtitle')
  vis.operator = ''
  vis.tool = ''
  vis.timeMode = 'auto'
  vis.timeText = ''
  vis.footer = ''
  vis.copyright = dftCopyright()
  vis.copyrightOn = true // 新建模板默认带版权章
  vis.disclaimer = t('rp.dftDisclaimer')
  vis.accent = '#1F3A5F' // 默认改沉稳深蓝(2026-09-26 用户: 原靛蓝太亮眼)
  vis.cover = true
  visLogo.value = ''
  vis.sections = visSectionsMeta.value.map(x => x.key)
  if (vis.sections.length === 0) {
    // sections 元数据还没拉到: 用内置兜底顺序(与后端 sectionOrder 一致)
    vis.sections = ['summary', 'risk', 'assets', 'vulns', 'vulnfix', 'penta', 'scans', 'fix', 'disclaimer', 'copyright']
  }
  resetVisEnabled()
  vis.sectionStyles = {} // 重置为默认: 逐章节样式全清
  stylePreset.value = ''
}

// ===== 封面 logo(2026-09-25 用户要求"模板能放 logo") =====
async function loadLogoPreview(name) {
  visLogo.value = ''
  if (!name) return
  try {
    const r = await fetch('/api/v2/report/word/templates/visual/logo?name=' + encodeURIComponent(name))
    if (!r.ok) return // 无 logo(404)正常
    visLogo.value = URL.createObjectURL(await r.blob())
  } catch (e) { /* 预览失败不影响编辑 */ }
}

async function onLogoFile(e) {
  const f = e.target.files && e.target.files[0]
  e.target.value = '' // 允许重复选同一文件
  if (!f) return
  if (!vis.name.trim()) { window.alert(t('rp.needNameForLogo')); return }
  logoBusy.value = true
  try {
    const b64 = await fileToB64(f)
    const r = await v2('/report/word/templates/visual/logo', {
      method: 'POST',
      body: JSON.stringify({ name: vis.name.trim(), data: b64 })
    })
    visLogo.value = 'data:' + (f.type || 'image/png') + ';base64,' + b64
    tplSavedMsg.value = t('rp.logoSaved')
    setTimeout(() => { tplSavedMsg.value = '' }, 4000)
  } catch (err) { window.alert(t('rp.logoFail', { err: err.message })) }
  finally { logoBusy.value = false }
}

async function delLogo() {
  if (!vis.name.trim()) return
  try {
    await v2('/report/word/templates/visual/logo?name=' + encodeURIComponent(vis.name.trim()), { method: 'DELETE' })
    visLogo.value = ''
  } catch (e) { window.alert(t('rp.delFail', { err: e.message })) }
}

async function delWordTpl(tp) {
  if (!window.confirm(t('rp.delTplConfirm', { name: tp.name }))) return
  try {
    await v2('/report/word/templates/' + encodeURIComponent(tp.name), { method: 'DELETE' })
    loadWordTpls()
  } catch (e) { /* http.js 统一提示 */ }
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
    fr.onerror = () => reject(new Error(t('rp.readFail')))
    fr.readAsDataURL(file)
  })
}

async function loadStatus() {
  try {
    status.value = await v2('/report/status')
    if (status.value && status.value.enabled) {
      loadOptions()
      loadWordTpls() // Word 模板列表(生成页"已有模板"区数据源)
    }
  } catch (e) { status.value = { enabled: false, hint: e.message } }
}

// 2026-10-04 i18n: 级别中文名统一走 sev.* 词条(原 SEV_CN 常量删除)
async function loadOptions() {
  try {
    options.value = await v2('/report/options')
    // 2026-10-02 用户口径: 选项基于数据里存在的 —— 已选的风险等级/探针节点
    // 没有数据了(如扫描报告/漏洞全删) → 清除表单值, 防按不存在的值筛出空报告
    if (form.f.severity && !((options.value.severities || []).includes(form.f.severity))) form.f.severity = ''
    if (form.f.probeNode && !((options.value.nodes || []).some(n => n.id === form.f.probeNode))) form.f.probeNode = ''
  } catch (e) { /* 降级: 保留默认节点 */ }
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

// ===== 预览抽屉(2026-09-25 二轮: "像抽屉一样打开页面看") =====
// 存档预览直连 /preview(同域 iframe 自动带会话 cookie; Word 由服务端转 HTML,
// 解析不了才回二进制 → 抽屉里 iframe 打不开时用户点"下载原件"兜底)。
// 生成预览是 POST 回来的 HTML → Blob URL。
function openDrawer(url, title, downloadUrl) {
  closeDrawer()
  drawer.value = { url, title: title || '', download: downloadUrl || '' }
}
function closeDrawer() {
  // 只有 blob: URL 需要回收(接口直链由浏览器自己管)
  if (drawer.value.url && drawer.value.url.startsWith('blob:')) URL.revokeObjectURL(drawer.value.url)
  drawer.value = { url: '', title: '', download: '' }
}
function previewArchive(a) {
  openDrawer('/api/v2/report/' + a.id + '/preview', a.title, '/api/v2/report/' + a.id + '/download')
}
// Esc 关抽屉
function onDrawerKeydown(e) {
  if (e.key !== 'Escape') return
  // 浮窗优先: 编辑中按 Esc 先关编辑窗, 别误关底下的预览抽屉
  if (tplModal.value) { closeTplModal(); return }
  if (drawer.value.url) closeDrawer()
}

// 预览: POST 返回 HTML, 用 Blob URL 交给抽屉 iframe(不能直接把 HTML 塞进
// v-html, 报告自身带 <style>/<script> 且体积大, iframe 隔离更安全)
async function genPreview() {
  busy.value = true
  try {
    await ensureTemplateSaved()
    const r = await fetch('/api/v2/report/preview', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildRequest('html'))
    })
    if (!r.ok) throw new Error('HTTP ' + r.status)
    const html = await r.text()
    openDrawer(URL.createObjectURL(new Blob([html], { type: 'text/html' })), t('rp.previewTitle'))
  } catch (e) { alert(t('rp.previewFail', { err: e.message })) } finally { busy.value = false }
}

// 生成前确保选中的模板已落盘(用户"编辑完直接出报告"的路径):
// 仅当"选中的模板"就是当前编辑器里未保存的模板时才强制保存; 否则按已存模板/内置版式。
async function ensureTemplateSaved() {
  if (vis.name.trim() && vis.name.trim() === form.f.template) {
    await saveVisualTpl()
  }
}

async function genDownload() {
  busy.value = true
  try {
    await ensureTemplateSaved()
    const d = await v2('/report/generate', { method: 'POST', body: { ...buildRequest(form.f.format), archive: false } })
    downloadReport(d.report.id)
  } catch (e) { alert(t('rp.genFail', { err: e.message })) } finally { busy.value = false }
}

async function genArchive() {
  busy.value = true
  try {
    await ensureTemplateSaved()
    const d = await v2('/report/generate', { method: 'POST', body: { ...buildRequest(form.f.format), archive: true } })
    alert(t('rp.archDone'))
    loadArchives()
    tab.value = 'arch'
    return d
  } catch (e) { alert(t('rp.genFail', { err: e.message })) } finally { busy.value = false }
}

// 下载走浏览器原生下载(服务端已设置 Content-Disposition)
function downloadReport(id) {
  window.open('/api/v2/report/' + id + '/download', '_blank')
}

function download(a) { downloadReport(a.id) }

async function del(a) {
  if (!confirm(t('rp.delReportConfirm', { title: a.title }))) return
  try {
    await v2('/report/' + a.id, { method: 'DELETE' })
    loadArchives()
    if (status.value) status.value.archiveCount = archives.value.length
  } catch (e) { alert(e.message) }
}

// 主入口: 选两份报告存档对比(按各自筛选条件重建漏洞明细, 2026-09-26 用户口径:
// 历史对比应对存档做对比, 而非无根据的时间窗)
async function runDiff() {
  if (!diffForm.baseId || !diffForm.targetId) { alert(t('rp.needBothArch')); return }
  diffBusy.value = true
  try {
    const b = archives.value.find(a => a.id === diffForm.baseId)
    const tgt = archives.value.find(a => a.id === diffForm.targetId)
    const d = await v2('/report/compare', {
      method: 'POST',
      body: {
        baseId: diffForm.baseId, targetId: diffForm.targetId,
        save: diffForm.save,
        title: t('rp.diffTitle', { base: b ? b.title : diffForm.baseId, target: tgt ? tgt.title : diffForm.targetId })
      }
    })
    diff.value = d.diff
    lastDiffID.value = d.archiveId || ''
  } catch (e) { alert(t('rp.diffFail', { err: e.message })) } finally { diffBusy.value = false }
}

// 备选: 按时间窗对比(全库漏洞切窗, 不依赖存档; 基线自动取目标窗前等长一段)
async function runWindowDiff() {
  if (!diffForm.from && !diffForm.to) { alert(t('rp.needWinDates')); return }
  diffBusy.value = true
  try {
    const d = await v2('/report/compare', {
      method: 'POST',
      body: { from: diffForm.from, to: diffForm.to, save: diffForm.save, title: t('rp.winTitle', { from: diffForm.from || '', to: diffForm.to || '' }) }
    })
    diff.value = d.diff
    lastDiffID.value = d.archiveId || ''
  } catch (e) { alert(t('rp.diffFail', { err: e.message })) } finally { diffBusy.value = false }
}

function diffPreview() {
  if (lastDiffID.value) downloadReport(lastDiffID.value)
}

function scoreCls(stats) {
  if (!stats) return ''
  const s = stats.riskScore || 0
  if (s >= 70) return 'bad'
  if (s >= 40) return 'warn'
  return 'ok'
}


// ===== 原始报告(二期) =====
// 数据源: 四大业务模块执行完成后的原始结构化结果(只存不加工, AI 字段预留)。
const rawList = ref([])
const rawTotal = ref(0)
const rawOptions = ref({ modules: [], tags: [], assets: [], jobs: [], dateRange: { from: '', to: '' } })
const rawF = reactive({ module: '', tag: '', asset: '', from: '', to: '', keyword: '', job: '' })
const rawSel = ref([])
const rawDetail = ref(null)
const rawBusy = ref(false)
const mergeForm = reactive({ title: '', tags: '' })

// 来源模块展示(与后端 report.RawModules 同口径, 未知模块原样回显)
// 2026-10-04 i18n: 模块名词条键(rp.mod*), 渲染期 t() 解析
const RAW_MOD_KEYS = { capture: 'rp.modCapture', scan: 'rp.modScan', weakpass: 'rp.modWp', monitor: 'rp.modMonitor', penta: 'rp.modPenta', merged: 'rp.modMerged' }
function rawModLabel(m) { return RAW_MOD_KEYS[m] ? t(RAW_MOD_KEYS[m]) : m }
function rawModKey(m) { return RAW_MOD_KEYS[m] ? m : 'other' }

// 关键统计列: 各模块的条目数口径不同, 按模块拼一行
function rawStatsText(r) {
  const s = r.stats || {}
  const ex = s.extra || {}
  switch (r.module) {
    case 'capture': return s.items != null ? t('rp.sPkt', { n: s.items }) : '-'
    case 'scan': return s.items != null ? t('rp.sVuln', { n: s.items }) + (ex.assets != null ? ' / ' + t('rp.sAsset', { n: ex.assets }) : '') + (ex.alive != null ? ' / ' + t('rp.sAlive', { n: ex.alive }) : '') : '-'
    case 'weakpass': return s.items != null ? t('rp.sTarget', { n: s.items }) + (ex.found != null ? ' / ' + t('rp.sHit', { n: ex.found }) : '') : '-'
    case 'monitor': return s.items != null ? t('rp.sTarget', { n: s.items }) + (ex.online != null ? ' / ' + t('rp.sOnline', { n: ex.online }) : '') + (ex.ok != null ? ' / ' + t('rp.sOk', { n: ex.ok }) : '') : '-'
    case 'merged': return s.items != null ? t('rp.sTotal', { n: s.items }) : '-'
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
  if (rawF.job) p.set('job', rawF.job)
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
        jobs: d.jobs || [],
        dateRange: d.dateRange || { from: '', to: '' }
      }
      // 2026-10-02 用户口径: 筛选选项基于当前数据里存在的 —— 已选中的来源/作业
      // 对应数据被删光后选项消失, 筛选要自动清除, 否则 select 无匹配 option、
      // 列表卡死为空还查不出来
      let reset = false
      if (rawF.module && !rawOptions.value.modules.some(m => m.id === rawF.module)) { rawF.module = ''; reset = true }
      if (rawF.job && !rawOptions.value.jobs.includes(rawF.job)) { rawF.job = ''; reset = true }
      if (reset) loadRaw()
    }
  } catch (e) { /* 选项失败不影响列表 */ }
}

function resetRawFilter() {
  Object.assign(rawF, { module: '', tag: '', asset: '', from: '', to: '', keyword: '', job: '' })
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
  if (!confirm(t('rp.delRawConfirm', { title: r.title }))) return
  try {
    await v2('/raw/' + r.id, { method: 'DELETE' })
    rawSel.value = rawSel.value.filter(id => id !== r.id)
    loadRaw()
  } catch (e) { alert(e.message) }
}

// 2026-09-26: 批量删除选中的原始报告(走 /raw/batch-delete, 后端上限 500/次)
async function rawBatchDel() {
  const n = rawSel.value.length
  if (!n) return
  if (n > 500) { alert(t('rp.max500')); return }
  if (!confirm(t('rp.batchDelConfirm', { n }))) return
  rawBusy.value = true
  try {
    const r = await v2('/raw/batch-delete', {
      method: 'POST',
      body: { ids: [...rawSel.value] }
    })
    rawSel.value = []
    alert(t('rp.deletedN', { n: r.deleted || 0 }))
    loadRaw()
  } catch (e) { alert(e.message) } finally { rawBusy.value = false }
}

async function mergeRaw() {
  if (rawSel.value.length < 2) { alert(t('rp.need2Raw')); return }
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
  if (!d || !d.payload) return t('rp.noBody')
  const p = typeof d.payload === 'string' ? JSON.parse(d.payload) : d.payload
  const s = JSON.stringify(p, null, 2)
  return s.length > 200000 ? s.slice(0, 200000) + '\n... ' + t('rp.truncated') : s
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
// 资产拓扑(2026-09-25 用户口径: 拓扑 = 原始报告里资产信息的列表化, 只做子表)。
// 数据源: payload.assets(资产+端口) + payload.ports(端口明细) + payload.findings(按 host 归漏洞数)。
// 合并键 = IP, 端口取并集, 漏洞数按该 IP 命中的 finding 计数。
const rawTopo = computed(() => {
  const d = rawDetail.value
  const p = rawP.value
  if (!d || !p) return []
  if (d.module === 'scan') {
    const byIp = {}
    const order = []
    const put = (ip) => {
      if (!ip || byIp[ip]) return
      byIp[ip] = { ip, hostname: '', os: '', ports: new Set(), vulns: 0 }
      order.push(ip)
    }
    for (const a of (p.assets || [])) {
      put(a.ip)
      if (!byIp[a.ip]) continue
      if (!byIp[a.ip].hostname && a.hostname) byIp[a.ip].hostname = a.hostname
      if (!byIp[a.ip].os && a.os) byIp[a.ip].os = a.os
      for (const pt of (a.ports || [])) byIp[a.ip].ports.add(pt)
    }
    for (const ip of Object.keys(p.ports || {})) {
      put(ip)
      if (!byIp[ip]) continue
      for (const rec of (p.ports[ip] || [])) byIp[ip].ports.add(rec.port)
    }
    for (const f of (p.findings || [])) {
      const ip = (f.host || '').split(':')[0].trim()
      if (ip && byIp[ip]) byIp[ip].vulns++
    }
    return order.map(ip => {
      const x = byIp[ip]
      return { ip, hostname: x.hostname, os: x.os, ports: [...x.ports].sort((a, b) => a - b), vulns: x.vulns }
    })
  }
  if (d.module === 'weakpass') {
    const byIp = {}
    const order = []
    for (const r of (p.results || [])) {
      const ip = (r.host || '').split(':')[0].trim()
      if (!ip) continue
      if (!byIp[ip]) { byIp[ip] = { ip, hostname: '', os: '', ports: new Set(), vulns: 0 }; order.push(ip) }
      if (r.port) byIp[ip].ports.add(r.port)
      if (r.ok) byIp[ip].vulns++
    }
    return order.map(ip => {
      const x = byIp[ip]
      return { ip, hostname: x.hostname, os: x.os, ports: [...x.ports].sort((a, b) => a - b), vulns: x.vulns }
    })
  }
  return []
})
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
  loadJobList()
  // 从"扫描作业"页跳来带 job 参数: 预选该作业并清空时间窗(否则默认 6 天窗会把
  // 更早作业的结果滤光, 报告反而空)
  if (route.query.job) {
    form.f.jobIds = [route.query.job]
    form.f.from = ''
    form.f.to = ''
  }
  // 资产树联动深链(2026-09-28): ?rawId=<id> 直接打开某份原始报告详情(扫描快照
  // 节点"查看报告"入口); ?asset=<ip> 预填资产筛选(资产行"原始报告"入口)。
  if (route.query.asset) rawF.asset = String(route.query.asset)
  if (route.query.rawId) {
    tab.value = 'raw'
    loadRaw()
    viewRaw({ id: String(route.query.rawId) })
  }
  window.addEventListener('keydown', onDrawerKeydown)
})
// 选了任务(任务名)即清空时间窗: "按任务名生成"的语义是取该作业全部结果,
// 默认时间窗(6 天)会把更早的作业数据滤掉。用户仍可在高级筛选里手动加回时间窗。
// (多选数组需 deep:true 才能捕获 checkbox 增删)
watch(() => form.f.jobIds, (ids) => {
  if (ids && ids.length) {
    form.f.from = ''
    form.f.to = ''
  }
}, { deep: true })

onBeforeUnmount(() => {
  closeDrawer() // 回收 blob URL, 关抽屉
  window.removeEventListener('keydown', onDrawerKeydown)
})
</script>

<style scoped>
.job-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.job-chips .chip-x { cursor: pointer; margin-left: 4px; color: var(--muted); }
.job-chips .chip-x:hover { color: var(--danger, #ef4444); }
.tabs { display: flex; gap: 6px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
.tab { background: var(--panel); border: 1px solid var(--line); color: var(--muted);
  padding: 7px 16px; border-radius: 8px; cursor: pointer; font-size: 13px; }
.tab.on { background: var(--accent); border-color: var(--accent); color: #fff; }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 10px 16px; }
.form-grid label { display: flex; flex-direction: column; gap: 4px; font-size: 12.5px; color: var(--muted); }
.form-grid label.wide { grid-column: 1 / -1; }
.form-grid label.chk { flex-direction: row; align-items: center; gap: 6px; padding-top: 20px; }
.block-title { font-size: 13px; font-weight: 600; margin: 18px 0 10px; padding-left: 9px;
  border-left: 3px solid var(--accent); }
/* 预览抽屉(2026-09-25 二轮: "像抽屉一样打开页面看"): 右侧全高 + iframe。
   报告 HTML 自带 max-width 居中版式, 抽屉给足宽度(92vw/1150px)后观感才不挤。 */
.drawer-mask { position: fixed; inset: 0; background: rgba(8, 12, 22, .55); z-index: 90; }
.drawer { position: fixed; top: 0; right: 0; bottom: 0; width: min(92vw, 1150px);
  background: #f8fafc; display: flex; flex-direction: column; box-shadow: -8px 0 32px rgba(0,0,0,.35); }
.drawer-head { display: flex; align-items: center; gap: 10px; padding: 10px 14px;
  background: rgba(11, 17, 30, .94); color: #fff; border-bottom: 1px solid var(--border); }
.drawer-title { font-size: 13px; max-width: 60%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.drawer-body { flex: 1; min-height: 0; background: #fff; }
.drawer-body iframe { width: 100%; height: 100%; border: 0; display: block; }
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
/* 封面 logo 上传框(浮窗内用) */
.doc-logo { width: 300px; height: 96px; margin: 0 auto 16px; border: 1.5px dashed #d1d5db;
  border-radius: 8px; display: flex; align-items: center; justify-content: center;
  cursor: pointer; position: relative; background: #fafafa; }
.doc-logo:hover { border-color: var(--accent); background: #f5f7ff; }
.doc-logo.has { border-style: solid; background: #fff; }
.doc-logo img { max-width: calc(100% - 16px); max-height: calc(100% - 16px); object-fit: contain; }
.doc-logo .busy { color: var(--accent); }
.doc-logo-x { position: absolute; top: -9px; right: -9px; width: 20px; height: 20px; border-radius: 50%;
  border: 0; background: #ef4444; color: #fff; font-size: 13px; line-height: 1; cursor: pointer; padding: 0; }
/* 模板编辑浮窗(2026-09-25 三轮; 2026-09-26 四轮深色化: 原来整窗纯白, 深色主题下
   长时间编辑刺眼 —— 外壳跟随主题深色, 只有中间那张纸是白的, 像 WPS 的"灰底白纸") */
.tpl-mask { position: fixed; inset: 0; background: rgba(4, 8, 14, .72); z-index: 95;
  display: flex; align-items: center; justify-content: center; padding: 3vh 3vw; }
.tpl-modal { background: var(--panel); color: var(--text); border: 1px solid var(--border2);
  border-radius: 12px; width: min(1320px, 96vw);
  max-height: 94vh; display: flex; flex-direction: column;
  box-shadow: 0 18px 60px rgba(0, 0, 0, .55); }
.tpl-head { display: flex; align-items: center; gap: 10px; padding: 10px 14px; flex-wrap: wrap;
  border-bottom: 1px solid var(--border2); }
.tpl-head .input.xs { width: 190px; height: 26px; font-size: 12.5px; }
.head-field { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--muted); }
/* 顶栏主题色入口: 一个色块按钮 + 点开的色板弹层(顶栏只占 26px, 不铺一片亮色块) */
.head-accent { position: relative; display: inline-flex; }
.accent-btn { width: 26px; height: 26px; border-radius: 6px; border: 1px solid var(--border2); cursor: pointer; padding: 0; }
/* popover(主题色/字色/底色共用): 深色卡片, 不刺眼 */
.pop {
  position: absolute; top: 32px; left: 0; z-index: 30; min-width: 200px;
  background: var(--panel2); border: 1px solid var(--border2); border-radius: 10px;
  padding: 10px; box-shadow: 0 12px 32px rgba(0, 0, 0, .5);
}
.pop-title { font-size: 12px; color: var(--muted); margin-bottom: 8px; }
.pop-custom { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted); margin-top: 8px; }
.tpl-body { flex: 1; min-height: 0; display: flex; gap: 14px; padding: 12px 14px 14px;
  overflow: hidden; background: var(--bg); }
/* 侧栏与画布: DOM 顺序是 侧栏→画布, 视觉顺序用 order 翻成 画布(左, 大) + 侧栏(右, 窄) */
.tpl-left { order: 2; width: 400px; flex: none; min-width: 0; overflow-y: auto; }
.tpl-preview-wrap { order: 1; flex: 1; min-width: 0; min-height: 0; display: flex; flex-direction: column; }
.tpl-preview-title { font-size: 12px; margin-bottom: 6px; flex: none; color: var(--muted); }
/* A4 纸: 白纸 + 投影。纸面保持白(报告就是白纸, 预览必须所见即所得), 用 #fdfdfd
   略柔化; 周围是深色编辑底, 整体亮度比"整窗纯白"低得多 */
.tpl-page {
  flex: 1; min-height: 0; overflow-y: auto;
  background: #fdfdfd; color: #1f2937; font-size: 12px;
  border: 1px solid #33415c; border-radius: 6px;
  box-shadow: 0 10px 34px rgba(0, 0, 0, .5);
  padding: 22px 20px;
}
.tp-cover { text-align: center; padding: 8px 0 16px; border-bottom: 2px solid #e5e7eb; margin-bottom: 12px; }
.tp-logo img { max-height: 48px; max-width: 160px; }
.tp-title { font-size: 20px; font-weight: 700; color: var(--tp-accent, #1F3A5F); margin: 16px 0 8px; line-height: 1.5; }
.tp-sub { font-size: 13px; color: #4b5563; margin-bottom: 12px; line-height: 1.6; }
.tp-client { font-size: 13px; margin-bottom: 10px; }
.tp-risk { font-size: 12.5px; margin-bottom: 14px; }
.tp-meta { font-size: 12px; color: #374151; line-height: 2; }
.tp-body { padding-top: 2px; }
.tp-header { font-size: 11px; color: #6b7280; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; margin-bottom: 10px; }
.tp-sec { margin-bottom: 12px; }
.tp-sec-title { font-size: 13px; font-weight: 700; color: var(--tp-accent, #1F3A5F); margin-bottom: 4px; }
.tp-sec-no { margin-right: 6px; }
.tp-sec-body { border: 1px dashed #dcdfe5; border-radius: 6px; padding: 9px 8px; background: #fafafa; }
.tp-line { height: 7px; border-radius: 3px; background: #e8eaee; margin-bottom: 6px; }
.tp-line:nth-child(2) { width: 88%; }
.tp-line:nth-child(3) { width: 70%; }
.tp-note { margin-top: 5px; font-size: 10.5px; }
.tp-tail { font-size: 10.5px; color: #6b7280; border-top: 1px solid #e5e7eb; padding-top: 8px; margin-top: 10px; line-height: 1.7; }
.tp-footer { font-size: 10.5px; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 6px; margin-top: 10px; }
.tpl-foot { display: flex; align-items: center; gap: 8px; padding: 12px 16px;
  border-top: 1px solid var(--line); background: #f8fafc; border-radius: 0 0 12px 12px; }
.tpl-cover { border: 1px dashed var(--line); border-radius: 10px; padding: 14px; margin-bottom: 14px;
  background: #fafbfc; }
.tpl-field { margin-bottom: 12px; }
.tpl-field-label { font-size: 12px; color: var(--muted); margin-bottom: 5px; letter-spacing: .3px; }
/* 风格预设(WPS 式整套配色): 深色卡片 + 顶部细色条, 不像色板那样铺一片亮色块 */
.style-presets { display: flex; flex-wrap: wrap; gap: 8px; }
.style-sw {
  display: inline-flex; flex-direction: column; align-items: stretch;
  width: 72px; border: 1px solid var(--border2); border-radius: 8px; overflow: hidden;
  cursor: pointer; background: var(--panel2); padding: 0; transition: border-color .15s, box-shadow .15s;
}
.style-sw:hover { border-color: var(--border2); filter: brightness(1.08); }
.style-sw.on { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(56, 189, 248, .25); }
.style-sw-bar { height: 22px; }
.style-sw-name { font-size: 11px; color: var(--muted); text-align: center; padding: 3px 2px; line-height: 1.2; }
.style-sw.on .style-sw-name { color: var(--accent); }
.tpl-time { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.gen-filter { border: 1px solid var(--line); border-radius: 8px; padding: 8px 14px; margin-bottom: 8px; }
.gen-filter summary { cursor: pointer; font-size: 12.5px; color: var(--muted); user-select: none; }
.gen-filter[open] summary { margin-bottom: 10px; }
/* 模板列表里的"logo"角标 / "内置"角标 */
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
/* 可视化排版编辑器: 章节行(序号 + 勾选 + 标题 + 排序按钮) */
.vis-sec-list { border: 1px solid var(--border2); border-radius: 8px; overflow: hidden; }
/* 2026-09-25 三轮: 行改两排 —— 上排 勾选/标题/排序, 下排 逐章节字体样式
   (字体颜色/底色/格式, 内容不可改) */
.vis-sec-row {
  display: flex; flex-direction: column; gap: 6px;
  padding: 6px 12px; border-bottom: 1px solid var(--border2);
}
.vis-sec-main { display: flex; gap: 10px; align-items: center; }
.vis-sec-row:last-child { border-bottom: none; }
.vis-sec-row:nth-child(odd) { background: var(--panel2); }
/* 选中态: 左侧章节行 与 右侧画布章节 双向联动("点哪改哪") */
.vis-sec-row.row-on { background: rgba(56, 189, 248, .1); box-shadow: inset 2px 0 0 rgba(56, 189, 248, .9); }
.tp-sec { cursor: pointer; border-radius: 6px; }
.tp-sec.sec-on { outline: 2px solid rgba(56, 189, 248, .9); outline-offset: 3px; }
/* 版面里的行内编辑块: 虚线提示"这里能直接改" */
.tp-inline { display: inline-block; min-width: 80px; border-bottom: 1px dashed var(--border2); }
.tp-cover-off {
  border: 1px dashed var(--border2); border-radius: 8px;
  padding: 10px 12px; margin-bottom: 12px; font-size: 12.5px;
}
/* 主题色/字色/底色 色板 */
.swatches { display: flex; flex-wrap: wrap; gap: 6px; }
.sw { width: 24px; height: 24px; padding: 0; border-radius: 6px; cursor: pointer; border: 2px solid transparent; }
.sw.on { border-color: var(--text); }
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

<template>
  <!-- TopoScene2D: 2D 平面拓扑网络地图(第四阶段, 2026-09-29; 2026-09-30 多视图重构)。
       与 3D 场景(TopoScene)共用同一份 nodes/links —— 同一份 ref, 状态/绑定实时同步。
       能力: ①自由摆位: 节点 n.px/n.py(属于当前视图)优先, 未摆位按 autoPos 自动网格,
             拖拽/右键可重置  ②自由框: 画布右键/按钮添加, 拖拽移动/拉角缩放/点击选中/
             双击改名/右键删除(纯视觉组织, 浏览态不响应)  ③框选多选: 编辑态左键拖空白
             框选多台设备/多框(Ctrl+点击增删), 拖任一选中项=整体移动, 选区右下角手柄
             =同步放大缩小整组; 平移=Shift+左键/中键拖  ④按网段折叠→汇总节点
             (数量+整体状态), 双击钻取进入子网、面包屑逐级返回  ⑤右下角全局概览小窗
             (点区域快速定位)  ⑥低缩放光点/标签降采样, 支撑 500+ 节点流畅缩放。
       渲染 = 原生 SVG(单 <g> 做平移缩放), 节点=圆+类型字形+名称, 链路=贝塞尔(主用实线/备用·中断虚线)。
       关键: 2D 坐标用视图内 px/py, 绝不写回共享 node.x/y —— 那是 3D 演示视图的坐标。 -->
  <div class="t2d" :class="[mode, { dragging: nodeDragging }]" @contextmenu.prevent.stop="openMenu($event, null)">
    <!-- 画布 -->
    <div ref="stageEl" class="t2d-stage" :class="{ linking: linkFrom }"
         :title="mode === 'edit' ? '左键拖空白=框选设备/框(整体移动·右下角手柄整体缩放) · Shift+左键或中键拖=平移 · 滚轮=缩放' : ''"
         @pointerdown="onSceneDown" @wheel.prevent="onWheel" @auxclick.prevent
         @dblclick.self="onBlankDblClick"
         @dragover.prevent="onLibDragOver" @drop.prevent="onLibDrop">
      <svg class="t2d-svg" ref="svgEl" :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="xMidYMid meet">
        <g :transform="worldTf">
          <!-- 自由框(2026-09-30 用户要求: 画布右键/按钮下拉添加; 可拖拽移动/拉角缩放/
               点击选中(同设备, 属性面板改名等)/双击标签改名/右键删除)。
               框是纯组织元素(视觉上圈住设备), 无自动布局行为; 层在链路/节点之下:
               框内点设备优先命中设备, 点框空白区域才选中框。 -->
          <g v-if="!drilled">
            <g v-for="b in props.boxes" :key="b.id" class="t2d-box"
               :class="{ sel: selBox === b.id, 'in-sel': selSet.has('b:' + b.id) }"
               :transform="`translate(${b.x}, ${b.y})`"
               @pointerdown.stop="onBoxDown($event, b)" @click.stop="onBoxClick($event, b)"
               @dblclick.stop="startRenameBox(b)"
               @contextmenu.stop.prevent="openMenu($event, null, null, b)">
              <!-- 2026-09-30 用户要求: 框边框(线型/线宽/颜色)与背景(颜色/透明度/无)可自定义, 标签可拖拽随意放置 -->
              <rect :width="b.w" :height="b.h" rx="10" class="t2d-box-rect" :style="boxRectStyle(b)" />
              <text :x="b.lx ?? 12" :y="b.ly ?? 24" class="t2d-box-label" :style="boxLabelStyle(b)"
                    @pointerdown.stop="onLabelDown($event, b)">{{ b.name }}</text>
              <!-- 右下角缩放手柄(编辑态): 拖拽拉大/缩小该框 -->
              <rect v-if="mode === 'edit'" :x="b.w - 14" :y="b.h - 14" width="14" height="14" rx="3"
                    class="t2d-box-resize" :title="'拖拽调整「' + b.name + '」大小'"
                    @pointerdown.stop="onBoxResizeStart($event, b)" />
            </g>
          </g>

          <!-- 链路: 颜色=连通状态(实测), 推测边(系统按网段猜的, 未经实测)细虚线区分。
               2026-10-01 用户口径"通断和速率必须可信, 不要编造": ①线上速率标签与流动
               光点整体删除 —— 线上显示的速率是"端点设备的总上下行"不是这条链路的流量
               (交换机~路由器线上标交换机速率=误导), 速率移到设备节点(真实归属);
               ②推测边不显示绿/红(后端"两端设备健康"曾被误读成"两端直连")。 -->
          <path v-for="l in visibleLinks" :key="'p' + l.linkId" :id="'t2d_' + l.linkId" :d="pathOf(l)"
                :class="['t2d-link', l.status, (l.kind === 'backup' ? 'backup' : ''), (linkUntested(l) ? 'untested' : ''), (isInferred(l) ? 'inferred' : '')]"
                :style="linkStyle(l)" fill="none" />
          <!-- 连线流动光效(2026-10-02 用户问"连线实时光效有吗?"): 仅"绑定端口且有真实流量"的线画
               流动光点(boundPortRate=该口真实速率, 15s 一拍) —— 2026-10-01 删除口径依然成立:
               未绑端口的线没有流量归属, 不给光点(不编造); 绑了端口后速率就是本链路真实
               流量, 光效才有归属依据。流速∝端口速率(快线流光快); 低缩放降采样同口径。
               2026-10-02 v255: 显隐改由独立"连线光效"勾选(displayCfg.flow)控制 —— 此前
               挂在"速率"勾选上, 用户关光效连带把设备名字下速率标签关了(用户报"设备上的
               速率不显示了") -->
          <path v-for="l in visibleLinks" :key="'f' + l.linkId" v-show="!lowZoom && displayCfg.flow && linkFlowDur(l)"
                :d="pathOf(l)" class="t2d-flow" :style="{ animationDuration: linkFlowDur(l) }" fill="none" />
          <path v-for="l in visibleLinks" :key="'h' + l.linkId" :d="pathOf(l)" class="t2d-hit"
                :title="linkTip(l)"
                @click.stop="onLinkClick(l)" @pointerdown.stop @contextmenu.stop.prevent="openMenu($event, null, l)" />
          <!-- 端口绑定标签(2026-10-02 v258 用户: "起始端口和终止端口为什么是一排?? 不是两个
               吗? 一个是靠近起始端口的设备, 另一个靠近终止端口的设备"): 原单个合并标签
               (两端用 ⇄ 拼一行)拆成两个独立标签 —— 起始端标签贴起始设备端(沿线下 22%),
               终止端标签贴终止设备端(沿线下 78%), 各自显该端"口名(或别名) ↑↓"(真实
               上下行, 与设备速率标签同口径, 取不到不显示); 未绑定的端不画。显隐受顶部
               "显示"勾选 displayCfg.port 控制。
               编辑态: ①两个标签可各自独立拖动(l.fromLblPos/l.toLblPos 世界坐标, 随视图
               文档持久化; 复位在右键菜单, 各端独立) ②标签是一等可点元素(事件隔离):
               点=选中链路开属性面板 ③双击=改该端端口别名(l.fromAlias/l.toAlias 随视图
               文档持久化; 别名只换名字部分, 后面的实时速率照常 15s 刷新) -->
          <template v-for="l in visibleLinks" :key="'pl' + l.linkId">
            <text v-show="!lowZoom && displayCfg.port && l.fromPort"
                  :x="portLabelPos(l, 'from').x" :y="portLabelPos(l, 'from').y"
                  class="t2d-portlabel" text-anchor="middle"
                  :style="props.mode === 'edit' ? { cursor: 'move' } : {}"
                  :title="props.mode === 'edit' ? '拖动=移动位置; 双击=改起始端口别名; 单击=打开链路属性' : '端口绑定(起始端)'"
                  @pointerdown.stop="onPortLabelDown($event, l, 'from')"
                  @click.stop="onPortLabelClick(l)"
                  @dblclick.stop="onPortLabelDblClick($event, l, 'from')">{{ portEndText(l.fromPort, l.fromDeviceId, l.fromAlias) }}</text>
            <text v-show="!lowZoom && displayCfg.port && l.toPort"
                  :x="portLabelPos(l, 'to').x" :y="portLabelPos(l, 'to').y"
                  class="t2d-portlabel" text-anchor="middle"
                  :style="props.mode === 'edit' ? { cursor: 'move' } : {}"
                  :title="props.mode === 'edit' ? '拖动=移动位置; 双击=改终止端口别名; 单击=打开链路属性' : '端口绑定(终止端)'"
                  @pointerdown.stop="onPortLabelDown($event, l, 'to')"
                  @click.stop="onPortLabelClick(l)"
                  @dblclick.stop="onPortLabelDblClick($event, l, 'to')">{{ portEndText(l.toPort, l.toDeviceId, l.toAlias) }}</text>
          </template>

          <!-- 折叠的子网汇总节点(数量 + 整体状态色) -->
          <g v-for="s in summaryNodes" :key="'s' + s.key" class="t2d-summary"
             :transform="`translate(${s.x}, ${s.y})`"
             @pointerdown.stop
             @click.stop="onSummaryClick(s)" @dblclick.stop="drillIn(s.key)"
             @contextmenu.stop.prevent="openMenu($event, s)">
            <rect :width="SUM_W" :height="SUM_H" :x="-SUM_W / 2" :y="-SUM_H / 2" rx="10" :class="'sum-' + s.status" />
            <text class="sum-ico" text-anchor="middle" y="-9">▤</text>
            <text class="sum-cidr" text-anchor="middle" y="10">{{ s.label }}</text>
            <text class="sum-count" text-anchor="middle" y="26">{{ t('topo.devUnit', { n: s.count }) }} · {{ s.statusCn }}</text>
          </g>

          <!-- 节点(圆 + 类型字形 + 名称) -->
          <g v-for="n in visibleNodes" :key="n.nodeId" class="t2d-node"
             :class="[n.status, 'safe-' + safeStatus(n), { core: !!n.isCore, sel: selNode === n.nodeId, manual: n.px != null, 'link-src': linkFrom === n.deviceId }]"
             :transform="`translate(${posOf(n.deviceId).x}, ${posOf(n.deviceId).y})`"
             @pointerdown.stop="onNodeDown($event, n)" @click.stop="onNodeClick($event, n)"
             @dblclick.stop="onNodeDblClick(n)" @mouseenter="onNodeHover($event, n)" @mouseleave="hover = null"
             @contextmenu.stop.prevent="openMenu($event, n)">
            <circle v-if="n.isCore" r="26" class="t2d-core" />
            <circle r="19" class="t2d-ico" :class="'t-' + n.type" :style="{ stroke: safeColor(n) }" />
            <text class="t2d-glyph" text-anchor="middle" dy="6">{{ typeGlyph(n.type) }}</text>
            <circle v-if="!lowZoom" r="5" cx="14" cy="14" class="t2d-led" :style="{ fill: safeColor(n) }" />
            <text v-if="!lowZoom && displayCfg.name" class="t2d-name" text-anchor="middle" y="34">{{ n.name }}</text>
            <!-- 设备真实上下行速率(SNMP 两帧差分, 设备自身的数据; 无数据不显示)。
                 2026-10-01 用户口径: 速率从线上移到设备 —— 线上的"速率"是端点设备
                 总上下行不是本链路流量(误导); 名字下方同坐标系渲染, 随视图缩放
                 与设备名同步放大缩小(用户: "速率文字不能像设备名字一样同步缩小吗") -->
            <text v-if="!lowZoom && displayCfg.rate && nodeRateText(n)" class="t2d-nrate" text-anchor="middle" y="47">{{ nodeRateText(n) }}</text>
            <!-- 流量环: 设备有真实上下行流量 → 绕节点流动光圈(速率越高转越快); 无流量不画;
                 随"速率"勾选一起显隐(环是速率的可视化表达) -->
            <circle v-if="!lowZoom && displayCfg.rate && nodeBusy(n)" r="24" class="t2d-ring" :style="ringStyle(n)">
              <animateTransform attributeName="transform" type="rotate" from="0" to="360" :dur="ringDur(n)" repeatCount="indefinite" />
            </circle>
          </g>

          <!-- 框选矩形(2026-09-30 用户要求: 左键拖空白多选设备/框, 世界坐标随视图缩放) -->
          <rect v-if="marquee" class="t2d-marquee" :x="marquee.x" :y="marquee.y" :width="marquee.w" :height="marquee.h" />
          <!-- 选区包围盒(≥2 项选中时): 右下角手柄=同步放大缩小整组(节点位置/框宽高按同比例) -->
          <g v-if="selBBox" class="t2d-selgroup">
            <rect class="t2d-selgroup-rect" :x="selBBox.x" :y="selBBox.y" :width="selBBox.w" :height="selBBox.h" />
            <rect v-if="!groupScaling" class="t2d-selgroup-handle"
                  :x="selBBox.x + selBBox.w - 13" :y="selBBox.y + selBBox.h - 13" width="14" height="14" rx="3"
                  :title="'拖拽整体缩放选中的 ' + selBBox.count + ' 项(同步放大/缩小)'"
                  @pointerdown.stop="onGroupScaleStart($event)" />
            <text v-if="groupScaling" class="t2d-selgroup-size"
                  :x="selBBox.x + selBBox.w + 10" :y="selBBox.y + selBBox.h + 4">{{ Math.round(selBBox.w) }} × {{ Math.round(selBBox.h) }}</text>
          </g>
        </g>
      </svg>

      <!-- 面包屑(钻取导航): 只在钻入子网后显示。
           2026-10-02 用户要求: 常驻"全部"按钮移除(全局视图下无意义, 值守画面干净);
           钻取中保留"全部 / 网段"回退入口(双击画布空白同样回退)。
           @pointerdown.stop: 浮层在舞台内, 事件不隔离会冒泡到舞台 onSceneDown →
           startPan → 松手判"点空白" → cancelLink(连线被取消)+blank-click(面板被关)
           —— 2026-10-02 用户实测"一点下拉区域就没有了"即此路径。 -->
      <div v-if="drilled" class="t2d-crumb" @pointerdown.stop>
        <button type="button" class="t2d-crumb-btn" @click="drillOut">{{ t('topo.all') }}</button>
        <span class="t2d-crumb-sep">/</span>
        <span class="t2d-crumb-cur">{{ drilledLabel }}</span>
      </div>

      <!-- 画线选网口浮层(2026-10-02 用户要求: 右键连线时就能选网口):
           非阻塞小条(画布照常点击, 不选=未绑定, 事后可在属性面板补绑)。
           from=进入连线态时选本端口; to=点目标成链后选对端口。
           选项=两端真实端口清单(fetchNodePorts 三数据源+同 IP 兜底), 无数据只有
           "未绑定"+原因说明(不编造端口)。不用 prompt(自动化环境会阻塞渲染)。 -->
      <div v-if="portPick" class="t2d-portpick" @pointerdown.stop>
        <span class="pp-t">{{ (portPick.stage === 'from' ? '本端网口 ' : '对端网口 ') + (portPick.node ? portPick.node.name : '') }}</span>
        <select :value="portPick.stage === 'from' ? linkFromPort : portPickVal"
                @change="portPick.stage === 'from' ? (linkFromPort = $event.target.value) : (portPickVal = $event.target.value)">
          <option value="">{{ t('topo.unbound') }}</option>
          <option v-for="p in portPickList" :key="p.port" :value="p.port">
            {{ p.port }} ({{ p.state ? (p.up ? 'up' : 'down') : '-' }}{{ (p.rxBps || 0) + (p.txBps || 0) > 0 ? ' · ' + rateShort((p.rxBps || 0) + (p.txBps || 0)) + '/s' : '' }})
          </option>
        </select>
        <button v-if="portPick.stage === 'from'" type="button" @click="portPick = null">{{ t('topo.gotIt') }}</button>
        <template v-else>
          <button type="button" class="pp-ok" @click="confirmToPort">{{ t('topo.ok') }}</button>
          <button type="button" @click="skipToPort">{{ t('topo.skip') }}</button>
        </template>
        <div v-if="portPickNote" class="pp-note">{{ portPickNote }}</div>
      </div>

      <!-- 悬浮详情卡 -->
      <div v-if="hover" class="t2d-hover" :style="hoverStyle">
        <div class="th-h"><b>{{ hover.name }}</b><span class="th-st" :class="'st-' + hover.status">{{ t(STATUS_CN[hover.status] || hover.status) }}</span></div>
        <div class="th-row"><span>{{ t('cfg.kind') }}</span><i>{{ typeText(hover.type) }}</i></div>
        <div class="th-row"><span>IP</span><i class="th-ip">{{ hover.ip || '—' }}</i></div>
        <div class="th-row"><span>{{ t('topo.bandwidthUtil') }}</span><i>{{ hover.utilText }}</i></div>
        <div class="th-row" v-if="hover.rateText"><span>{{ t('topo.upDownRate') }}</span><i>{{ hover.rateText }}</i></div>
        <div class="th-row" v-else-if="hover.rateNote"><span>{{ t('topo.upDownRate') }}</span><i class="th-note">{{ hover.rateNote }}</i></div>
      </div>

      <!-- 框改名 / 端口别名改名(编辑态双击): 输入框悬浮在标签锚点处, Enter/失焦提交 -->
      <div v-if="renaming" class="t2d-rename"
           :class="renaming.kind === 'box' ? 'rn-left' : 'rn-center'"
           :style="{ left: renaming.x + 'px', top: renaming.y + 'px' }">
        <input :value="renaming.name" :placeholder="renaming.kind === 'port' ? '端口别名(留空=清除)' : '分组名称'"
               @keyup.enter="commitRename" @blur="commitRename"
               @pointerdown.stop @dblclick.stop @focus="e => e.target.select()" />
      </div>
    </div>

    <!-- 快捷控件: 查看/缩放 + 子网折叠/展开(查看操作, 双模式可用) -->
    <!-- 2026-10-03: 全屏时整体隐藏(用户: "全屏时右上角的复位放大缩小的按钮框就不要显示, 连缩放也没有");
         滚轮缩放/右键"复位视角"不受影响, 只是不占画面 -->
    <div class="t2d-ctrl" v-if="!fs">
      <button type="button" title="复位视图" @click="resetView">⌂</button>
      <button type="button" title="放大" @click="zoomBy(1.25)">＋</button>
      <button type="button" title="缩小" @click="zoomBy(0.8)">－</button>
      <span class="t2d-ctrl-sep"></span>
      <button type="button" title="折叠所有子网" @click="collapseAll">⊟</button>
      <button type="button" title="展开所有子网" @click="expandAll">⊞</button>
    </div>

    <!-- 右下角全局概览小窗: 全图区域预览, 点区域=居中定位, 拖动=移动视口;
         2026-10-01 用户反馈"左下角的框挡视线, 要能像设备树栏一样缩起来": 角上折叠按钮,
         收起后原位留小按钮(点击展开), 状态持久化 LS, 刷新页面保持原状态 -->
    <div class="t2d-mm" v-if="showMini && miniOn">
      <button type="button" class="t2d-mm-fold" title="收起概览小地图" @click.stop="toggleMini">—</button>
      <svg ref="mmSvg" :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="xMidYMid meet" @pointerdown="onMMDown" @contextmenu.prevent>
        <rect :x="0" :y="0" :width="W" :height="H" class="mm-bg" />
        <line v-for="l in displayLinks" :key="'ml' + l.linkId" class="mm-line"
              :x1="mmEnd(l, 1)" :y1="mmEnd(l, 'y1')" :x2="mmEnd(l, 2)" :y2="mmEnd(l, 'y2')" />
        <circle v-for="s in summaryNodes" :key="'ms' + s.key" class="mm-sum" :class="'led-' + s.status"
                :cx="s.x" :cy="s.y" r="40" />
        <circle v-for="n in displayNodes" :key="'md' + n.nodeId" class="mm-dot" :class="'led-' + n.status"
                :cx="posOf(n.deviceId).x" :cy="posOf(n.deviceId).y" r="22" />
        <rect v-if="mmVp" class="mm-vp" :x="mmVp.x" :y="mmVp.y" :width="mmVp.w" :height="mmVp.h" />
      </svg>
    </div>
    <!-- 收起后原位小按钮(点击展开小地图) -->
    <button type="button" v-else-if="showMini" class="t2d-mm-mini" title="展开全局概览小地图" @click="toggleMini">▦</button>

    <!-- 提示条 -->
    <div v-if="tip" class="t2d-tip">{{ tip }}</div>

    <!-- 右键菜单(节点/链路/子网/空白; 与 3D 同口径: 变更类仅编辑态) -->
    <Teleport to="body">
      <div v-if="menuOpen" class="t2d-menu" :style="menuStyle" @pointerdown.stop @click.stop>
        <template v-if="menuSummary">
          <div class="t2d-menu-h">{{ t('topo.subnet') }} · {{ menuSummary.label }}</div>
          <button type="button" @click="drillIn(menuSummary.key)">{{ t('topo.drillIn') }}</button>
          <button type="button" @click="toggleCollapse(menuSummary.key)">{{ isCollapsed(menuSummary.key) ? '展开子网' : '折叠子网' }}</button>
        </template>
        <template v-else-if="menuLink">
          <div class="t2d-menu-h">{{ t('topo.link') }} · {{ linkMenuTitle }}</div>
          <button type="button" @click="linkAction('detail')">{{ t('topo.viewDetails') }}</button>
          <!-- 连通性测试: 中心端真实探测两端 IP(2026-09-29 用户要求: 画了线不算通, 测过才算) -->
          <button type="button" @click="linkAction('check')" :disabled="menuLink._checking">
            {{ menuLink._checking ? '测试中…' : (menuLink.tested ? '重新测试连通' : '测试连通') }}
          </button>
          <template v-if="mode === 'edit'">
            <div class="t2d-menu-h">{{ t('rp.edit') }}</div>
            <!-- 端口别名(2026-10-02 v254): 画布标签改名; 标签位置复位从"双击标签"移到这里
                 (双击改成了改别名) -->
            <button v-if="menuLink.fromPort" type="button" @click="linkAction('renameFrom')">{{ t('topo.renameFrom') }}</button>
            <button v-if="menuLink.toPort" type="button" @click="linkAction('renameTo')">{{ t('topo.renameTo') }}</button>
            <!-- v258: 两端标签各自可拖 → 复位也各端独立(只在该端拖过时出现) -->
            <button v-if="menuLink.fromLblPos" type="button" @click="linkAction('resetLblFrom')">{{ t('topo.resetLblFrom') }}</button>
            <button v-if="menuLink.toLblPos" type="button" @click="linkAction('resetLblTo')">{{ t('topo.resetLblTo') }}</button>
            <button type="button" @click="linkAction('backup')">{{ menuLink.kind === 'backup' ? '设为主用链路(实线)' : '设为备用链路(虚线)' }}</button>
            <button type="button" class="danger" @click="linkAction('delete')">{{ t('topo.delLink') }}</button>
          </template>
        </template>
        <template v-else-if="menuBox">
          <div class="t2d-menu-h">{{ t('topo.box') }} · {{ menuBox.name }}</div>
          <template v-if="mode === 'edit'">
            <button type="button" @click="boxAction('rename')">{{ t('topo.renameBox') }}</button>
            <button type="button" class="danger" @click="boxAction('delete')">{{ t('topo.delBox') }}</button>
            <!-- 2026-10-01 用户要求: 框选多个后右键菜单提供批量删除(页面弹确认) -->
            <button v-if="selSet.size >= 2" type="button" class="danger" @click="deleteSelected()">{{ t('topo.delSelItems', { n: selSet.size }) }}</button>
          </template>
        </template>
        <template v-else-if="menuNode">
          <div class="t2d-menu-h">{{ menuNode.name }}</div>
          <button type="button" @click="nodeAction('detail')">{{ t('topo.viewDetails') }}</button>
          <button type="button" @click="nodeAction('alert')">{{ t('topo.cfgAlert') }}</button>
          <button type="button" @click="nodeAction('nodemon')">{{ t('topo.goNodeMon') }}</button>
          <button type="button" @click="nodeAction('drill')">{{ t('topo.portDetail') }}</button>
          <button v-if="menuNode.px != null" type="button" @click="resetPosAction">{{ t('topo.resetPos') }}</button>
          <template v-if="mode === 'edit'">
            <div class="t2d-menu-h">{{ t('rp.edit') }}</div>
            <button type="button" @click="nodeAction('link')">{{ t('topo.linkFrom') }}</button>
            <button type="button" @click="nodeAction('core')">{{ menuNode.isCore ? '取消核心标记' : '标记核心节点' }}</button>
            <button type="button" @click="nodeAction('rebind')">{{ t('topo.rebind') }}</button>
            <button type="button" class="danger" @click="nodeAction('delete')">{{ t('topo.delNode') }}</button>
            <!-- 2026-10-01 用户要求: 框选多个后右键菜单提供批量删除(页面弹确认) -->
            <button v-if="selSet.size >= 2" type="button" class="danger" @click="deleteSelected()">{{ t('topo.delSelItems', { n: selSet.size }) }}</button>
          </template>
        </template>
        <template v-else>
          <div class="t2d-menu-h">{{ t('topo.canvas') }}</div>
          <button type="button" @click="canvasAction('export')">{{ t('topo.exportImg') }}</button>
          <button type="button" @click="canvasAction('resetview')">{{ t('topo.resetView') }}</button>
          <template v-if="mode === 'edit'">
            <!-- 2026-10-01 用户要求: 框选多台设备/多框后, 对选中区域右键 → "删除选中的设备和框"(页面弹确认) -->
            <template v-if="selSet.size >= 2">
              <div class="t2d-menu-h">{{ t('topo.multiSel') }}</div>
              <button type="button" class="danger" @click="deleteSelected()">{{ t('topo.delSelAll', { n: selSet.size }) }}</button>
            </template>
            <div class="t2d-menu-h">{{ t('topo.add') }}</div>
            <!-- 2026-09-30 用户要求: 画布右键直接添加框/设备库设备(落点=右键处) -->
            <button type="button" @click="canvasAction('addbox')">{{ t('topo.addBoxHere') }}</button>
            <div class="t2d-menu-item sub">
              <span>{{ t('topo.addDevice') }}</span>
              <div class="t2d-submenu">
                <template v-for="g in deviceTypes" :key="g.key">
                  <div class="t2d-sub-h">{{ t(g.label) }}</div>
                  <button v-for="dt in g.items" :key="dt.v" type="button" @click="canvasAction('adddevice', dt.v)">
                    {{ dt.glyph }} {{ t(dt.t) }}
                  </button>
                </template>
              </div>
            </div>
            <div class="t2d-menu-h">{{ t('topo.ops') }}</div>
            <button type="button" @click="collapseAll">{{ t('topo.collapseAll') }}</button>
            <button type="button" @click="expandAll">{{ t('topo.expandAll') }}</button>
            <button v-if="hasManualPos" type="button" @click="resetAllPosAction">{{ t('topo.resetAllPos') }}</button>
          </template>
        </template>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, computed, nextTick, watch, onMounted, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import {
  W, H, typeGlyph, typeText, safeStatus, safeColor,
  LINK_COLOR, STATUS_CN, SAFE_CN, TYPES, TYPE_GROUPS, TOPO_TYPE_MIME,
  groupBySubnet, subnetKey, subnetStatus,
} from './topoModel.js'
import { t } from '../../i18n'
// 右键"添加设备…"子菜单按分组展开(TYPE_GROUPS 只有 key/label, 这里补 items)
const deviceTypes = computed(() => TYPE_GROUPS.map(g => ({
  key: g.key,
  label: g.label,
  items: Object.keys(TYPES).filter(v => TYPES[v].group === g.key)
    .map(v => ({ v, t: TYPES[v].t, glyph: TYPES[v].g })),
})))
import { autoPos, displayCfg } from './topoViews.js'
import { fetchNodePorts, rateShort } from './topoPorts.js'

const props = defineProps({
  nodes: { type: Array, default: () => [] },
  links: { type: Array, default: () => [] },
  // dashData 设备台账(2026-10-02: 画线选端口要按 source 分支取真实端口清单, 同 topoPorts 口径)
  devices: { type: Array, default: () => [] },
  mode: { type: String, default: 'browse' },
  // 自由框(2026-09-30 用户要求): [{id,name,x,y,w,h}] 世界坐标; 页面从当前视图取,
  // 拖拽移动/拉角缩放直接改对象(页面 watch 持久化), 改名/删除经 emit 回页面。
  boxes: { type: Array, default: () => [] },
  selBox: { type: String, default: '' },
  selNode: { type: String, default: '' },
  selLink: { type: String, default: '' },
  leftInset: { type: Number, default: 0 },
  rightInset: { type: Number, default: 0 },
  // 小地图(全局概览)开关: 独立页常开; 大屏拓扑卡空间小(小窗 180×108 占卡片 1/4), 传 false 隐藏
  showMini: { type: Boolean, default: true },
  // 2026-10-03 用户要求: 全屏(值守/大屏墙)隐藏右上角快捷控件(复位/放大/缩小/折叠/展开),
  // 独立页传 isFs; 大屏卡不传=窗口形态, 行为不变
  fs: { type: Boolean, default: false },
  // 自动适配视口(2026-09-29): 首帧节点就绪后自动 fit, 让全部拓扑完整落在画布内。
  // 解决大屏拓扑卡(480×400)加载后初始视图裁切、只看到局部的问题 —— 与 Zabbix 地图"打开即见全图"口径对齐。
  // 独立页同样受益(打开即见全拓扑), 需要自控视角的调用方可传 false。
  autoFit: { type: Boolean, default: true },
  // 低缩放隐藏阈值(2026-10-01): 独立页 500+ 节点性能门控 0.55; 大屏拓扑卡画布小(480×400),
  // fit 后 scale 常 <0.55 会把光点/速率标签全藏掉(用户反馈"大屏没有光点特效"), 传 0.3 放宽
  lowZoomScale: { type: Number, default: 0.55 },
})
const emit = defineEmits(['select', 'delete', 'drill',
  'config-alert', 'toggle-core', 'rebind', 'toggle-backup', 'export', 'blank-click',
  'drop-node', 'link-add', 'link-check',
  'add-box', 'box-rename', 'delete-box',
  'select-multi', 'dirty',
  'delete-multi'])   // delete-multi=框选批量删除[{kind:'n'|'b',id}](页面弹确认后执行)
const router = useRouter()

const stageEl = ref(null)
const svgEl = ref(null)
const mmSvg = ref(null)
const tip = ref('')
let tipT = null
function flash(s) { tip.value = s; if (tipT) clearTimeout(tipT); tipT = setTimeout(() => { tip.value = '' }, 2400) }

const SUM_W = 150, SUM_H = 58
// 2026-10-01 用户反馈"框的尺寸不能比 1100×640 再大?": 框是纯视觉组织元素, 无上限逻辑,
// 原上限(略小于世界 1200×720)导致圈不住大区域 → 上限提到 3000×1800(越界部分小地图自然裁切, 无副作用)
const BOX_W_MIN = 120, BOX_W_MAX = 3000, BOX_H_MIN = 60, BOX_H_MAX = 1800

// ===== 视图状态 =====
const viewState = ref({ tx: 0, ty: 0, scale: 1 })
const SCALE_MIN = 0.12, SCALE_MAX = 3.2
// 2026-10-01 用户反馈"左下角的框(小地图)挡视线": 小地图可折叠(与设备树栏同口径:
// 收起后原位留小按钮), 状态持久化 LS, 刷新页面保持原状态; 默认展开(旧行为)
const LS_MINI = 'yugsight_topo3d_mini'
const miniOn = ref((() => { try { return localStorage.getItem(LS_MINI) !== '0' } catch (e) { return true } })())
function toggleMini() {
  miniOn.value = !miniOn.value
  try { localStorage.setItem(LS_MINI, miniOn.value ? '1' : '0') } catch (e) { /* LS 写失败忽略 */ }
}
// 2026-09-29: 「复位视图」= 自动适配全图(而非单位变换) —— 节点在画布外
// (手动摆位持久化)时单位变换会回到"一片黑", fit 保证任何场景都"打开即见全图"
function resetView() { fitToView() }
// 自动适配: 以全部显示节点的包围盒为基准, 计算让整图完整入画布的缩放与平移。
// 折叠了子网时只算当前可见节点(显示节点的包围盒), 钻取时自然只适配该网段成员。
function fitToView() {
  const el = svgEl.value
  if (!el) return
  const list = displayNodes.value
  if (!list.length) return
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
  for (const n of list) {
    const p = posOf(n.deviceId)
    if (p.x < minX) minX = p.x
    if (p.x > maxX) maxX = p.x
    if (p.y < minY) minY = p.y
    if (p.y > maxY) maxY = p.y
  }
  if (!isFinite(minX)) return
  const bw = Math.max(1, maxX - minX), bh = Math.max(1, maxY - minY)
  const rect = el.getBoundingClientRect()
  if (!rect.width || !rect.height) return   // 容器尚未布局, 由调用方稍后重试
  const s = Math.min(SCALE_MAX, Math.max(SCALE_MIN, Math.min(rect.width / bw, rect.height / bh) * 0.9))
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2
  viewState.value = { tx: W / 2 - cx * s, ty: H / 2 - cy * s, scale: s }
}
// 自动适配两个入口(2026-09-29 用户反馈"设备总数 1, 画布一片黑"):
// ① 挂载时数据已就位(页面/卡片都是 v-else/v-if 数据就绪后才挂载本组件,
//    原 0→>0 watch 永远等不到转变, fitToView 从未执行 → 视图停在单位变换:
//    节点被拖到过画布外(手动摆位持久化)时 inView 恒 false 整片黑;
//    未越界时单节点在大画布 scale=1 下也只是个难发现的小点) → onMounted 补 fit;
// ② 挂载后才到数据(0→>0) → watch 处理。容器可能尚未完成布局(如全屏切换刚
//    结束), rAF 有界重试(10 帧)兜底, 成功一次后不再自动重适配(尊重手动平移/缩放)。
let didFit = false
// 2026-09-30 用户反馈"打开大屏/编辑态画布黑黑的, 点一下浏览模式才正常":
// 挂载时容器可能尚未完成布局(大屏卡网格/页面外层过渡), fit 拿不到有效 rect,
// 10 帧重试耗尽后视图停在单位变换 —— 持久化过手动摆位的节点都在画布外 → 一片黑。
// 修复: ①ResizeObserver 盯容器尺寸, 用户尚未手动操作视角前, 尺寸一变就补 fit;
//       ②模式切换(浏览/编辑)时若从未 fit 成功同样补 fit(用户旧"点一下浏览模式"
//       能修好的经验路径, 变成必然生效)。
const userMovedView = ref(false)   // 用户主动操作过视角(平移/缩放/框选/定位)后不再自动重适配
function markViewMoved() { if (!didFit) userMovedView.value = true }
// 2026-09-30 加固: 重试从"10 帧(≈160ms)"延长到"100ms×50(≈5s)"—— 大屏整页首开时
// 卡片网格/外层过渡的布局可能晚于 10 帧才稳定(重试耗尽 → 视图停在单位变换 → 持久化
// 过手动摆位的节点全在画布外 → 黑屏); 5s 时间窗覆盖布局晚到的长尾, 成功后立即停。
function fitWhenReady(retries = 50) {
  if (didFit) return
  if (!displayNodes.value.length) {   // 尚无节点: 不标记完成, 等 0→>0 路径再来
    if (retries > 0) setTimeout(() => fitWhenReady(retries - 1), 100)
    return
  }
  fitToView()
  const r = svgEl.value ? svgEl.value.getBoundingClientRect() : null
  if (r && r.width > 0 && r.height > 0) { didFit = true; return }
  if (retries > 0) setTimeout(() => fitWhenReady(retries - 1), 100)
}
watch(() => props.nodes.length, (n, prev) => {
  if (!props.autoFit || n === 0 || prev > 0) return
  nextTick(() => fitWhenReady())
})
watch(() => props.mode, () => {   // 模式切换: 从未适配成功且用户没动过视角 → 补 fit
  if (props.autoFit && !didFit && !userMovedView.value) nextTick(() => fitWhenReady())
})
let stageRO = null
function onStageResize() {
  if (!props.autoFit || didFit || userMovedView.value) return
  const r = svgEl.value ? svgEl.value.getBoundingClientRect() : null
  if (r && r.width > 0 && r.height > 0 && displayNodes.value.length) fitWhenReady(0)   // 成功则置 didFit
}
onMounted(() => {
  if (props.autoFit && props.nodes.length) nextTick(() => fitWhenReady())
  if (window.ResizeObserver && stageEl.value) {
    stageRO = new ResizeObserver(onStageResize)
    stageRO.observe(stageEl.value)
  }
  window.addEventListener('keydown', onEscKey)   // ESC: 取消连线 / 清框选 / 关端口浮层
  portRateTimer = setInterval(refreshPortRates, 15000)   // 线上绑定端口速率随设备轮询同频刷新
  refreshPortRates()
  // 端口绑定变化(画线选口/属性面板改绑/解绑)立即刷新线上速率, 不等 15s 拍
  watch(() => (props.links || []).map(l => (l.fromPort || '') + '|' + (l.toPort || '')).join(','), refreshPortRates)
})
// 低缩放(缩得很小)时隐藏光点/名称/LED, 大幅降低 SVG 节点数 → 500+ 流畅。
// 2026-10-01 用户反馈"全是绿线但没有速率": 旧口径只要 scale 低于阈值就全藏标签 ——
// 小拓扑(几十台设备)标签性能开销可忽略, 用户缩小看全图会"一个字都没有"误以为功能失效,
// 故只在节点多(500+ 性能场景)才门控; 小拓扑任意缩放级别都显示。
// (阈值仍可配: 大屏拓扑卡画布小 fit 缩放低, 传 0.3 保留节点速率/流量环特效)
const lowZoom = computed(() => displayNodes.value.length > 150 && viewState.value.scale < props.lowZoomScale)
const worldTf = computed(() => {
  const v = viewState.value
  return `translate(${v.tx}, ${v.ty}) scale(${v.scale})`
})

// ===== 布局 + 子网折叠 + 钻取 =====
const collapsed = ref(new Set())     // 折叠的子网 key 集合
const drilled = ref('')              // 当前钻入的子网 key('' = 全局)
// 2026-09-30: 物理(分层)/逻辑(业务分组)自动布局随双子视图取消 —— 节点 2D 位置
// = n.px/n.py(视图内世界坐标, 拖拽/落点写入), 未设置则 autoPos 自动网格。
// 坐标仍算在"副本"(posMap)上, 绝不写回共享 node.x/y(那是 3D 演示视图的坐标)。
// 自动网格位置(按视图内顺序确定, 刷新稳定)。2026-09-30 性能: 不再按 n.px==null 过滤
// —— posOf 本就优先取手动摆位 px/py, 这里全量预算, 拖拽时改 px 不会触发本 computed
// 每帧 O(N) 重算(此前拖节点卡顿的来源之一)。
const autoPosMap = computed(() => {
  const m = new Map()
  props.nodes.forEach((n, i) => m.set(n.deviceId, autoPos(i)))
  return m
})
const hasManualPos = computed(() => props.nodes.some(n => n.px != null))
const layoutData = computed(() => {
  const m = new Map()
  for (const n of props.nodes) m.set(n.deviceId, posOf(n.deviceId))
  // 子网中心 = 成员位置均值(仅供折叠汇总节点定位, 不改变成员坐标)
  const perSubnet = {}
  for (const g of groupBySubnet(props.nodes)) {
    let sx = 0, sy = 0
    for (const mem of g.members) { const p = m.get(mem.deviceId) || { x: 0, y: 0 }; sx += p.x; sy += p.y }
    perSubnet[g.key] = { cx: Math.round(sx / g.members.length), cy: Math.round(sy / g.members.length), count: g.members.length }
  }
  return { m, perSubnet, only: drilled.value }
})
const nodeMap = computed(() => new Map(props.nodes.map(n => [n.deviceId, n])))
// ===== 节点摆位(2026-09-30: 位置属于当前视图) =====
// 直接改节点对象 n.px/n.py(= 页面当前视图的节点, 页面 deep watch 防抖持久化);
// 场景内不再自建全局 localStorage(旧 manualPos 随多视图机制取消, 旧数据已迁入视图)。
function screenToWorld(e) {
  const m = toLocal(e)
  const v = viewState.value
  return { x: (m.x - v.tx) / v.scale, y: (m.y - v.ty) / v.scale }
}
const nodeDragging = ref(false)
let suppressClick = false
let dragUp = null
function onNodeDown(e, n) {
  if (e.button !== 0) return
  suppressClick = false // 新交互开始, 清掉上次拖拽可能残留的抑制标记
  hover.value = null
  const base = posOf(n.deviceId)
  // 多选: 拖的是选区成员 → 整组平移; 拖的是选区外节点 → 选区收敛为它自己再拖
  if (selSet.value.size > 1) {
    if (selSet.value.has('n:' + n.nodeId)) {
      startGroupDrag(e, selEntries(), { bx: base.x, by: base.y })
      return
    }
    selSet.value = new Set(['n:' + n.nodeId])
  }
  const off = { x: screenToWorld(e).x - base.x, y: screenToWorld(e).y - base.y }
  let moved = false
  function mv(ev) {
    const w = screenToWorld(ev)
    const nx = w.x - off.x, ny = w.y - off.y
    if (!moved && (Math.abs(nx - base.x) > 4 || Math.abs(ny - base.y) > 4)) {
      moved = true
      nodeDragging.value = true
    }
    if (moved) { n.px = Math.round(nx); n.py = Math.round(ny) }   // 直接写视图内节点(页面 watch 持久化)
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    dragUp = null
    nodeDragging.value = false
    if (moved) { suppressClick = true; emitDirty() }   // 拖拽结束触发的 click 不算"选中"
  }
  dragUp = up
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
function resetNodePos(deviceId) {
  const n = nodeMap.value.get(deviceId)
  if (!n || n.px == null) return false
  delete n.px; delete n.py
  return true
}
function resetPosAction() {
  const n = menuNode.value
  closeMenu()
  if (n && resetNodePos(n.deviceId)) { flash(t('topo.posRestored')); emitDirty() }
}
function resetAllPosAction() {
  closeMenu()
  for (const n of props.nodes) { delete n.px; delete n.py }
  flash(t('topo.resetAllPos'))
  emitDirty()
}

// ===== 设备库拖拽落点(编辑模式; 借鉴 Zabbix 元素库 → 画布生成节点) =====
function onLibDragOver(e) {
  if (props.mode !== 'edit') return
  if (e.dataTransfer && e.dataTransfer.types && e.dataTransfer.types.includes(TOPO_TYPE_MIME)) {
    e.dataTransfer.dropEffect = 'copy'
  }
}
function onLibDrop(e) {
  if (props.mode !== 'edit') return
  const type = e.dataTransfer && e.dataTransfer.getData(TOPO_TYPE_MIME)
  if (!type || !TYPES[type]) return
  const w = screenToWorld(e)
  emit('drop-node', { type, x: w.x, y: w.y })
}

// ===== 手动连线(编辑模式; 借鉴 Zabbix 主机间拉线建链路) =====
// 流程: 右键节点「从此节点连线」→ 进入连线态(源节点高亮) → 点击目标节点成链;
// 点空白 / 再点源节点 / ESC 取消。不做"按住拖动拉线": 节点拖拽(摆位)与拉线
// 共用左键 pointerdown, 两条交互互相抢, 两步点选在现有事件流里最稳。
const linkFrom = ref('')
const linkFromPort = ref('')   // 画线时选定的本端网口(空=未绑定, 2026-10-02)
let linkKeyHandler = null
function startLink(deviceId) {
  linkFrom.value = deviceId
  linkFromPort.value = ''
  flash(t('topo.linkStep2'))
  linkKeyHandler = (ev) => { if (ev.key === 'Escape') cancelLink() }
  window.addEventListener('keydown', linkKeyHandler)
  const n = (props.nodes || []).find(x => x.deviceId === deviceId)
  if (n) openPortPick('from', n)
}
function cancelLink() {
  if (portPick.value) portPick.value = null
  if (!linkFrom.value) return
  linkFrom.value = ''
  linkFromPort.value = ''
  if (linkKeyHandler) { window.removeEventListener('keydown', linkKeyHandler); linkKeyHandler = null }
}

// ===== 画线选网口(2026-10-02 用户要求: 连线时候就可以选择) =====
// 非阻塞浮层: from 阶段=进入连线态即可选本端(不选直接点目标也成链); to 阶段=成链
// 后选对端(确定/跳过/ESC)。端口清单与属性面板下拉同源(fetchNodePorts), 无数据=
// 只有"未绑定"+原因说明(用户口径: 没有真实端口就不给选项, 但要说明为什么)。
const portPick = ref(null)      // { stage: 'from'|'to', node, link? }
const portPickList = ref([])
const portPickNote = ref('')
const portPickVal = ref('')
let portPickSeq = 0
async function openPortPick(stage, node, link) {
  const my = ++portPickSeq
  portPick.value = { stage, node, link: link || null }
  portPickList.value = []
  portPickNote.value = ''
  portPickVal.value = ''
  if (!node) return
  try {
    const d = await fetchNodePorts(node, props.devices)
    if (portPickSeq !== my || !portPick.value || portPick.value.node !== node) return  // 已换到另一端/已关
    portPickList.value = d.ports || []
    if (!portPickList.value.length) portPickNote.value = d.note || ''
  } catch (e) {
    if (portPickSeq !== my) return
    portPickNote.value = '端口数据读取失败: ' + ((e && e.message) || e)
  }
}
function confirmToPort() {
  const l = portPick.value && portPick.value.link
  portPick.value = null
  if (l) { l.toPort = portPickVal.value || ''; emitDirty() }
}
function skipToPort() { portPick.value = null }

// 绑定端口真实速率(线上小字用, 与设备速率标签同口径: 不编造, 取不到不显示)。
// 15s 一拍刷新(与设备轮询同频); fetchNodePorts 自带 30s 按 deviceId 缓存, 同端点多条
// 链路共享一次取数。键=deviceId+端口名, 端口被解绑后残留条目无害(无引用不显示)。
const portRateMap = ref(new Map())
let portRateTimer = null
function boundPortRate(l) {
  const pick = (port, devId) => {
    if (!port || !devId) return 0
    const e = portRateMap.value.get(devId + ':' + port)
    return e ? (e.rx || 0) + (e.tx || 0) : 0
  }
  return pick(l.fromPort, l.fromDeviceId) || pick(l.toPort, l.toDeviceId)
}
// 每端标签文本(2026-10-02 v254 用户: "标签上不是该网口的上下行, 为什么显示该设备
// 下行速率"): 旧版只给一个 rx+tx 合计数(无方向, 易误读成设备下行) → 现在每个绑定端
// 各显该口的真实上下行(与设备速率标签同口径: ↑=流出/tx, ↓=流入/rx)。数据是逐口的
// (SNMP ifTable 逐口差分 / 探针逐网卡 / 采集逐网卡, 见 topoPorts.js), 不是设备总量。
// 名字部分: 别名(l.fromAlias/l.toAlias, 画布上改名)优先, 无别名回原口名;
// 有真实速率才显 ↑↓(端口取不到数据不显"↑0 ↓0", 不编造); 未绑定端显 —。
function portEndText(port, devId, alias) {
  if (!port) return '—'
  const name = alias || port
  const e = portRateMap.value.get(devId + ':' + port)
  if (e && (e.rx > 0 || e.tx > 0)) return name + ' ↑' + rateShort(e.tx) + ' ↓' + rateShort(e.rx)
  return name
}
// 连线流动光效时长(2026-10-02): 无真实流量(未绑端口/该口速率为 0)→ '' 不画(不编造)。
// 流速映射: 1MB/s→约 1.5s/圈, 10MB/s→约 0.8s, ≥100MB/s 触底 0.4s(可见但不刺眼)。
function linkFlowDur(l) {
  const r = boundPortRate(l)
  if (!(r > 0)) return ''
  const ms = 2000 * Math.pow(1e6 / (r + 1e6), 0.4)
  return Math.round(Math.max(400, Math.min(2000, ms))) + 'ms'
}
// 端口标签位置(2026-10-02 v258: 两端各一个标签, 各贴各的设备端):
// 默认锚点 = 起始端标签沿线下 22%(贴起始设备边), 终止端标签 78%(贴终止设备边),
// 线上 7px; 用户拖过 → 用 l.fromLblPos/l.toLblPos(世界坐标, 存链路对象上随视图文档
// 持久化, 与节点 n.px/n.py 同机制)。v254~v257 的单个 l.lblPos 不再读取(拆成两端后
// 无归属, 自然回落到两端默认位; 用户拖新标签即覆盖)。
function portAnchor(l, end) {
  const a = endpointPos(l.fromDeviceId)
  const b = endpointPos(l.toDeviceId)
  const t = end === 'to' ? 0.78 : 0.22
  return { x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t - 7 }
}
function portLabelPos(l, end) {
  return (end === 'to' ? l.toLblPos : l.fromLblPos) || portAnchor(l, end)
}
// 编辑态拖动标签(v258: 两端标签各自独立拖, 落位写 l.fromLblPos/l.toLblPos):
// 与节点拖拽同口径(screenToWorld 世界坐标换算, 移动才落位, 松手 emitDirty 持久化)
let lblClickSuppress = false
function onPortLabelDown(e, l, end) {
  if (e.button !== 0 || props.mode !== 'edit') return   // 浏览态只点选不拖(大屏卡只读)
  lblClickSuppress = false
  const base = portLabelPos(l, end)
  let moved = false
  function mv(ev) {
    const w = screenToWorld(ev)
    if (!moved && (Math.abs(w.x - base.x) > 3 || Math.abs(w.y - base.y) > 3)) moved = true
    if (moved) l[end === 'to' ? 'toLblPos' : 'fromLblPos'] = { x: Math.round(w.x), y: Math.round(w.y) }
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    if (moved) { lblClickSuppress = true; emitDirty() }   // 拖拽收尾的 click 不算"选中"
  }
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
function onPortLabelClick(l) {
  if (lblClickSuppress) { lblClickSuppress = false; return }
  emit('select', { kind: 'link', id: l.linkId })   // 点标签=打开链路属性(可重绑/解绑端口), 不删任何东西
}
function resetPortLabelPos(l, end) {
  const k = end === 'to' ? 'toLblPos' : 'fromLblPos'
  if (!l[k]) return
  delete l[k]
  emitDirty()
}
function refreshPortRates() {
  const jobs = []
  const seen = new Set()
  for (const l of props.links || []) {
    for (const [devId, port] of [[l.fromDeviceId, l.fromPort], [l.toDeviceId, l.toPort]]) {
      if (!devId || !port) continue
      const key = devId + ':' + port
      const e = portRateMap.value.get(key)
      if ((e && Date.now() - e.at < 15000) || seen.has(key)) continue
      seen.add(key)
      const n = (props.nodes || []).find(x => x.deviceId === devId)
      if (!n) continue
      jobs.push((async () => {
        const d = await fetchNodePorts(n, props.devices)
        const p = (d.ports || []).find(x => x.port === port)
        const m = new Map(portRateMap.value)
        m.set(key, { rx: p ? Math.round(p.rxBps || 0) : 0, tx: p ? Math.round(p.txBps || 0) : 0, at: Date.now() })
        portRateMap.value = m
      })())
    }
  }
  if (jobs.length) Promise.allSettled(jobs)
}
// 节点 2D 位置: 视图内手动摆位 n.px/n.py 优先, 否则自动网格(autoPos),
// 最后兜底 3D 坐标 x/y(迁移节点可能有 3D 坐标)。不引用 layoutData —— 避免循环。
function posOf(deviceId) {
  const n = nodeMap.value.get(deviceId)
  if (n && n.px != null) return { x: n.px, y: n.py }
  return autoPosMap.value.get(deviceId) || (n ? { x: n.x || 0, y: n.y || 0 } : { x: 0, y: 0 })
}

// 子网分组(当前可见范围: 钻取时只有该网段)
const subnets = computed(() => {
  const inScope = drilled.value ? props.nodes.filter(n => subnetKey(n.ip) === drilled.value) : props.nodes
  return groupBySubnet(inScope)
})
// 显示为"汇总节点"的子网 = 已折叠 且 成员≥2 且 非钻取(钻取时展开全部内部拓扑)
const summaryNodes = computed(() => {
  if (drilled.value) return []
  const out = []
  const ps = layoutData.value.perSubnet
  for (const g of subnets.value) {
    if (!collapsed.value.has(g.key) || g.members.length < 2) continue
    const p = ps[g.key]
    out.push({
      key: g.key, label: g.label, count: g.members.length,
      status: subnetStatus(g.members), statusCn: t(SAFE_CN[subnetStatus(g.members)]),
      x: p ? p.cx : W / 2, y: p ? p.cy : H / 2,
    })
  }
  return out
})
function isCollapsed(k) { return collapsed.value.has(k) }
function toggleCollapse(k) {
  const s = new Set(collapsed.value)
  if (s.has(k)) s.delete(k); else s.add(k)
  collapsed.value = s
}
function collapseAll() { collapsed.value = new Set(subnets.value.filter(g => g.members.length >= 2).map(g => g.key)) }
function expandAll() { collapsed.value = new Set() }

// 显示节点 = 未被折叠进汇总的节点
const displayNodes = computed(() => {
  if (drilled.value) return props.nodes.filter(n => subnetKey(n.ip) === drilled.value)
  const hidden = new Set()
  for (const g of subnets.value) if (collapsed.value.has(g.key) && g.members.length >= 2) for (const n of g.members) hidden.add(n.deviceId)
  return props.nodes.filter(n => !hidden.has(n.deviceId))
})
// 显示链路 = 至少一端可见(折叠端点映射到汇总节点中心, 全局态画子网间链路)
const displayLinks = computed(() => {
  const shown = new Set(displayNodes.value.map(n => n.deviceId))
  // 两端都必须存在才画(2026-10-01): 旧口径非钻取用 || —— 只有一端在视图里的悬空
  // 链路照样渲染, 缺失端点 posOf 落 (0,0), 线尾巴伸向画布原点且终点没有设备。
  return props.links.filter(l => shown.has(l.fromDeviceId) && shown.has(l.toDeviceId))
})
// 链路端点坐标(折叠端点 → 该子网汇总节点中心)
function endpointPos(deviceId) {
  if (drilled.value) return posOf(deviceId)
  const ps = layoutData.value.perSubnet
  const k = subnetKey(nodeMap.value.get(deviceId)?.ip)
  if (collapsed.value.has(k) && ps[k]) return { x: ps[k].cx, y: ps[k].cy }
  return posOf(deviceId)
}
// ===== 视口裁剪(500+ 节点流畅): 主画布只渲染可见区域内的节点/链路(小地图仍渲染全量做总览) =====
const viewRect = computed(() => {
  const v = viewState.value, m = 80
  return { x1: (-v.tx) / v.scale - m, y1: (-v.ty) / v.scale - m, x2: (W - v.tx) / v.scale + m, y2: (H - v.ty) / v.scale + m }
})
function inView(x, y) { const r = viewRect.value; return x >= r.x1 && x <= r.x2 && y >= r.y1 && y <= r.y2 }
const visibleNodes = computed(() => displayNodes.value.filter(n => { const p = posOf(n.deviceId); return inView(p.x, p.y) }))
const visibleLinks = computed(() => displayLinks.value.filter(l => {
  const a = endpointPos(l.fromDeviceId), b = endpointPos(l.toDeviceId)
  return inView(a.x, a.y) || inView(b.x, b.y)
}))
function pathOf(l) {
  const a = endpointPos(l.fromDeviceId), b = endpointPos(l.toDeviceId)
  const my = (a.y + b.y) / 2
  return `M ${a.x} ${a.y} C ${a.x} ${my}, ${b.x} ${my}, ${b.x} ${b.y}`
}
// 未测链路(2026-09-29 用户口径): 手动画的线只表示"拓扑关系", 不是"通" ——
// 未经中心端连通性测试一律灰虚线"未测"。
function linkUntested(l) { return !l._real && !l.tested }
// 推测边(2026-10-01 用户反馈"192.168.1.1 和 172.16.199.1 连线为什么也是绿的"):
// 页面空视图曾自动填充后端按网段关系猜的边(同 /24 星型/跨段链), 其"绿"来自后端
// "两端设备都健康" —— 被误读成"两端直连"。推测边=后端链路集(_real)里的边但用户
// 没画过(userDrawn)也没实测过(tested) → 细虚线"推测"样式, 不显示绿/红;
// 用户手动实测后(tested)显示真实结果, 或删掉重画(userDrawn=实画线)。
function isInferred(l) { return !!l._real && !l.tested && !l.userDrawn }
function linkTip(l) {
  const t = []
  if (l.fromPort || l.toPort) {
    const a = (props.nodes || []).find(n => n.deviceId === l.fromDeviceId)
    const b = (props.nodes || []).find(n => n.deviceId === l.toDeviceId)
    t.push('端口绑定: ' + (a ? a.name : '?') + ':' + (l.fromPort || '—') + ' ⇄ ' + (b ? b.name : '?') + ':' + (l.toPort || '—') + '(该端口真实速率见节点端口详情)')
  }
  t.push(isInferred(l)
    ? '推测连接(系统按网段关系推测, 未经实测; 不代表两端直连) — 不准确可删除或右键"测试连通性"实测'
    : (l.tested ? '连通性口径: 中心端监控可达两端(ICMP/TCP 实测); 不代表两端设备直连' : '未测试连通性(中心端可达两端才会变绿)'))
  return t.join(' · ')
}
function linkStyle(l) {
  if (isInferred(l)) return { strokeWidth: '1.1px', stroke: '#94a3b8', opacity: 0.5, strokeDasharray: '4 4' }
  if (linkUntested(l)) return { strokeWidth: '1.4px', stroke: '#64748b', opacity: 0.85 }
  const util = l.utilPct != null ? l.utilPct : Math.min(100, Math.round((l.pps || 0) / 60))
  let w = 1.6 + (Math.min(100, util) / 100) * 4.4
  if (l.status !== 'normal') w += 1.5
  return { strokeWidth: w + 'px', stroke: LINK_COLOR[l.status] || LINK_COLOR.normal, opacity: l.status === 'normal' ? 0.8 : 1 }
}
// ===== 节点真实上下行速率(2026-10-01: 速率从线移到设备, 真实归属不编造) =====
// n.inBps/n.outBps 由页面/大屏卡随 15s 设备轮询写入(SNMP 两帧差分, 与悬浮卡同源)。
// ↑=流出设备(上行) ↓=流入设备(下行); 两端都为 0/无数据 → 不显示(无数据不编造)。
function fmtRate(m) {
  const v = Number(m) || 0
  if (v >= 100) return Math.round(v) + 'M'
  if (v >= 1) return Math.round(v * 10) / 10 + 'M'
  if (v > 0) return Math.max(1, Math.round(v * 1000)) + 'K'
  return '0'
}
function nodeRateText(n) {
  const inM = ((n.inBps || 0) * 8) / 1e6
  const outM = ((n.outBps || 0) * 8) / 1e6
  if (inM <= 0 && outM <= 0) return ''
  return '↑' + fmtRate(outM) + ' ↓' + fmtRate(inM)
}
function nodeBusy(n) {
  return (n.inBps || 0) + (n.outBps || 0) > 0
}
// 流量环: 绕节点图标(r=19)外圈 r=24, 一段亮弧持续旋转, 周期 ∝ 1/总速率
// (1Mbps≈12s → 10Mbps≈6s → 30Mbps+≈2s); 颜色跟随节点状态色(在线绿/告警黄)。
function ringStyle(n) {
  return { stroke: safeColor(n), strokeDasharray: '14 62' }   // 周长 2π·24≈150.8, 一段 14
}
function ringDur(n) {
  const total = ((n.inBps || 0) + (n.outBps || 0)) * 8 / 1e6   // Mbps
  return Math.max(2, Math.min(12, 60 / total)).toFixed(1) + 's'
}
// ===== 自由框交互(2026-09-30 用户要求: 拖拽移动/拉角缩放/点击选中/改名/右键删除) =====
// 框对象 = 当前视图 boxes 里的 reactive 对象: 拖拽/缩放直接改 b.x/b.y/b.w/b.h(页面
// deep watch 防抖持久化); 改名/删除经 emit 回页面。浏览态(大屏卡)框不响应鼠标
// (CSS pointer-events:none), 平移画布不会被框挡住。
function onBoxDown(e, b) {
  if (props.mode !== 'edit' || e.button !== 0) return
  suppressClick = false
  hover.value = null
  // 多选: 拖的是选区成员 → 整组平移(含框内设备); 选区外 → 收敛为它自己再拖
  if (selSet.value.size > 1) {
    if (selSet.value.has('b:' + b.id)) {
      startGroupDrag(e, selEntries(), { bx: b.x, by: b.y })
      return
    }
    selSet.value = new Set(['b:' + b.id])
  }
  const start = screenToWorld(e)
  const off = { x: start.x - b.x, y: start.y - b.y }
  let moved = false
  function mv(ev) {
    const w = screenToWorld(ev)
    const nx = w.x - off.x, ny = w.y - off.y
    if (!moved && (Math.abs(nx - b.x) > 4 || Math.abs(ny - b.y) > 4)) moved = true
    if (moved) { b.x = Math.round(nx); b.y = Math.round(ny) }
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    if (moved) { suppressClick = true; emitDirty() } // 拖完触发的 click 不算"选中"
  }
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
function onBoxResizeStart(e, b) {
  if (props.mode !== 'edit' || e.button !== 0) return
  const start = screenToWorld(e)
  const w0 = b.w, h0 = b.h
  function mv(ev) {
    const w = screenToWorld(ev)
    b.w = Math.max(BOX_W_MIN, Math.min(BOX_W_MAX, Math.round(w0 + (w.x - start.x))))
    b.h = Math.max(BOX_H_MIN, Math.min(BOX_H_MAX, Math.round(h0 + (w.y - start.y))))
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    if (b.w !== w0 || b.h !== h0) emitDirty()
  }
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
function onBoxClick(e, b) {
  if (suppressClick) { suppressClick = false; return }
  if (portPick.value && portPick.value.stage === 'to') { portPick.value = null; return }   // 点画布其他处=跳过选对端口
  if (linkFrom.value) { cancelLink(); return }
  // Ctrl/⌘+点击 = 在框选集合里增删该项; 普通点击 = 收敛为单项
  if (e && (e.ctrlKey || e.metaKey)) {
    const s = new Set(selSet.value)
    const k = 'b:' + b.id
    if (s.has(k)) s.delete(k); else s.add(k)
    selSet.value = s
  } else {
    selSet.value = new Set(['b:' + b.id])
  }
  emit('select', { kind: 'box', id: b.id })
  emitMulti()
}
// ===== 框外观自定义(2026-09-30 用户要求: 边框线型/线宽/颜色 + 背景颜色/透明度/无 + 标签拖拽) =====
// 全部字段可选(旧数据无字段走默认值, 与原有视觉一致):
//   边框: b.strokeStyle('solid'|'dash'|'short') / b.strokeWidth / b.strokeColor
//   背景: b.fillColor + b.fillOpacity / b.fillNone(无背景)
//   标签: b.lx/b.ly(默认 12/24, 可拖拽随意放置) / b.fontColor / b.fontSize / b.fontBold / b.fontFamily
function dashOf(style) {
  if (style === 'dash') return '9 7'
  if (style === 'short') return '4 4'
  return 'none'
}
function boxRectStyle(b) {
  const sel = props.selBox === b.id   // 主选中项: 高亮描边(与旧 CSS .sel 同口径), 自定义值仍生效
  const w = b.strokeWidth != null ? b.strokeWidth : 1.2
  const stroke = sel ? '#38bdf8' : (b.strokeColor || '#3884ff')
  // 默认背景 = 旧版淡蓝 rgba(56,132,255,.05)(#3884ff @ 0.05), 旧数据无字段时观感不变
  const color = b.fillColor || '#3884ff'
  const op = b.fillOpacity != null ? b.fillOpacity : 0.05
  const fill = b.fillNone
    ? (sel ? 'rgba(56,132,255,.1)' : 'none')
    : hexA(color, sel ? Math.max(0.1, op) : op)
  return {
    stroke,
    'stroke-width': sel ? Math.max(2, w) : w,
    'stroke-dasharray': dashOf(b.strokeStyle),
    fill,
  }
}
// #rrggbb + alpha → rgba() 字符串(非法色值原样返回, 浏览器忽略后走 CSS 兜底)
function hexA(hex, a) {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(hex || ''))
  if (!m) return String(hex || '')
  const n = parseInt(m[1], 16)
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${Math.max(0, Math.min(1, a))})`
}
function boxLabelStyle(b) {
  return {
    fill: b.fontColor || '#9fb0c8',
    'font-size': (b.fontSize || 15) + 'px',
    'font-weight': b.fontBold ? '700' : '400',
    'font-family': b.fontFamily || 'inherit',
  }
}
// 标签拖拽: 编辑态按住标签拖动随意放置(写入 b.lx/b.ly); 未拖动=普通点击(选中框)
function onLabelDown(e, b) {
  if (props.mode !== 'edit' || e.button !== 0) return
  suppressClick = false
  hover.value = null
  const start = screenToWorld(e)
  const ox = b.lx != null ? b.lx : 12
  const oy = b.ly != null ? b.ly : 24
  let moved = false
  function mv(ev) {
    const w = screenToWorld(ev)
    const nx = w.x - (start.x - ox), ny = w.y - (start.y - oy)
    if (!moved && (Math.abs(nx - ox) > 4 || Math.abs(ny - oy) > 4)) { moved = true; suppressClick = true }
    if (!moved) return
    b.lx = Math.round(Math.max(-20, Math.min(b.w + 20, nx)))
    b.ly = Math.round(Math.max(-16, Math.min(b.h + 16, ny)))
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    nodeDragging.value = false
    if (moved) emitDirty()
  }
  nodeDragging.value = true   // grabbing 光标
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
// ③ 改名: 编辑态双击框/框标签 → 标签锚点处悬浮输入框, Enter/失焦提交。
//    不用 prompt(): headless/自动化环境 alert/prompt 阻塞渲染, 且样式不可控。
const renaming = ref(null)   // { kind: 'box', id, name, x, y }
function worldToScreen(wx, wy) {
  const v = viewState.value
  const r = stageEl.value ? stageEl.value.getBoundingClientRect() : { width: W, height: H }
  return { x: (wx * v.scale + v.tx) * r.width / W, y: (wy * v.scale + v.ty) * r.height / H }
}
function startRenameBox(b) {
  if (props.mode !== 'edit') return
  renaming.value = { kind: 'box', id: b.id, name: b.name || '', ...worldToScreen(b.x + 12, b.y + 24) }
}
// 端口别名(2026-10-02 v254 用户: "端口在画布上显示可以进行改名做为别名显示";
// v258 两端标签拆分后=双击哪个端标签就改哪端):
// 别名按链路端存 l.fromAlias/l.toAlias(随视图文档持久化, 与 fromLblPos/toLblPos
// 同机制; 链路属性面板里"起始端口别名/终止端口别名"输入框是同一数据); 别名只换
// 名字部分, 后面的实时速率(↑↓)照常 15s 刷新; 空别名=清除(回显原口名)。
function startRenamePort(l, end) {
  if (props.mode !== 'edit') return
  if (!(end === 'from' ? l.fromPort : l.toPort)) return
  const p = portLabelPos(l, end)
  renaming.value = { kind: 'port', linkId: l.linkId, end, name: (end === 'from' ? l.fromAlias : l.toAlias) || '', ...worldToScreen(p.x, p.y) }
}
function onPortLabelDblClick(e, l, end) {
  if (props.mode !== 'edit') return
  startRenamePort(l, end)   // v258: 双击哪个端标签就改哪端的别名
}
function commitRename() {
  const r = renaming.value
  if (!r) return
  renaming.value = null
  const v = String(r.name || '').trim()
  if (r.kind === 'box') {
    if (!v) return
    emit('box-rename', { id: r.id, name: v })
  } else if (r.kind === 'port') {
    const l = (props.links || []).find(x => x.linkId === r.linkId)
    if (!l) return
    const k = r.end === 'from' ? 'fromAlias' : 'toAlias'
    if (v) l[k] = v; else delete l[k]   // 空别名=清除
    emitDirty()
  }
}

// ===== 框选多选 + 整体移动/整体缩放(2026-09-30 用户要求) =====
// 左键拖空白 = 框选(编辑态); 平移保留 Shift+左键 / 中键拖 / 滚轮 / 概览窗。
// 选集合 = 命名空间 id('n:' + nodeId / 'b:' + boxId); 单点选中收敛为单项,
// Ctrl/⌘+点击 = 增删切换。主选中(属性面板对象)= 框选到的第一个节点, 否则第一个框,
// 经既有 emit('select') 上报, 页面侧逻辑零改动。
// 整体移动: 拖任一选中项 = 整组平移(节点写 px/py, 框写 x/y, 页面 deep watch 防抖落盘)。
// 整体缩放: 选区包围盒右下角手柄, 以包围盒左上角为原点等比缩放(节点位置/框宽高同步,
// 框宽高仍受 BOX_W/H_MIN..MAX 约束)。
const selSet = ref(new Set())
const marquee = ref(null)   // 框选中的矩形(世界坐标) {x,y,w,h}
const groupScaling = ref(false)
// 2026-09-30 用户要求: 框选多个时属性面板显示"多个设备和框的清单"(非单个设备属性)。
// 每次选集合变化都上报 select-multi(放在 emit('select') 之后, 页面以清单为准);
// 单项/空清单时页面板收回普通单对象属性。
function emitMulti() {
  const items = []
  const s = selSet.value
  for (const n of displayNodes.value) {
    if (!s.has('n:' + n.nodeId)) continue
    items.push({ kind: 'node', id: n.nodeId, name: n.name, sub: n.ip || '—', status: n.status })
  }
  if (!drilled.value) {
    for (const b of props.boxes) {
      if (!s.has('b:' + b.id)) continue
      items.push({ kind: 'box', id: b.id, name: b.name, sub: b.w + ' × ' + b.h + ' px' })
    }
  }
  emit('select-multi', items)
}
function clearSel() { selSet.value = new Set(); emitMulti() }
// 页面持久化信号: 拖拽/缩放/标签移动等高频几何变更不再靠页面 deep watch
// (deep watch 每帧全量遍历大文档是编辑卡顿主因), 改由场景在操作结束时上报 dirty
function emitDirty() { emit('dirty') }
// 当前选区内的可操作元素(隐藏节点/钻取态的框不参与整组操作)
function selEntries() {
  const out = []
  const s = selSet.value
  for (const n of displayNodes.value) {
    if (!s.has('n:' + n.nodeId)) continue
    const p = posOf(n.deviceId)
    out.push({ kind: 'n', obj: n, bx: p.x, by: p.y })
  }
  if (!drilled.value) {
    for (const b of props.boxes) {
      if (!s.has('b:' + b.id)) continue
      out.push({ kind: 'b', obj: b, bx: b.x, by: b.y, bw: b.w, bh: b.h })
    }
  }
  return out
}
// 选区包围盒(≥2 项): 节点按中心±28(含名称标签), 框按矩形; 节点/框集合变化时自动重算
const selBBox = computed(() => {
  const s = selSet.value
  if (s.size < 2 || props.mode !== 'edit') return null
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
  for (const n of displayNodes.value) {
    if (!s.has('n:' + n.nodeId)) continue
    const p = posOf(n.deviceId)
    minX = Math.min(minX, p.x - 28); maxX = Math.max(maxX, p.x + 28)
    minY = Math.min(minY, p.y - 28); maxY = Math.max(maxY, p.y + 36)
  }
  if (!drilled.value) {
    for (const b of props.boxes) {
      if (!s.has('b:' + b.id)) continue
      minX = Math.min(minX, b.x); maxX = Math.max(maxX, b.x + b.w)
      minY = Math.min(minY, b.y); maxY = Math.max(maxY, b.y + b.h)
    }
  }
  if (!isFinite(minX)) return null
  return { x: minX, y: minY, w: maxX - minX, h: maxY - minY, count: s.size }
})
// 节点/框被页面删除后, 选集合里的残留 id 不再参与整组操作
watch([() => props.nodes, () => props.boxes], () => {
  const s = selSet.value
  if (!s.size) return
  const ok = new Set()
  for (const n of props.nodes) ok.add('n:' + n.nodeId)
  for (const b of props.boxes) ok.add('b:' + b.id)
  for (const k of [...s]) if (!ok.has(k)) s.delete(k)
  selSet.value = new Set(s)
})
// 框选: 编辑态左键拖空白(连线态除外, 那时光标在挑目标节点)
function startMarquee(e) {
  const start = screenToWorld(e)
  const v0 = viewState.value.scale
  let moved = false
  function mv(ev) {
    const w = screenToWorld(ev)
    const x = Math.min(w.x, start.x), y = Math.min(w.y, start.y)
    const ww = Math.abs(w.x - start.x), hh = Math.abs(w.y - start.y)
    if (!moved && (ww > 6 / v0 || hh > 6 / v0)) { moved = true; suppressClick = true }
    if (moved) marquee.value = { x, y, w: ww, h: hh }
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    cleanup = null
    if (!moved) {
      // 未拖动 = 点空白: 清选区(与旧"点空白取消连线/关面板"口径一致)
      clearSel()
      cancelLink()
      emit('blank-click')
      return
    }
    finishMarquee()
  }
  cleanup = up
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
function finishMarquee() {
  const r = marquee.value
  marquee.value = null
  if (!r || r.w < 4 || r.h < 4) { clearSel(); emit('blank-click'); return }
  const ns = new Set()
  for (const n of displayNodes.value) {
    const p = posOf(n.deviceId)
    if (p.x >= r.x && p.x <= r.x + r.w && p.y >= r.y && p.y <= r.y + r.h) ns.add('n:' + n.nodeId)
  }
  if (!drilled.value) {
    for (const b of props.boxes) {
      if (b.x < r.x + r.w && b.x + b.w > r.x && b.y < r.y + r.h && b.y + b.h > r.y) ns.add('b:' + b.id)
    }
  }
  selSet.value = ns
  if (!ns.size) { emit('blank-click'); return }
  const nCount = [...ns].filter(k => k[0] === 'n').length
  const bCount = ns.size - nCount
  // 主选中 = 第一个选中的节点(否则第一个框) → 属性面板
  const firstN = displayNodes.value.find(n => ns.has('n:' + n.nodeId))
  const firstB = firstN ? null : props.boxes.find(b => ns.has('b:' + b.id))
  if (firstN) emit('select', { kind: 'node', id: firstN.nodeId })
  else if (firstB) emit('select', { kind: 'box', id: firstB.id })
  emitMulti()   // 在 select 之后上报, 页面属性面板以"多清单"为准
  if (ns.size > 1) flash(t('topo.boxSelected', { n: ns.size, d: nCount, b: bCount }))
}
// 整体移动: 选集合内的节点/框被拖 = 整组平移
function startGroupDrag(e, entries, anchor) {
  const off = { x: screenToWorld(e).x - anchor.bx, y: screenToWorld(e).y - anchor.by }
  let moved = false
  function mv(ev) {
    const w = screenToWorld(ev)
    const ax = w.x - off.x, ay = w.y - off.y
    if (!moved && (Math.abs(ax - anchor.bx) > 4 || Math.abs(ay - anchor.by) > 4)) {
      moved = true
      nodeDragging.value = true
    }
    if (!moved) return
    for (const ent of entries) {
      const dx = ax - anchor.bx, dy = ay - anchor.by
      if (ent.kind === 'n') { ent.obj.px = Math.round(ent.bx + dx); ent.obj.py = Math.round(ent.by + dy) }
      else { ent.obj.x = Math.round(ent.bx + dx); ent.obj.y = Math.round(ent.by + dy) }
    }
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    dragUp = null
    nodeDragging.value = false
    if (moved) { suppressClick = true; emitDirty() }   // 拖完触发的 click 不算"选中"
  }
  dragUp = up
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
// 整体缩放: 选区包围盒右下角手柄, 以包围盒左上角为原点等比(0.2x~4x)
function onGroupScaleStart(e) {
  if (props.mode !== 'edit' || e.button !== 0) return
  suppressClick = false
  const bb = selBBox.value
  if (!bb || !bb.w || !bb.h) return
  const ox = bb.x, oy = bb.y, w0 = bb.w
  const entries = selEntries()
  groupScaling.value = true
  nodeDragging.value = true   // 复用 grabbing 光标
  let moved = false
  function mv(ev) {
    const w = screenToWorld(ev)
    const k = Math.max(0.2, Math.min(4, (w.x - ox) / Math.max(1, w0)))
    if (Math.abs(k - 1) < 0.02) return
    moved = true
    for (const ent of entries) {
      if (ent.kind === 'n') {
        ent.obj.px = Math.round(ox + (ent.bx - ox) * k)
        ent.obj.py = Math.round(oy + (ent.by - oy) * k)
      } else {
        ent.obj.x = Math.round(ox + (ent.bx - ox) * k)
        ent.obj.y = Math.round(oy + (ent.by - oy) * k)
        ent.obj.w = Math.max(BOX_W_MIN, Math.min(BOX_W_MAX, Math.round(ent.bw * k)))
        ent.obj.h = Math.max(BOX_H_MIN, Math.min(BOX_H_MAX, Math.round(ent.bh * k)))
      }
    }
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    groupScaling.value = false
    nodeDragging.value = false
    if (moved) { flash(t('topo.selectionScaled')); emitDirty() }
  }
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
// ESC: 取消连线 > 清选区
function onEscKey(ev) {
  if (ev.key !== 'Escape') return
  if (portPick.value && portPick.value.stage === 'to') { portPick.value = null; return }
  if (linkFrom.value) cancelLink()
  else if (selSet.value.size) clearSel()
}

// ===== 钻取 =====
function labelByKey(k) { return !k ? '' : (k === '_ungrouped' ? '未分组网段' : k + '.0/24') }
const drilledLabel = computed(() => labelByKey(drilled.value))
function drillIn(key) {
  if (!key) return
  drilled.value = key
  collapsed.value = new Set()
  resetView()
  flash(t('topo.drilledInto', { name: labelByKey(key) }))
}
function drillOut() { drilled.value = ''; resetView() }
// 切视图/节点集大变: 当前钻入的子网在新集合里不存在则回全局, 防画布空白
watch(() => props.nodes, (ns) => {
  if (drilled.value && !ns.some(n => subnetKey(n.ip) === drilled.value)) {
    drilled.value = ''
    collapsed.value = new Set()
  }
})
function onSummaryClick(s) { emit('select', { kind: 'subnet', id: s.key }) }
function onBlankDblClick() { if (drilled.value) drillOut() }

// ===== 平移 / 缩放(锚定鼠标) =====
function toLocal(e) {
  const r = svgEl.value.getBoundingClientRect()
  return { x: (e.clientX - r.left) / r.width * W, y: (e.clientY - r.top) / r.height * H }
}
function onWheel(e) {
  markViewMoved()
  const v = viewState.value
  const f = e.deltaY < 0 ? 1.12 : 0.9
  const ns = Math.min(SCALE_MAX, Math.max(SCALE_MIN, v.scale * f))
  if (ns === v.scale) return
  const m = toLocal(e)
  const wx = (m.x - v.tx) / v.scale, wy = (m.y - v.ty) / v.scale
  v.tx = m.x - wx * ns
  v.ty = m.y - wy * ns
  v.scale = ns
}
function zoomBy(f) {
  markViewMoved()
  const v = viewState.value
  const ns = Math.min(SCALE_MAX, Math.max(SCALE_MIN, v.scale * f))
  if (ns === v.scale) return
  v.tx = W / 2 - (W / 2 - v.tx) * (ns / v.scale)
  v.ty = H / 2 - (H / 2 - v.ty) * (ns / v.scale)
  v.scale = ns
}
let cleanup = null
function onSceneDown(e) {
  suppressClick = false // 新交互开始, 清掉上次拖拽可能残留的抑制标记
  hover.value = null
  if (e.button === 1) e.preventDefault()   // 中键拖=平移, 同时禁掉 Chrome 中键自动滚屏
  if (e.button !== 0 && e.button !== 1) return
  // 2026-09-30 用户要求: 编辑态左键拖空白 = 框选(多选设备/框);
  // 平移保留: Shift+左键 / 中键拖(浏览态左键拖仍是平移); 滚轮/概览窗不变。
  if (props.mode === 'edit' && e.button === 0 && !linkFrom.value && !e.shiftKey) {
    startMarquee(e)
    return
  }
  startPan(e)
}
function startPan(e) {
  const v = viewState.value
  const sx = e.clientX, sy = e.clientY, o = { tx: v.tx, ty: v.ty }
  let moved = false
  function mv(ev) {
    const dx = ev.clientX - sx, dy = ev.clientY - sy
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) { moved = true; markViewMoved() }
    const r = svgEl.value.getBoundingClientRect()
    v.tx = o.tx + dx * W / r.width
    v.ty = o.ty + dy * H / r.height
  }
  function up() {
    window.removeEventListener('pointermove', mv); window.removeEventListener('pointerup', up); cleanup = null
    if (!moved) { cancelLink(); emit('blank-click') }   // 点空白 = 取消连线/清选区(浏览态)
  }
  cleanup = up
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}
// 小地图视口框
const mmVp = computed(() => {
  const v = viewState.value
  const x1 = (-v.tx) / v.scale, y1 = (-v.ty) / v.scale
  const x2 = (W - v.tx) / v.scale, y2 = (H - v.ty) / v.scale
  const x = Math.max(0, x1), y = Math.max(0, y1)
  const x2c = Math.min(W, x2), y2c = Math.min(H, y2)
  if (x2c - x < 1 || y2c - y < 1) return null
  return { x, y, w: x2c - x, h: y2c - y }
})
function mmEnd(l, which) {
  const a = endpointPos(l.fromDeviceId), b = endpointPos(l.toDeviceId)
  return which === 1 ? a.x : which === 2 ? b.x : which === 'y1' ? a.y : b.y
}
function mmWorld(e) {
  const r = mmSvg.value.getBoundingClientRect()
  return { x: (e.clientX - r.left) / r.width * W, y: (e.clientY - r.top) / r.height * H }
}
function onMMDown(e) {
  if (e.button !== 0) return
  const p = mmWorld(e)
  const v = viewState.value
  const t0 = { tx: v.tx, ty: v.ty }
  function mv(ev) {
    const q = mmWorld(ev)
    v.tx = t0.tx - (q.x - p.x) * v.scale
    v.ty = t0.ty - (q.y - p.y) * v.scale
  }
  function up() {
    window.removeEventListener('pointermove', mv)
    window.removeEventListener('pointerup', up)
    // 松手点距起点极小 = 单击: 视口居中到该点(快速定位区域)
    const q = mmWorld(e)
    if (Math.abs(q.x - p.x) < 6 && Math.abs(q.y - p.y) < 6) {
      v.tx = W / 2 - p.x * v.scale
      v.ty = H / 2 - p.y * v.scale
    }
  }
  window.addEventListener('pointermove', mv)
  window.addEventListener('pointerup', up)
}

// ===== 选中 / 悬浮 =====
function onNodeClick(e, n) {
  if (suppressClick) { suppressClick = false; return } // 拖拽结束后的 click 不算选中
  // 连线态: 点目标节点成链(点回源节点=取消)
  if (linkFrom.value) {
    if (linkFrom.value === n.deviceId) { cancelLink(); return }
    const from = linkFrom.value
    const fromPort = linkFromPort.value
    cancelLink()
    emit('link-add', { fromDeviceId: from, toDeviceId: n.deviceId, fromPort })
    // 成链后立即选对端网口(非阻塞浮层; 重复链路时=给既有链路补绑对端口)
    nextTick(() => {
      const l = (props.links || []).find(x => (x.fromDeviceId === from && x.toDeviceId === n.deviceId) ||
        (x.fromDeviceId === n.deviceId && x.toDeviceId === from))
      if (l) openPortPick('to', n, l)
    })
    return
  }
  // Ctrl/⌘+点击 = 在框选集合里增删该项(不动其他成员); 普通点击 = 收敛为单项
  if (e && (e.ctrlKey || e.metaKey)) {
    const s = new Set(selSet.value)
    const k = 'n:' + n.nodeId
    if (s.has(k)) s.delete(k); else s.add(k)
    selSet.value = s
  } else {
    selSet.value = new Set(['n:' + n.nodeId])
  }
  emit('select', { kind: 'node', id: n.nodeId })
  emitMulti()
}
function onLinkClick(l) { emit('select', { kind: 'link', id: l.linkId }) }
function onNodeDblClick(n) { focusDevice(n.deviceId) }
const hover = ref(null)
const hoverStyle = computed(() => {
  const h = hover.value
  if (!h) return {}
  return { left: h.sx + 'px', top: h.sy + 'px', transform: 'translate(-50%, -100%)' }
})
function onNodeHover(e, n) {
  if (e.buttons) return
  const r = stageEl.value.getBoundingClientRect()
  const ls = props.links.filter(l => l.fromDeviceId === n.deviceId || l.toDeviceId === n.deviceId)
  let utilText = '—'
  if (ls.length) utilText = Math.round(ls.map(l => (l.utilPct != null ? l.utilPct : Math.min(100, Math.round((l.pps || 0) / 60)))).reduce((a, b) => a + b, 0) / ls.length) + '%'
  // 2026-10-01: 速率口径统一为设备自身真实上下行(SNMP 两帧差分, 与节点名字下方
  // 标签同源 n.inBps/n.outBps) —— 旧口径按相连链路 trafficSide 汇总, 线速率删除后失效
  const inM = ((n.inBps || 0) * 8) / 1e6, outM = ((n.outBps || 0) * 8) / 1e6
  const rateTxt = (inM > 0 || outM > 0) ? `↑${fmtRate(outM)} ↓${fmtRate(inM)}` : ''
  // 无速率时明确给出原因(2026-10-01 用户: "Edge 不显示速率, Chrome 显示")—— 速率
  // 只有 SNMP 监控目标才有(两帧差分), 用户手加的空 IP 节点/未纳管设备永远不会出数,
  // 静默留白会被当成 bug。口径: 不编造速率, 但必须说明为什么没有。
  let rateNote = ''
  if (!rateTxt) rateNote = n.ip ? '无 SNMP 速率: 该 IP 不是监控目标(节点监控→协议配置添加)' : '无 IP: 该节点未绑定真实设备'
  hover.value = { name: n.name, type: n.type, ip: n.ip, status: n.status, utilText, rateText: rateTxt, rateNote, sx: e.clientX - r.left, sy: e.clientY - r.top - 12 }
}

// ===== 右键菜单 =====
const menuOpen = ref(false)
const menuStyle = ref({})
const menuNode = ref(null)
const menuLink = ref(null)
const menuSummary = ref(null)
const linkMenuTitle = computed(() => {
  const l = menuLink.value
  if (!l) return ''
  const a = props.nodes.find(x => x.deviceId === l.fromDeviceId)
  const b = props.nodes.find(x => x.deviceId === l.toDeviceId)
  return (a ? a.name : '?') + ' ↔ ' + (b ? b.name : '?')
})
const menuBox = ref(null)
// menuWorld: 打开菜单时的世界坐标(画布右键"在此添加框/添加设备"的落点)
const menuWorld = ref({ x: W / 2, y: H / 2 })
function openMenu(e, node, link, box) {
  const summary = (node && node.key && node.count != null) ? node : null
  menuNode.value = summary ? null : (node || null)
  menuLink.value = link || null
  menuBox.value = (box && !summary) ? box : null
  menuSummary.value = summary
  menuWorld.value = screenToWorld(e)
  menuStyle.value = { left: Math.min(e.clientX, window.innerWidth - 210) + 'px', top: Math.min(e.clientY, window.innerHeight - 340) + 'px' }
  menuOpen.value = true
  window.addEventListener('pointerdown', closeMenu, { once: true })
}
function closeMenu() { menuOpen.value = false }
function nodeAction(kind) {
  const n = menuNode.value; closeMenu(); if (!n) return
  if (kind === 'detail') emit('select', { kind: 'node', id: n.nodeId })
  else if (kind === 'alert') emit('config-alert', n)
  else if (kind === 'nodemon') router.push('/nodemonitor')
  else if (kind === 'drill') emit('drill', n)
  else if (kind === 'core') emit('toggle-core', n)
  else if (kind === 'rebind') emit('rebind', n)
  else if (kind === 'link') startLink(n.deviceId)
  else if (kind === 'delete') emit('delete', { nodeId: n.nodeId })
}
function linkAction(kind) {
  const l = menuLink.value; closeMenu(); if (!l) return
  if (kind === 'detail') emit('select', { kind: 'link', id: l.linkId })
  else if (kind === 'check') emit('link-check', l)   // 连通性测试(页面调后端真实探测)
  else if (kind === 'backup') emit('toggle-backup', l)
  else if (kind === 'delete') emit('delete', { linkId: l.linkId })
  else if (kind === 'renameFrom') startRenamePort(l, 'from')
  else if (kind === 'renameTo') startRenamePort(l, 'to')
  else if (kind === 'resetLblFrom') resetPortLabelPos(l, 'from')
  else if (kind === 'resetLblTo') resetPortLabelPos(l, 'to')
}
function canvasAction(kind, type) {
  closeMenu()
  if (kind === 'resetview') { resetView(); return }
  if (kind === 'export') { emit('export'); return }
  if (kind === 'layout') { emit('reset-layout'); return }
  // 2026-09-30: 画布右键"在此添加框/添加设备"(落点=右键处世界坐标)
  if (kind === 'addbox') { emit('add-box', { x: menuWorld.value.x, y: menuWorld.value.y }); return }
  if (kind === 'adddevice' && type) emit('drop-node', { type, x: menuWorld.value.x, y: menuWorld.value.y })
}
function boxAction(kind) {
  const b = menuBox.value; closeMenu(); if (!b) return
  if (kind === 'rename') startRenameBox(b)
  else if (kind === 'delete') emit('delete-box', { id: b.id })
}
// 框选批量删除(2026-10-01 用户要求): 场景只上报选中项清单, 确认与删除都在页面
// 执行(页面持有视图文档数据, 且删除要弹确认 + 级联删链路 + 落盘)
function deleteSelected() {
  closeMenu()
  if (selSet.value.size < 2) return
  emit('delete-multi', selEntries().map(e => ({ kind: e.kind, id: e.kind === 'n' ? e.obj.nodeId : e.obj.id })))
}

// ===== 外部调用: 定位(居中放大) =====
function focusDevice(deviceId) {
  markViewMoved()
  const n = props.nodes.find(x => x.deviceId === deviceId)
  if (!n) return false
  if (!drilled.value) {   // 若在折叠子网里 → 先展开该子网
    const k = subnetKey(n.ip)
    if (collapsed.value.has(k)) { const s = new Set(collapsed.value); s.delete(k); collapsed.value = s }
  }
  const p = posOf(deviceId)
  const v = viewState.value
  v.scale = Math.min(SCALE_MAX, Math.max(1.3, v.scale * 1.3))
  v.tx = W / 2 - p.x * v.scale
  v.ty = H / 2 - p.y * v.scale
  emit('select', { kind: 'node', id: n.nodeId })
  return true
}
defineExpose({
  focusDevice, resetView, fitToView,
  // 页面批量删除选中项后清掉场景内选区(防残留幽灵选中参与整组拖拽)
  clearSelection: clearSel,
  // 供页面"多套视图"读写 2D 的折叠/钻取状态
  getDrillState: () => ({ drilled: drilled.value, collapsed: [...collapsed.value] }),
  setDrillState: (s) => { drilled.value = (s && s.drilled) || ''; collapsed.value = new Set((s && s.collapsed) || []) },
})

// 节点/链路集合变化时 layoutData 会自动重算(computed 依赖), 无需手动 recompute
onBeforeUnmount(() => {
  if (tipT) clearTimeout(tipT)
  if (portRateTimer) clearInterval(portRateTimer)
  if (cleanup) cleanup()
  if (dragUp) dragUp()
  if (linkKeyHandler) window.removeEventListener('keydown', linkKeyHandler)
  window.removeEventListener('keydown', onEscKey)
  window.removeEventListener('pointerdown', closeMenu)
  if (stageRO) stageRO.disconnect()
})
</script>

<style scoped>
.t2d { position: relative; width: 100%; height: 100%; overflow: hidden; background: radial-gradient(120% 90% at 50% 0%, #0d1730 0%, #070d18 70%); }
.t2d-stage { position: absolute; inset: 0; cursor: grab; }
.t2d-stage:active { cursor: grabbing; }
.t2d-svg { display: block; width: 100%; height: 100%; }
/* 区域背景 */
/* 自由框(2026-09-30): 半透明底 + 虚线描边; 选中态高亮。浏览态(大屏卡)整组
   pointer-events:none —— 平移画布不会被框挡住, 框纯展示。 */
.t2d-box { cursor: default; }
/* 边框/背景色与线型由内联样式(场景 boxRectStyle)按框对象字段绘制, 这里是旧数据的兜底色 */
.t2d-box-rect { fill: rgba(56, 132, 255, .05); stroke: rgba(56, 132, 255, .35); stroke-width: 1.2; transition: stroke .2s ease, fill .2s ease; }
/* 标签默认不拦截指针(点标签=点框); 编辑态可按住拖拽随意放置 → 放行 + 移动光标 */
.t2d-box-label { font-size: 15px; fill: rgba(159, 176, 200, .85); letter-spacing: 3px; pointer-events: none; }
.t2d.edit .t2d-box-label { pointer-events: auto; cursor: move; }
.t2d-box:hover .t2d-box-rect { stroke: rgba(56, 189, 248, .7); }
/* 选中态高亮由 boxRectStyle 内联绘制(与自定义色并存), 旧 CSS 规则保留兜底 */
.t2d-box.sel .t2d-box-rect { stroke: #38bdf8; stroke-width: 2; fill: rgba(56, 132, 255, .1); }
.t2d.browse .t2d-box { pointer-events: none; }
/* 框右下角缩放手柄: 平时淡显, 悬停高亮 */
.t2d-box-resize { fill: rgba(56, 189, 248, .25); stroke: rgba(56, 189, 248, .6); stroke-width: 1; cursor: nwse-resize; }
.t2d-box-resize:hover { fill: rgba(56, 189, 248, .55); }
/* 框选矩形(2026-09-30: 编辑态左键拖空白, 世界坐标随视图缩放) */
.t2d-marquee { fill: rgba(56, 189, 248, .08); stroke: #38bdf8; stroke-width: 1.2; stroke-dasharray: 5 4; pointer-events: none; }
/* 选区包围盒(≥2 项选中): 只有右下角手柄可交互, 其余不挡节点/框点击 */
.t2d-selgroup { pointer-events: none; }
.t2d-selgroup-rect { fill: none; stroke: rgba(251, 191, 36, .55); stroke-width: 1.2; stroke-dasharray: 6 4; }
.t2d-selgroup-handle { pointer-events: all; fill: rgba(251, 191, 36, .3); stroke: #fbbf24; stroke-width: 1; cursor: nwse-resize; }
.t2d-selgroup-handle:hover { fill: rgba(251, 191, 36, .6); }
.t2d-selgroup-size { font-size: 12px; fill: #fbbf24; font-variant-numeric: tabular-nums; }
/* 框选集合高亮(金色环, 与主选中项 sel 的粗环并存) */
.t2d-node.in-sel .t2d-ico { stroke: #fbbf24; stroke-width: 3; filter: drop-shadow(0 0 6px #fbbf24); }
.t2d-box.in-sel .t2d-box-rect { stroke: #fbbf24; stroke-width: 2; fill: rgba(251, 191, 36, .06); }
/* 编辑态: 左键拖空白=框选 → 十字光标(平移用 Shift+左键/中键, 见舞台 title 提示) */
.t2d.edit .t2d-stage { cursor: crosshair; }
.t2d.edit .t2d-stage:active { cursor: crosshair; }
/* 链路 */
.t2d-link { filter: drop-shadow(0 0 4px currentColor); transition: stroke .4s ease, stroke-width .4s ease; }
.t2d-link.warn { animation: t2dBreath 1.4s ease-in-out infinite; }
.t2d-link.down { stroke-dasharray: 9 7; animation: t2dBlink 1s steps(2, start) infinite; }
.t2d-link.backup { stroke-dasharray: 9 7; }
.t2d-link.untested { stroke-dasharray: 5 5; }
/* 连线流动光点(2026-10-02): 虚线周期 2+14=16, 每圈 dashoffset -16 = 无缝循环;
   pointer-events:none 不挡 hit path; 统一绿色 = "有真实流量"(线色仍表状态, 光效表流量) */
.t2d-flow {
  stroke: #34d399; stroke-width: 2; stroke-linecap: round; stroke-dasharray: 2 14;
  animation: t2dFlow linear infinite; pointer-events: none; opacity: .9;
  filter: drop-shadow(0 0 3px rgba(52, 211, 153, .7));
}
@keyframes t2dFlow { to { stroke-dashoffset: -16; } }
/* 框改名输入框: 悬浮在框标签锚点处(左上对齐) */
.t2d-rename { position: absolute; z-index: 30; }
.t2d-rename.rn-left { transform: translate(0, -12px); }
.t2d-rename input {
  width: 150px; font-size: 12px; padding: 2px 8px; border-radius: 4px;
  color: #eaf1fb; background: rgba(12, 20, 36, .96); border: 1px solid #38bdf8; outline: none;
}
.t2d-hit { stroke: transparent; stroke-width: 16; fill: none; pointer-events: stroke; cursor: pointer; }
/* 节点真实上下行速率(2026-10-01: 速率从线上移到设备, 真实归属):
   与 .t2d-name 同坐标系(世界坐标), 随视图缩放同步放大/缩小 —— 不做逆缩放补偿,
   用户口径"速率文字要像设备名字一样同步缩小"; 深色描边光晕保证亮/暗背景可读 */
.t2d-nrate { font-size: 9px; fill: #a5d8ff; paint-order: stroke; stroke: rgba(4, 10, 20, .85); stroke-width: 2.5px; pointer-events: none; }
/* 流量环: 设备有真实流量时绕节点流动的光弧(animateTransform 旋转驱动) */
.t2d-ring { fill: none; stroke-width: 1.6; opacity: .75; pointer-events: none; }
@keyframes t2dBreath { 0%, 100% { opacity: .9; } 50% { opacity: .35; } }
@keyframes t2dBlink { 0% { opacity: 1; } 50% { opacity: .3; } 100% { opacity: 1; } }
/* 节点 */
.t2d-node { cursor: grab; }
.t2d-node:active { cursor: grabbing; }
.t2d.dragging .t2d-stage { cursor: grabbing; }
/* 手动摆位过的节点: 虚线环提示"位置已被拖动, 右键可重置" */
.t2d-node.manual .t2d-ico { stroke-dasharray: 4 3; }
.t2d-ico { fill: #16203a; stroke-width: 2; transition: stroke .4s ease; }
.t2d-glyph { font-size: 20px; fill: #dbe6f5; pointer-events: none; }
.t2d-led { stroke: #0a1220; stroke-width: 2; }
.t2d-node.safe-red .t2d-led { animation: t2dBlink 1.2s ease-in-out infinite; }
.t2d-node.down .t2d-ico { opacity: .75; }
.t2d-node.warn .t2d-ico { animation: t2dPulseWarn 1.4s ease-in-out infinite; }
.t2d-node.error .t2d-ico { animation: t2dPulseErr 1.4s ease-in-out infinite; }
@keyframes t2dPulseWarn { 0%, 100% { stroke-width: 2; } 50% { stroke-width: 5; } }
@keyframes t2dPulseErr { 0%, 100% { stroke-width: 2; } 50% { stroke-width: 6; } }
.t2d-name { font-size: 12px; fill: #dbe6f5; pointer-events: none; }
.t2d-node.safe-gray .t2d-name { fill: #64748b; }
.t2d-node.error .t2d-name { fill: #fca5a5; }
.t2d-core { fill: none; stroke: #f5c542; stroke-width: 2.5; filter: drop-shadow(0 0 6px rgba(245, 197, 66, .8)); }
.t2d-node.sel .t2d-ico { stroke: #fbbf24; stroke-width: 3.5; filter: drop-shadow(0 0 8px #fbbf24); }
.t2d.edit .t2d-node:hover .t2d-ico { stroke: rgba(56, 189, 248, .9); }
/* 连线态: 源节点蓝色高亮环 + 画布十字光标(提示"选目标节点") */
.t2d.linking .t2d-stage { cursor: crosshair; }
.t2d-node.link-src .t2d-ico { stroke: #38bdf8; stroke-width: 3.5; filter: drop-shadow(0 0 8px #38bdf8); }
/* 子网汇总节点 */
.t2d-summary { cursor: pointer; }
.t2d-summary rect.sum-green { fill: rgba(52, 211, 153, .14); stroke: #34d399; stroke-width: 2; }
.t2d-summary rect.sum-yellow { fill: rgba(251, 191, 36, .16); stroke: #fbbf24; stroke-width: 2; }
.t2d-summary rect.sum-red { fill: rgba(248, 113, 113, .18); stroke: #f87171; stroke-width: 2; }
.t2d-summary rect.sum-gray { fill: rgba(148, 163, 184, .12); stroke: #94a3b8; stroke-width: 2; }
.t2d-summary:hover rect { stroke-width: 3.5; filter: drop-shadow(0 0 8px rgba(56, 189, 248, .6)); }
.sum-ico { font-size: 20px; fill: #dbe6f5; }
.sum-cidr { font-size: 12.5px; fill: #eaf1fb; font-variant-numeric: tabular-nums; }
.sum-count { font-size: 10.5px; fill: #9fb0c8; }
/* 面包屑 */
.t2d-crumb {
  position: absolute; left: 12px; top: 12px; z-index: 24; display: flex; align-items: center; gap: 6px;
  padding: 4px 8px; background: rgba(10, 18, 32, .78); border: 1px solid rgba(56, 132, 255, .35);
  border-radius: 8px; backdrop-filter: blur(8px); font-size: 12px;
}
.t2d-crumb-btn { background: transparent; border: none; color: #9fb0c8; font-size: 12px; cursor: pointer; padding: 2px 6px; border-radius: 4px; }
.t2d-crumb-btn:hover { color: #fff; background: rgba(56, 132, 255, .2); }
.t2d-crumb-btn.on { color: #fff; background: rgba(56, 132, 255, .3); }
.t2d-crumb-sep { color: #475569; }
.t2d-crumb-cur { color: #fbbf24; font-variant-numeric: tabular-nums; }
/* 悬浮卡 */
.t2d-hover { position: absolute; z-index: 25; width: 180px; pointer-events: none; background: rgba(10, 18, 32, .94); border: 1px solid rgba(56, 132, 255, .45); border-radius: 8px; padding: 8px 10px; box-shadow: 0 10px 28px rgba(0, 0, 0, .55); backdrop-filter: blur(6px); }
.th-h { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 5px; }
.th-h b { font-size: 12.5px; color: #eaf1fb; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.th-st { flex: 0 0 auto; font-size: 10px; border-radius: 4px; padding: 1px 6px; }
.th-st.st-normal { color: #34d399; background: rgba(52, 211, 153, .14); }
.th-st.st-warn { color: #fbbf24; background: rgba(251, 191, 36, .14); }
.th-st.st-error { color: #f87171; background: rgba(248, 113, 113, .16); }
.th-st.st-down { color: #94a3b8; background: rgba(148, 163, 184, .14); }
.th-row { display: flex; justify-content: space-between; font-size: 11.5px; color: #8295b0; padding: 2px 0; }
.th-row i { font-style: normal; color: #dbe6f5; font-variant-numeric: tabular-nums; }
.th-ip { font-family: var(--mono, monospace); }
/* 无速率时的原因说明(比留白诚实: 说明"为什么没有"而不是让人猜功能坏了) */
.th-note { color: #94a3b8 !important; font-size: 11px; max-width: 250px; text-align: right; line-height: 1.35; white-space: normal; }
/* 快捷控件 */
.t2d-ctrl { position: absolute; top: 12px; right: calc(12px + var(--ri, 0px)); z-index: 24; display: flex; align-items: center; gap: 4px; padding: 4px 6px; background: rgba(10, 18, 32, .72); border: 1px solid rgba(56, 132, 255, .35); border-radius: 8px; backdrop-filter: blur(8px); box-shadow: 0 4px 18px rgba(0, 0, 0, .4); }
.t2d-ctrl button { width: 26px; height: 24px; border-radius: 5px; cursor: pointer; color: #9fb0c8; background: transparent; border: 1px solid transparent; font-size: 13px; line-height: 1; }
.t2d-ctrl button:hover { color: #fff; background: rgba(56, 132, 255, .24); }
.t2d-ctrl-sep { width: 1px; height: 16px; background: rgba(255, 255, 255, .14); margin: 0 2px; }
/* 小地图(全局概览) */
.t2d-mm { position: absolute; left: calc(12px + var(--li, 0px)); bottom: 12px; z-index: 24; width: 180px; height: 108px; background: rgba(10, 18, 32, .78); border: 1px solid rgba(56, 132, 255, .35); border-radius: 8px; overflow: hidden; backdrop-filter: blur(8px); box-shadow: 0 4px 18px rgba(0, 0, 0, .4); cursor: crosshair; }
.t2d-mm svg { display: block; width: 100%; height: 100%; }
/* 小地图折叠按钮(2026-10-01: 挡视线可收起, 与设备树栏同口径; 收起后原位留小按钮) */
.t2d-mm-fold { position: absolute; top: 3px; right: 3px; z-index: 2; width: 18px; height: 18px; padding: 0; border-radius: 4px; cursor: pointer; color: #8295b0; background: rgba(10, 18, 32, .8); border: 1px solid rgba(56, 132, 255, .3); font-size: 12px; line-height: 1; }
.t2d-mm-fold:hover { color: #fff; background: rgba(56, 132, 255, .25); }
.t2d-mm-mini { position: absolute; left: calc(12px + var(--li, 0px)); bottom: 12px; z-index: 24; width: 30px; height: 30px; padding: 0; border-radius: 8px; cursor: pointer; color: #8295b0; background: rgba(10, 18, 32, .78); border: 1px solid rgba(56, 132, 255, .35); backdrop-filter: blur(8px); box-shadow: 0 4px 18px rgba(0, 0, 0, .4); font-size: 14px; line-height: 1; }
.t2d-mm-mini:hover { color: #fff; background: rgba(56, 132, 255, .25); }
.mm-bg { fill: rgba(56, 132, 255, .05); }
.mm-line { stroke: rgba(52, 214, 200, .28); stroke-width: 3; }
.mm-dot { stroke: none; }
.mm-dot.led-normal, .mm-sum.led-green { fill: #34d399; }
.mm-dot.led-warn, .mm-sum.led-yellow { fill: #fbbf24; }
.mm-dot.led-error, .mm-sum.led-red { fill: #f87171; }
.mm-dot.led-down, .mm-sum.led-gray { fill: #64748b; }
.mm-sum { stroke: #0a1220; stroke-width: 2; }
.mm-vp { fill: rgba(248, 113, 113, .12); stroke: #f87171; stroke-width: 2; vector-effect: non-scaling-stroke; }
/* 提示条 */
.t2d-tip { position: absolute; left: 50%; transform: translateX(-50%); bottom: 12px; z-index: 26; font-size: 12px; color: #fbbf24; background: rgba(10, 18, 32, .92); border: 1px solid rgba(251, 191, 36, .35); border-radius: 6px; padding: 3px 12px; }
/* 线上端口绑定标签: 描边底衬保证深色画布上可读。
   2026-10-02: 不再 pointer-events:none —— 标签是一等可点/可拖元素(点=选链路, 拖=移位,
   双击=复位); 事件在模板里 .stop 隔离, 不会漏到舞台触发 cancelLink/框选 */
.t2d-portlabel { font-size: 9px; fill: #8fe3b0; paint-order: stroke; stroke: rgba(8, 14, 26, .85); stroke-width: 3px; user-select: none; }
/* 画线选网口浮层(2026-10-02): 画布顶部居中, 非阻塞(画布事件照常) */
.t2d-portpick {
  position: absolute; top: 8px; left: 50%; transform: translateX(-50%); z-index: 30;
  display: flex; align-items: center; gap: 8px; max-width: calc(100% - 40px);
  background: rgba(13, 21, 38, .95); border: 1px solid rgba(56, 189, 248, .5); border-radius: 8px;
  padding: 7px 12px; box-shadow: 0 4px 18px rgba(0, 0, 0, .5);
}
.t2d-portpick .pp-t { font-size: 12px; color: #eaf1fb; white-space: nowrap; }
.t2d-portpick select {
  flex: 1; min-width: 120px; max-width: 260px; font-size: 12px; padding: 3px 8px; border-radius: 5px;
  color: #e0e6f0; background: #162032; border: 1px solid #2a3f5f; appearance: none; -webkit-appearance: none;
}
.t2d-portpick button {
  font-size: 12px; padding: 3px 12px; border-radius: 5px; cursor: pointer; white-space: nowrap;
  color: #8295b0; background: rgba(255, 255, 255, .06); border: 1px solid rgba(255, 255, 255, .15);
}
.t2d-portpick button:hover { color: #fff; background: rgba(56, 132, 255, .3); }
.t2d-portpick button.pp-ok { color: #38bdf8; border-color: rgba(56, 189, 248, .5); background: rgba(56, 189, 248, .12); }
.t2d-portpick .pp-note {
  position: absolute; top: calc(100% + 4px); left: 0; right: 0;
  font-size: 11px; color: #94a3b8; line-height: 1.5; white-space: normal;
}
/* 右键菜单 */
.t2d-menu { position: fixed; z-index: 9999; min-width: 156px; background: rgba(12, 20, 36, .97); border: 1px solid rgba(56, 132, 255, .4); border-radius: 8px; padding: 4px; box-shadow: 0 12px 34px rgba(0, 0, 0, .6); }
.t2d-menu-h { padding: 5px 12px 2px; font-size: 10.5px; color: #64748b; letter-spacing: 1px; border-top: 1px solid rgba(255, 255, 255, .06); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.t2d-menu-h:first-child { border-top: none; }
.t2d-menu button { display: block; width: 100%; text-align: left; padding: 6px 12px; font-size: 12px; color: #cdd6e4; background: transparent; border: none; border-radius: 5px; cursor: pointer; }
.t2d-menu button:hover { background: rgba(56, 132, 255, .22); color: #fff; }
.t2d-menu button.danger { color: #f87171; }
.t2d-menu button.danger:hover { background: rgba(248, 113, 113, .18); }
/* 右键菜单"添加设备…"子菜单(2026-09-30): 悬停主项在右侧展开设备库分组列表 */
.t2d-menu-item.sub { position: relative; display: block; padding: 6px 12px; font-size: 12px; color: #cdd6e4; cursor: pointer; border-radius: 5px; }
.t2d-menu-item.sub:hover { background: rgba(56, 132, 255, .22); color: #fff; }
.t2d-submenu { display: none; position: absolute; left: calc(100% - 4px); top: -4px; min-width: 150px; max-height: 320px; overflow-y: auto; background: rgba(12, 20, 36, .98); border: 1px solid rgba(56, 132, 255, .4); border-radius: 8px; padding: 4px; box-shadow: 0 12px 34px rgba(0, 0, 0, .6); z-index: 10; }
.t2d-menu-item.sub:hover .t2d-submenu { display: block; }
.t2d-sub-h { padding: 5px 12px 2px; font-size: 10.5px; color: #64748b; letter-spacing: 1px; border-top: 1px solid rgba(255, 255, 255, .06); }
.t2d-sub-h:first-child { border-top: none; }
.t2d-submenu button { display: block; width: 100%; text-align: left; padding: 5px 12px; font-size: 12px; color: #cdd6e4; background: transparent; border: none; border-radius: 5px; cursor: pointer; }
.t2d-submenu button:hover { background: rgba(56, 132, 255, .22); color: #fff; }
</style>

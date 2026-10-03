<template>
  <!-- /topology/3d 独立网络拓扑页(2026-09-28 建; 2026-09-30 用户要求:
       ① 改名"网络拓扑"(去掉 3D); ② 移除"3D 三维"视图(不能展示真实三维状态, 无意义),
       "2D 平面"改名"当前画布"; ③ 设备树底部"导入设备/重新布局"两按钮移除;
       ④ 空视图编辑态必须可加设备/加框(空态提示改为不挡操作)。
       标准运维拓扑布局: 顶部导航 + 左侧设备树 + 中部画布 + 右侧属性/告警 + 底部状态栏。
       套站内 Layout 外壳(路由不带 meta.full), 一键全屏由本页按钮触发。
       数据与 dashData 同源同主键(deviceId), 15s 轮询同步; 双模式与大屏同一套逻辑。
       TopoScene.vue(3D 场景组件)封存不再引用(文件保留, 与旧布局数据同策略)。 -->
  <div class="tp" ref="rootEl" @mousemove="onUiMouseMove" @mouseleave="hideUi">
    <!-- 顶部(全屏浏览时自动上移隐藏, 见 script"浏览模式自动隐藏"节) -->
    <div class="tp-top" ref="topBarEl" :class="{ 'ui-hidden': autohideOn && !uiTop }">
      <div class="tp-crumb">
        <a href="javascript:void(0)" @click="goHome">{{ t('topo.home') }}</a> / <span>{{ t('topo.name') }}</span>
        <a class="tp-back" href="javascript:void(0)" @click="goBigScreen">{{ t('topo.backToScreen') }}</a>
      </div>
      <div class="tp-search">
        <input v-model="kw" :placeholder="t('topo.searchPh')" @input="onKwInput" @keyup.enter="onSearchEnter" @blur="showResults = false" />
        <button type="button" @click="onSearchEnter">{{ t('topo.locate') }}</button>
        <div v-if="showResults && searchList.length" class="tp-search-list">
          <div v-for="n in searchList" :key="n.nodeId" @mousedown.prevent="onPickSearch(n)">
            <i :style="{ background: safeColor(n) }"></i>
            <span class="tp-sl-name">{{ n.name }}</span>
            <em>{{ n.ip || '—' }}</em>
          </div>
        </div>
      </div>
      <!-- 2026-09-30 用户要求: "3D 三维"移除(不能展示真实三维状态), "2D 平面"改名"当前画布"
           —— 现在只有一种画布形态, 静态标签不再做切换 -->
      <span class="tp-canvas-tag">{{ t('topo.canvasTag') }}</span>
      <!-- 框(2026-09-30 用户要求: 取消"框框设置"面板, 改按钮下拉 + 画布右键"在此添加框") -->
      <div class="tp-groups" v-if="mode === 'edit'">
        <button type="button" :class="{ on: boxesOpen }" :title="t('topo.boxTitle')" @click="boxesOpen = !boxesOpen">{{ t('topo.boxBtn') }}</button>
        <div v-if="boxesOpen" class="tp-groups-panel">
          <button type="button" class="tp-gp-add" @click="addBoxAtCenter">{{ t('topo.addBox') }}</button>
          <div class="tp-gp-note">{{ t('topo.boxNote') }}</div>
        </div>
      </div>
      <!-- 浏览/编辑: 2D/3D 通用(2026-09-30 用户要求: 3D 与 2D 一样可编辑) -->
      <div class="tp-mode">
        <button type="button" :class="{ on: mode === 'browse' }" @click="setMode('browse')">{{ t('bpro.modeBrowse') }}</button>
        <button type="button" :class="{ on: mode === 'edit' }" @click="setMode('edit')">{{ t('bpro.modeEdit') }}</button>
      </div>
      <!-- 显示设置(2026-10-02 用户要求: 顶部按钮+勾选, 控制设备名字/速率/线上网口信息显隐;
           独立页与大屏拓扑卡共用同一份偏好 LS yugsight_topo_display) -->
      <div class="tp-display">
        <button type="button" :class="{ on: dispOpen }" :title="t('topo.dispTitle')" @click="dispOpen = !dispOpen">{{ t('topo.dispBtn') }}</button>
        <div v-if="dispOpen" class="tp-display-panel">
          <label><input type="checkbox" :checked="displayCfg.name" @change="setDisplayCfg('name', $event.target.checked)" />{{ t('topo.dName') }}</label>
          <label><input type="checkbox" :checked="displayCfg.rate" @change="setDisplayCfg('rate', $event.target.checked)" />{{ t('topo.dRate') }}</label>
          <!-- 2026-10-02 v255: 光效独立开关(只影响流动光点, 不联动设备速率标签) -->
          <label :title="t('topo.flowTitle')"><input type="checkbox" :checked="displayCfg.flow" @change="setDisplayCfg('flow', $event.target.checked)" />{{ t('topo.dFlow') }}</label>
          <label><input type="checkbox" :checked="displayCfg.port" @change="setDisplayCfg('port', $event.target.checked)" />{{ t('topo.dPort') }}</label>
        </div>
      </div>
      <!-- 多套拓扑视图(2026-09-30 用户要求: 物理/逻辑子视图取消, 改多套独立视图:
           每套=完整拓扑文档(节点/链路/框/摆位), 互相不影响; 编辑即写当前视图, 自动落盘) -->
      <div class="tp-views">
        <select :value="store.active" @change="switchView($event.target.value)" :disabled="!store.views.length"
                :title="t('topo.viewsTitle')">
          <option v-for="v in store.views" :key="v.name" :value="v.name">{{ v.name }}</option>
        </select>
        <button type="button" :title="t('topo.newViewTitle')" @click="newView">{{ t('topo.new') }}</button>
        <button type="button" :title="t('topo.dupTitle')" @click="duplicateView">{{ t('topo.dup') }}</button>
        <button type="button" class="tp-v-del" :class="{ warn: deletingView === store.active }" :title="t('topo.delViewTitle')" @click="deleteViewCur">
          {{ deletingView === store.active ? t('topo.confirmDel') : t('bpro.del') }}
        </button>
        <!-- 视图轮播(2026-09-30 用户要求: 视图多了可以轮播; ≥2 套才可开; 仅浏览态转, 编辑态自动暂停) -->
        <span class="tp-v-car">
          <button type="button" :class="{ on: carOn }" :disabled="store.views.length < 2"
                  :title="t('topo.carTitle')" @click="toggleCar">
            {{ carOn ? t('topo.carOn') : t('topo.car') }}
          </button>
          <select v-if="carOn" :value="carInterval" @change="setCarInterval($event.target.value)" :title="t('topo.carInterval')">
            <option v-for="i in CAR_INTERVALS" :key="i.v" :value="i.v">{{ i.t }}</option>
          </select>
        </span>
        <!-- 新窗口分显(2026-10-02 用户要求: 多屏各显一套视图): 在新窗口打开当前选中的视图,
             新窗口钉住自己的视图不跟随全局激活, 两窗口可同时显示不同视图; 视图文档仍共享 -->
        <button type="button" :title="t('topo.newWinTitle')" @click="openViewInNewWindow">{{ t('topo.newWin') }}</button>
      </div>
      <button type="button" class="tp-fs" @click="toggleFullscreen">{{ isFs ? t('bpro.exitFullscreen') : t('bpro.fullscreenHint') }}</button>
    </div>

    <!-- 主体: 画布全幅占满(≥85%), 设备树/属性告警/控制栏全部改为半透明贴边悬浮, 不占画布空间 -->
    <div class="tp-body" :style="{ '--li': leftInset + 'px', '--ri': rightInset + 'px' }">
      <!-- 加载态: 数据未就绪 -->
      <div v-if="!ready" class="tp-state">
        <div class="tp-state-spin"></div>
        <span>{{ t('topo.loading') }}</span>
      </div>
      <!-- 画布: 编辑态即使空视图也渲染(2026-09-30 用户反馈: 新建视图2后"暂无拓扑数据"
           整层挡住画布, 编辑态下既加不了设备也加不了框) —— 空态提示只作不挡操作的覆盖层 -->
      <!-- low-zoom-scale=0.3 与大屏拓扑卡同口径: 全页画布 fit 整图时缩放常 <0.55,
           默认阈值会把光点/速率标签全藏掉(2026-10-01 用户反馈"网络拓扑里速率/光点没了") -->
      <TopoScene2D v-if="ready && (mode === 'edit' || nodes.length)" ref="sceneRef" class="tp-scene"
                   :nodes="nodes" :links="viewLinks" :devices="S.devices" :mode="mode" :low-zoom-scale="0.3"
                   :fs="isFs"
                   :boxes="boxes" :sel-box="selKind === 'box' ? selId : ''"
                   :left-inset="leftInset" :right-inset="rightInset"
                   :sel-node="selKind === 'node' ? selId : ''" :sel-link="selKind === 'link' ? selId : ''"
                   @select="onSelect" @select-multi="onMultiSelect" @dirty="onSceneDirty"
                   @delete="onDelete" @drill="onDrill"
                   @config-alert="onConfigAlert" @toggle-core="onToggleCore" @rebind="onRebind"
                   @toggle-backup="onToggleBackup" @export="onExport" @blank-click="closePanel"
                   @drop-node="onDropNode" @link-add="onAddLink" @link-check="onCheckLink"
                   @add-box="onAddBox" @box-rename="onBoxRename" @delete-box="onBoxDelete" @delete-multi="onDeleteMulti" />
      <!-- 空态提示: 编辑态=pointer-events:none 覆盖层(底下画布可加设备/加框); 浏览态=整层占位 -->
      <div v-if="ready && !nodes.length" class="tp-state" :class="{ 'no-block': mode === 'edit' }">
        <span class="tp-state-empty">{{ t('topo.empty') }}</span>
        <span class="tp-state-sub">{{ t('topo.emptyHint') }}</span>
      </div>
      <div v-if="srcTip" class="tp-src">{{ srcTip }}</div>

      <!-- 右上角实时告警条(SSE nodecollect 实时推送; 提示蓝/一般黄/严重红; 点击定位放大对应节点) -->
      <div v-if="RT.alerts.length" class="tp-alerts">
        <div class="tp-alerts-h">{{ t('topo.alerts') }} <b>{{ RT.alerts.length }}</b>
          <i class="tp-conn" :class="{ on: RT.connected }">{{ RT.connected ? t('topo.sseOn') : t('topo.sseOff') }}</i>
        </div>
        <div class="tp-alerts-list">
          <div v-for="a in RT.alerts.slice(0, 5)" :key="a.id" class="tp-alert" :class="'lv-' + a.level" @click="onAlertClick(a)">
            <i :style="{ background: ALERT_LEVEL_COLOR[a.level] }"></i>
            <div class="tp-a-b">
              <b>{{ a.name }}</b>
              <span>{{ a.content }}</span>
            </div>
            <em>{{ t(ALERT_LEVEL_CN[a.level]) }}</em>
          </div>
        </div>
      </div>

      <!-- 左侧设备树(2026-09-30 用户要求: 底部"导入设备/重新布局"两按钮移除;
           空视图首次打开的自动导入仍在 bootstrap 里做) -->
      <div class="tp-float tp-float-left" :class="{ open: leftVisible, 'ui-hidden': autohideOn && !uiLeft }">
        <TopoTree v-show="leftVisible" :nodes="nodes" :mode="mode" :sel-node="selId"
                  @pick="onTreePick" @batch-hide="batchHide"
                  @quick-add="onQuickAdd" />
        <button type="button" class="tp-tab" @click="treeOpen = !treeOpen">{{ leftVisible ? '‹' : t('topo.tree') }}</button>
      </div>

      <!-- 右侧属性面板(选中节点/链路从右侧滑出; 框选多个时显示多选清单; 点画布空白或手动 › 收起) -->
      <div class="tp-float tp-float-right" :class="{ open: rightVisible, 'ui-hidden': autohideOn && !uiRight }">
        <TopoInspector v-show="rightVisible" :sel-obj="selObj" :sel-kind="selKind" :nodes="nodes" :links="viewLinks"
                       :devices="S.devices" :last-alert="lastAlert" :mode="mode" :multi-items="multiItems"
                       @update="onUpdate" @delete="onDelete({})" @locate="locate" @close="closePanel" @check="onCheckLink" />
        <button type="button" class="tp-tab" @click="inspToggle = !inspToggle">{{ rightVisible ? '›' : t('topo.inspector') }}</button>
      </div>
    </div>

    <!-- 底部控制栏(半透明贴边悬浮): 心跳 + 关键指标 + 精简图例
         2026-10-02 用户反馈: 底部文字太啰嗦 —— 图例说明文字与"近 24h/趋势"占位块删除(未接真实数据, 纯噪音) -->
    <div class="tp-bottom">
      <!-- 心跳(2026-10-02 用户要求): 有告警/红线/节点掉线 → 红闪, 否则绿点缓脉冲 -->
      <span class="tp-hb" :class="{ bad: hbBad }" :title="hbBad ? t('topo.hbBad') : t('topo.hbOk')">
        <i></i>{{ hbBad ? t('topo.hbBadShort') : t('topo.hb') }}
      </span>
      <div class="tp-stats">
        <span>{{ t('topo.total') }} <b>{{ nodes.length }}</b></span>
        <span>{{ t('topo.onlineRate') }} <b>{{ onlineRate }}%</b></span>
        <span>{{ t('topo.avgUtil') }} <b>{{ avgUtil }}%</b></span>
        <span>{{ t('topo.avgLoss') }} <b>{{ avgLoss }}%</b></span>
        <span class="tp-src-tag" :class="{ err: !!S.errLink }" :title="S.errLink || ''">{{ t('topo.src') }}: {{ linkSourceText }}</span>
      </div>
      <!-- 精简图例(2026-10-02 用户要求: 只留四色线语义, 说明文字删) -->
      <div class="tp-legend">
        <span><i class="lg lg-green"></i>{{ t('topo.lgConn') }}</span>
        <span><i class="lg lg-red"></i>{{ t('topo.lgDown') }}</span>
        <span><i class="lg lg-untested"></i>{{ t('topo.lgUntested') }}</span>
        <span><i class="lg lg-inferred"></i>{{ t('topo.lgInferred') }}</span>
      </div>
    </div>

    <!-- 端口级下钻(右键菜单「端口详情」; 2026-09-29 改真实 SNMP 接口表, 不再 Mock)
         2026-10-02: 中央弹窗改**右侧抽屉** —— 113 口的交换机在弹窗里要滚很久还看不全
         (用户: "详情页太长了, 所以没有看到")。抽屉占满高度、表体独立滚动、表头吸顶,
         另加关键字搜索与 UP/DOWN 筛选, 一眼能定位到某个口。 -->
    <div v-if="drillNode" class="tp-drawer-mask" @click="drillNode = null"></div>
    <aside v-if="drillNode" class="tp-drawer">
      <div class="tp-dr-h">
        <div class="tp-dr-title">
          <b>{{ drillNode.name }}</b>
          <span class="tp-dr-sub">{{ drillNode.ip || '—' }} · {{ t('topo.portView') }}</span>
        </div>
        <button type="button" :title="t('topo.close')" @click="drillNode = null">×</button>
      </div>
      <div v-if="drillData && !drillData.loading && drillData.ports && drillData.ports.length" class="tp-dr-tools">
        <input v-model="portKw" class="tp-dr-kw" :placeholder="t('topo.portSearchPh')" />
        <div class="tp-dr-seg">
          <button type="button" :class="{ on: portFilter === 'all' }" @click="portFilter = 'all'">{{ t('topo.all') }} {{ drillData.ports.length }}</button>
          <button type="button" :class="{ on: portFilter === 'up' }" @click="portFilter = 'up'">UP {{ upCount }}</button>
          <button type="button" :class="{ on: portFilter === 'down' }" @click="portFilter = 'down'">DOWN {{ downCount }}</button>
        </div>
      </div>
      <div class="tp-dr-body">
        <div v-if="drillData && drillData.loading" class="tp-modal-note">{{ t('topo.portLoading') }}</div>
        <table v-else-if="portRows.length" class="tp-ports">
          <thead><tr><th>{{ t('topo.colPort') }}</th><th>{{ t('topo.colState') }}</th><th>{{ t('topo.down') }}</th><th>{{ t('topo.up') }}</th><th>{{ t('topo.bandwidth') }}</th><th>{{ t('topo.util') }}</th></tr></thead>
          <tbody>
            <tr v-for="p in portRows" :key="p.port">
              <td class="tp-port-name">{{ p.port }}</td>
              <!-- 状态未知(部分平台拿不到链路状态)显示 '-', 不冒充 DOWN -->
              <td :class="p.state === 'up' ? 'up' : (p.state === 'down' ? 'down' : '')">{{ p.state === 'up' ? 'UP' : (p.state === 'down' ? 'DOWN' : '—') }}</td>
              <td>{{ fmtBps(p.rxBps) }}</td>
              <td>{{ fmtBps(p.txBps) }}</td>
              <td>{{ p.speed > 0 ? fmtBps(p.speed) : '—' }}</td>
              <td>{{ p.util === '—' ? '—' : p.util + '%' }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="tp-modal-note">{{ (drillData && drillData.note) || t('topo.noPorts') }}</div>
      </div>
      <div v-if="drillData && drillData.note" class="tp-dr-foot">{{ drillData.note }}</div>
    </aside>

    <!-- 资产绑定弹窗(设备库拖拽生成节点后; 选纳管/发现的资产, 或跳过保持未纳管) -->
    <TopoBindDialog :open="!!bindNode" :node="bindNode" :devices="S.devices"
                    :used-ids="usedDeviceIds" @bind="onBindAsset" @skip="onSkipBind" @close="bindNode = null" />
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { useRouter, useRoute } from 'vue-router'
// TopoScene.vue(3D 场景)2026-09-30 起不再引用(用户要求移除"3D 三维"), 文件封存保留
import TopoScene2D from '../components/topo3d/TopoScene2D.vue'
import TopoTree from '../components/topo3d/TopoTree.vue'
import TopoInspector from '../components/topo3d/TopoInspector.vue'
import TopoBindDialog from '../components/topo3d/TopoBindDialog.vue'
import {
  nodeFromDevice, newNode, newLink, fillRatesByIP,
  uid,
  safeColor, normAlertLevel, ALERT_LEVEL_COLOR, ALERT_LEVEL_CN, stepDebounce, LINK_COLOR,
} from '../components/topo3d/topoModel.js'
// 多套独立拓扑视图仓库(2026-09-30: 物理/逻辑子视图取消, 每套视图=完整拓扑文档;
// 含视图轮播控制器 startViewCarousel/stopViewCarousel/loadViewCarCfg)
import {
  ensureStore, createView, deleteView, setActive,
  persistContent as persistContentViews,
  loadViewCarCfg, saveViewCarCfg, startViewCarousel, stopViewCarousel,
  displayCfg, setDisplayCfg, applyViewDeepLink,
} from '../components/topo3d/topoViews.js'
// 显示元素显隐(2026-10-02): displayCfg 与大屏 TopoCard 共享(场景直接读), 这里只管勾选面板
const dispOpen = ref(false)
// 链路活数据同步(2026-10-01: 抽共享模块, 大屏拓扑卡 TopoCard 同源复用 —— 此前大屏卡
// 只初始化一次链路, 探针上线后大屏线不恢复绿/无速率光点)
import { applyApiLinks, autoCheckManualLinks, markChecking, isChecking } from '../components/topo3d/topoLinkLive.js'
// 端口清单共享取数(2026-10-02): 端口详情抽屉与链路"按端口绑定"下拉共用同一实现,
// 防两份取数逻辑漂移(探针 ifaces / 主机采集 nic 差分 / SNMP 接口表 + 同 IP 兜底)
import { fetchNodePorts } from '../components/topo3d/topoPorts.js'
import { useShared, shared, loadNetworkLinks, setTopoCustomCount } from '../components/cards/dashData.js'
import { enterFullscreen, setFsIntent, scheduleFullscreenRestore } from '../fullscreen.js'
import { t } from '../i18n'

const S = useShared()          // 与仪表盘/大屏共用同一份 15s 轮询快照
const router = useRouter()
const route = useRoute()

const LS_MODE = 'yugsight_topo3d_mode'
// 2026-09-30 用户要求: "3D 三维"整体移除 —— 3D 坐标缓存(LS_COORD)/子布局 VIEWS/
// 3D 坐标排布(layoutLayered/Rack/Force)随之不再使用, 2D 摆位住视图文档的 px/py。

const rootEl = ref(null)
const sceneRef = ref(null)
const mode = ref(readMode())
const kw = ref('')
const selKind = ref('')
const selId = ref('')
const drillNode = ref(null)
const isFs = ref(false)
let fsHandler = null
const ready = ref(false)                     // 数据加载完成前显示加载态

// ===== 视图轮播(2026-09-30 用户要求: 视图多了可以进行轮播设置) =====
// 开关/间隔持久化(yugsight_topo_view_carousel, 默认关); 仅浏览态运行(编辑态自动暂停,
// 切回浏览恢复); 全局计时器在 topoViews.js, 大屏拓扑卡(TopoCard)与本页共用同一配置。
// 2026-10-04 i18n: 档位文案键值化, 模板渲染期 t() 解析
const CAR_INTERVALS = [
  { v: 10, t: 'topo.iv10' }, { v: 15, t: 'topo.iv15' }, { v: 30, t: 'topo.iv30' }, { v: 60, t: 'topo.iv60' },
]
const carOn = ref(false)
const carInterval = ref(15)
{ const c = loadViewCarCfg(); carOn.value = c.on; carInterval.value = c.interval }
function persistCar() {
  saveViewCarCfg({ on: carOn.value, interval: carInterval.value })
  syncCar()
}
function toggleCar() {
  if (store.views.length < 2) { flashSrc(t('topo.carNeed2')); return }
  carOn.value = !carOn.value
  persistCar()
  flashSrc(carOn.value ? t('topo.carStarted') : t('topo.carStopped'))
}
function setCarInterval(v) {
  carInterval.value = Number(v) || 15
  persistCar()
}
// 浏览态 + 已开启 + ≥2 视图 → 转; 其余情况停(编辑态/视图不足/关闭)
function syncCar() {
  if (mode.value === 'browse' && carOn.value && store.views.length >= 2) startViewCarousel(carInterval.value)
  else stopViewCarousel()
}
// (视图数/模式 的 watch 在 store 声明之后注册, 避免 setup 期 TDZ 引用)

// ===== 多套拓扑视图(2026-09-30 用户要求: 物理/逻辑子视图取消, 改多套独立视图) =====
// 每套视图 = 一份完整拓扑文档(节点/链路/框/摆位), 仓库在 topoViews.js(yugsight_topo_views_v2):
// 切换/新建/复制/删除视图互不影响; 编辑即写当前视图文档, 下方 deep watch 防抖落盘。
// 旧版物理分层盒/逻辑业务组(yugsight_topo_groups_v1)与旧全局布局(key)不再被引用。
const store = ensureStore()
// 视图轮播启停: 切浏览/编辑 或 视图数变化(增删到 <2)时即时同步(定义在 store 之后防 TDZ)
watch(mode, syncCar)
watch(() => store.views.length, syncCar)
const curView = computed(() => store.views.find(v => v.name === store.active) || store.views[0] || null)
// nodes/links/boxes = 当前视图文档的引用; filter 重建赋值也回写视图对象(计算属性 setter)
const nodes = computed({ get: () => (curView.value ? curView.value.nodes : []), set: v => { if (curView.value) curView.value.nodes = v } })
const links = computed({ get: () => (curView.value ? curView.value.links : []), set: v => { if (curView.value) curView.value.links = v } })
const boxes = computed({ get: () => (curView.value ? curView.value.boxes : []), set: v => { if (curView.value) curView.value.boxes = v } })
// 落盘(2026-09-30 性能修复): 旧 "curView deep watch" 对整份文档(数百节点+链路)
// 做深度遍历, 拖拽时每次属性写(每帧)都触发一次全量遍历 → 编辑拖拽/缩放卡顿
// ("过一会儿又正常"=拖完不再写)。改为三路:
// ① 场景几何变更(拖拽/整体缩放/标签移动/重置摆位结束) → 场景 emit dirty → 防抖写盘;
// ② 结构变更(节点/链路/框数组整体替换) → curView 浅 watch 触发;
// ③ 轮询状态同步不写盘(状态是派生数据, 刷新后由轮询重新同步, 无需持久化)。
// 2026-10-02: 内容落盘走 persistContentViews(给当前视图打 v.upd 戳, 按视图合并基准,
// 见 topoViews"每视图版本"节); 切视图(setActive 置 switchFlag)触发的 watch 那一次
// 消费标记不打戳 —— 防轮播切视图让每个视图都变"最新"。
let pvT = null
function schedulePersist() {
  if (pvT) clearTimeout(pvT)
  pvT = setTimeout(() => { persistContentViews(); syncCustomCount() }, 300)
}
watch(curView, schedulePersist)   // 浅监听: 顶层属性(数组引用)变化才触发
const sceneDirtyTick = ref(0)
watch(sceneDirtyTick, schedulePersist)
function onSceneDirty() { sceneDirtyTick.value++ }
// 框选多选清单(≥2 项): 属性面板显示"设备/框清单"视图(用户 2026-09-30 要求)
const multiItems = ref(null)
function onMultiSelect(items) {
  multiItems.value = Array.isArray(items) && items.length >= 2 ? items : null
  if (multiItems.value) inspToggle.value = true
}
function switchView(name) {
  if (!store.views.some(v => v.name === name) || name === store.active) return
  setActive(name)   // 2026-10-02: 统一入口置切视图标记(curView 变化触发的 watch 那次 persist 不打 v.upd 戳)
  selKind.value = ''; selId.value = ''; multiItems.value = null
  requestAnimationFrame(() => {
    const scn = sceneRef.value
    if (scn && typeof scn.fitToView === 'function') scn.fitToView()
  })
  // 2026-10-01: 新视图的链路速率/光点状态要等下一轮 15s 拍才补全 → 切完视图
  // "光点消失了、过一会儿才有"。切完立即同步一次(幂等, 与轮询拍同函数)
  syncLinkLive()
  flashSrc(t('topo.viewSwitched', { name }))
}
function newView() {
  const name = (window.prompt(t('topo.newViewPrompt'), t('topo.viewN', { n: store.views.length + 1 })) || '').trim()
  if (!name) return
  if (store.views.some(v => v.name === name)) { flashSrc(t('topo.dupName')); return }
  createView(name)
  requestAnimationFrame(() => { const scn = sceneRef.value; if (scn && scn.fitToView) scn.fitToView() })
  flashSrc(t('topo.viewCreated', { name }))
}
function duplicateView() {
  const v = curView.value
  if (!v) return
  const name = (window.prompt(t('topo.dupViewPrompt'), v.name + '_' + t('topo.copySuffix')) || '').trim()
  if (!name) return
  if (store.views.some(x => x.name === name)) { flashSrc(t('topo.dupName')); return }
  createView(name, v)
  requestAnimationFrame(() => { const scn = sceneRef.value; if (scn && scn.fitToView) scn.fitToView() })
  flashSrc(t('topo.viewDuplicated', { from: v.name, to: name }))
}
const deletingView = ref('')
function deleteViewCur() {
  const name = store.active
  if (store.views.length <= 1) { flashSrc(t('topo.keepOne')); return }
  if (deletingView.value !== name) { deletingView.value = name; return }   // 二连击确认防误删
  deletingView.value = ''
  if (deleteView(name)) flashSrc(t('topo.viewDeleted', { name }))
}
// ===== 新窗口分显(2026-10-02 用户要求: 多屏各显一套视图) =====
// 开新窗口带 ?view=<当前视图>: 新窗口加载后 applyViewDeepLink 钉住该视图(见 topoViews.js
// "新窗口分显钉住"节) —— 两个窗口各自显示各自的视图、互不跟随对方的视图切换; 视图文档
// (节点/链路/框)仍是同一份(跨窗口共享, 一边编辑 30s 内另一边可见)。按钮在视图下拉旁,
// 先用下拉选好要开的视图再点"新窗口"。
function openViewInNewWindow() {
  const name = store.active
  if (!name) { flashSrc(t('topo.noViewToOpen')); return }
  const url = location.origin + location.pathname + '#/topology/3d?view=' + encodeURIComponent(name)
  const w = window.open(url, '_blank')
  flashSrc(w ? t('topo.viewOpened', { name }) : t('topo.popupBlocked'))
}

// ===== 框(2026-09-30 用户要求: 取消"框框设置"面板, 改按钮下拉 + 画布右键) =====
// 框 = 当前视图文档里的自由矩形(boxes), 纯组织元素(视觉上圈住设备):
// 拖拽移动/拉角缩放/双击改名由场景直接改对象(deep watch 防抖落盘); 添加/删除经场景 emit 回来。
const boxesOpen = ref(false)
function addBoxAt(x, y) {
  const b = { id: uid('box'), name: t('topo.boxN', { n: boxes.value.length + 1 }), x: Math.round(x - 140), y: Math.round(y - 80), w: 280, h: 160 }
  boxes.value.push(b)
  selKind.value = 'box'; selId.value = b.id; inspToggle.value = true   // 选中新框 → 属性面板打开(与设备同)
  return b
}
function onAddBox({ x, y }) {
  addBoxAt(x, y)
  flashSrc(t('topo.boxAdded'))
}
function addBoxAtCenter() {
  boxesOpen.value = false
  addBoxAt(600, 360)
  flashSrc(t('topo.boxAdded'))
}
function onBoxRename({ id, name }) {
  const b = boxes.value.find(x => x.id === id)
  if (b && name && name !== b.name) { b.name = name; persist(); flashSrc(t('topo.boxRenamed', { name })) }   // 就地改名不触发浅 watch, 显式落盘
}
function onBoxDelete({ id }) {
  const b = boxes.value.find(x => x.id === id)
  boxes.value = boxes.value.filter(x => x.id !== id)
  if (selKind.value === 'box' && selId.value === id) { selKind.value = ''; selId.value = '' }
  flashSrc(t('topo.boxDeleted', { name: b ? b.name : '' }))
}
// 框选批量删除(2026-10-01 用户要求): 框选多台设备/多框后右键 → "删除选中的设备和框"。
// 先弹确认(不可撤销 + 设备级联删链路), 确认后才动数据; 删框不动框内设备(框只是视觉组织)。
function onDeleteMulti(items) {
  if (!Array.isArray(items) || !items.length) return
  const nCnt = items.filter(x => x.kind === 'n').length
  const bCnt = items.filter(x => x.kind === 'b').length
  const what = [nCnt ? t('topo.devCount', { n: nCnt }) : '', bCnt ? t('topo.boxCount', { n: bCnt }) : ''].filter(Boolean).join(', ')
  if (!confirm(t('topo.multiDelConfirm', { what }))) return
  for (const it of items) {
    if (it.kind === 'n') {
      const n = nodes.value.find(x => x.nodeId === it.id)
      const devId = n ? n.deviceId : ''
      nodes.value = nodes.value.filter(x => x.nodeId !== it.id)
      if (devId) links.value = links.value.filter(l => l.fromDeviceId !== devId && l.toDeviceId !== devId)
    } else if (it.kind === 'b') {
      boxes.value = boxes.value.filter(b => b.id !== it.id)
    }
  }
  selKind.value = ''; selId.value = ''; multiItems.value = null
  if (sceneRef.value && sceneRef.value.clearSelection) sceneRef.value.clearSelection()
  persist()
  flashSrc(t('topo.multiDeleted', { what }))
}

// ===== 悬浮面板(半透明贴边, 不占画布) =====
// 画布是全幅的, 设备树/属性告警浮在画布之上; 折叠时场景内的小地图/快捷控件
// 会随 inset 让位(传给 TopoScene 的 left-inset / right-inset)。
// 2026-10-01 用户反馈: "浏览模式时设备树和属性栏不要显示在画布内, 保持画面干净":
// 浏览模式=只读值守视图 → 两栏默认收起(画布干净, 节点详情悬浮卡已有);
// 编辑模式=管理操作 → 两栏默认展开(2026-09-29 "看不到东西" 反馈的原始口径)。
// 切换模式联动开合; 手动点侧边标签在任一模式下仍可随时开合。
const treeOpen = ref(mode.value !== 'browse')
const inspToggle = ref(mode.value !== 'browse')
const inspVisible = computed(() => inspToggle.value)

// ===== 浏览模式自动隐藏(2026-10-02 用户要求): 值守画面零界面 =====
// 浏览模式下顶栏/左设备树/右属性栏默认全部隐藏(顶栏上移滑出、两侧侧滑淡出),
// 鼠标进入对应边缘热区或面板本体才滑出, 移出自动再隐藏;
// 编辑模式保持原行为: 常驻显示 + 侧边标签手动开合。
// 2026-10-02 用户追加: "没有全屏时不需要缩上去" —— 自动隐藏只在**全屏**(值守/大屏墙)生效;
// 窗口浏览 = 自动隐藏前的行为(顶栏常驻, 设备树/属性栏=侧边标签点击展开)
const isBrowseMode = computed(() => mode.value === 'browse')
const autohideOn = computed(() => isBrowseMode.value && isFs.value)
const uiTop = ref(false)
const uiLeft = ref(false)
const uiRight = ref(false)
const topBarEl = ref(null)
const leftVisible = computed(() => (autohideOn.value ? uiLeft.value : treeOpen.value))
const rightVisible = computed(() => (autohideOn.value ? uiRight.value : inspVisible.value))
// 场景 inset 只在自动隐藏时归零: 全屏浏览的面板是悬浮叠层(悬停滑出),
// 小地图/底部控制栏位置保持稳定; 窗口浏览按开合状态正常让位
const leftInset = computed(() => (autohideOn.value ? 0 : (treeOpen.value ? 232 : 0)))
const rightInset = computed(() => (autohideOn.value ? 0 : (inspVisible.value ? 284 : 0)))
// 边缘热区(2026-10-03 用户拍板口径): **贴到边缘才弹** —— 触发区固定 10px。
// 演进: 44px 被反馈"没靠近就弹出来" → 试了 5% 视口自适应(更宽)同被否
// (在画布边缘附近悬停/拖节点就会弹, 干扰操作) → 用户明确"我要靠到边缘的才弹"。
// 迟滞: 已显示时指针仍在面板体内(左≤250 / 右≤290 / 顶≤栏高+12)保持显示, 防贴边抖动
function onUiMouseMove(e) {
  if (!autohideOn.value || !rootEl.value) return
  const r = rootEl.value.getBoundingClientRect()
  const x = e.clientX - r.left
  const y = e.clientY - r.top
  if (x < 0 || y < 0 || x > r.width || y > r.height) return
  const barH = topBarEl.value ? topBarEl.value.offsetHeight : 56
  const EDGE = 10   // 贴边触发阈值(px): 鼠标必须压到屏幕边缘
  uiTop.value = y < EDGE || (uiTop.value && y < barH + 12)
  uiLeft.value = x < EDGE || (uiLeft.value && x < 250)
  uiRight.value = (r.width - x) < EDGE || (uiRight.value && (r.width - x) < 290)
}
function hideUi() { uiTop.value = false; uiLeft.value = false; uiRight.value = false }

function readMode() {
  // 2026-09-29 用户反馈: 从大屏卡进来第一眼要能找到编辑入口 —— 默认编辑模式
  // (设备库/右键连线/属性面板全在编辑态), 用户切过浏览则记住其选择。
  try { return localStorage.getItem(LS_MODE) === 'browse' ? 'browse' : 'edit' } catch (e) { return 'edit' }
}
function setMode(m) {
  mode.value = m
  try { localStorage.setItem(LS_MODE, m) } catch (e) { /* 忽略 */ }
  if (m === 'browse') {
    selKind.value = ''; selId.value = ''   // 切浏览: 清选中(只读视图)
    treeOpen.value = false; inspToggle.value = false   // 浏览=干净画面: 两栏收起(2026-10-01 用户口径)
    hideUi()                                  // 三块界面全部滑出(2026-10-02 自动隐藏)
  } else {
    treeOpen.value = true; inspToggle.value = true   // 编辑=管理操作: 两栏展开
  }
}

// ===== 拓扑实例数据(2026-09-30: 住在当前视图文档里, 见上方"多套拓扑视图"节) =====
// persist = 立即落盘当前视图(yugsight_topo_views_v2); 常规变更由 deep watch 防抖兜底,
// 结构增删(节点/链路/框)时立即调, 防 300ms 内关页丢改动。
// 2026-10-02: 内容变更语义 → persistContentViews(打当前视图 v.upd 戳)
function persist() {
  persistContentViews()
  syncCustomCount()   // 结构变化后同步自定义节点计数给大屏缩略卡
}
// 自定义节点 = deviceId 以 U_ 开头(手动新增), 与纳管(P_)/资产(A_)区分
// (3D 坐标缓存 LS_COORD / 3D 布局 relayout / 设备树"重新布局"随"3D 三维"一并移除,
//  2D 摆位持久化在视图文档的 px/py, 由 topoViews 落盘)
function syncCustomCount() {
  const c = nodes.value.filter(n => String(n.deviceId || '').indexOf('U_') === 0).length
  setTopoCustomCount(c)
}

// 导入纳管设备(已存在 deviceId 不重复生成)
// 2026-10-01 用户反馈"那资产管理的台账表的 IP 全进这个拓扑里？？?"——旧实现把
// S.devices 全量灌入(含资产台账全部 A_*), 空视图一开就是满屏陌生节点。口径改为
// 只自动导入纳管设备(探针 P_*/节点监控 M_*/采集任务 C_*, isMonitor 标记): 拓扑是
// "我监控的网络", 不是资产台账的镜像; 台账资产要进拓扑仍可从设备树手动拖入。
function importDevices() {
  const list = (S.devices || []).filter(d => d.isMonitor)
  if (!list.length) { flashSrc(t('topo.noMonitored')); return }
  let added = 0
  for (const d of list) {
    if (nodes.value.some(n => n.deviceId === d.deviceId)) continue
    nodes.value.push(nodeFromDevice(d, added))
    added++
  }
  // 2026-10-01: 不再自动填充后端按网段猜的链路集 —— 推测边被误读成"两端直连"
  // (用户: "192.168.1.1 和 172.16.199.1 连线为什么也是绿的?"); 链路由用户自己画。
  flashSrc(added ? t('topo.imported', { n: added }) : t('topo.noNewDev'))
}
// 首次进入: 当前视图已有内容(旧版迁移/用户此前编辑)不动; 否则导入纳管设备。
// 2026-10-01: 删除示例假节点分支(路由器/核心交换机/防火墙…, 无 IP 无真实数据)——
// 值守者会把它们当成真实设备, 与大屏卡"刻意不用演示节点"同口径; 空画布走场景
// 空态提示(设备树/画布右键添加), 无数据不编造。
function bootstrap() {
  if (curView.value.nodes.length) { return true }
  importDevices()
  return false
}
// 设备列表(S.devices)是 15s 轮询的异步源: 页面首进时第一拍可能还没回来, 立即
// bootstrap 会导入落空(2026-10-01 真机 E2E: 首访直接进了假节点分支)。等第一拍
// 设备数据到达再执行(与 TopoCard 的 devUpdatedAt watch 兜底同口径); 8s 超时
// 无数据(设备接口全挂)照常执行 —— 空画布出引导, 比假节点诚实。
function bootstrapWait() {
  if ((S.devices || []).length || S.devUpdatedAt) return bootstrap()
  return new Promise((resolve) => {
    let done = false
    const stop = watch(() => S.devUpdatedAt, () => {
      if (done) return
      done = true; stop()
      resolve(bootstrap())
    })
    setTimeout(() => {
      if (done) return
      done = true; stop()
      resolve(bootstrap())
    }, 8000)
  })
}
onMounted(async () => {
  isFs.value = !!document.fullscreenElement
  fsHandler = () => { isFs.value = !!document.fullscreenElement }
  document.addEventListener('fullscreenchange', fsHandler)
  // 刷新后恢复全屏: 意图在(上次没退出)且当前不在全屏 → 首个交互即重新进入
  fsRestoreCleanup = scheduleFullscreenRestore()
  // 新窗口分显深链(2026-10-02): ?view=<名称> 激活并钉住该视图 —— 必须在 bootstrap 之前,
  // 否则空的目标视图会被"默认视图"的自动导入逻辑带偏(bootstrap 只认当前激活视图)
  const qv = String((route.query || {}).view || '')
  if (qv) {
    if (applyViewDeepLink(qv)) flashSrc(t('topo.winPinned', { name: qv }))
    else if (store.views.length) flashSrc(t('topo.viewNotFound', { name: qv }))
    // 视图未载入(服务器文档未拉回)时 applyViewDeepLink 挂起, 文档回落时自动补激活
  }
  // 多套视图仓库在 setup 时已由 ensureStore() 载入(含旧版布局一次性迁移)
  const restored = await bootstrapWait()
  // 链路: 复用 dashData 的加载方法(真实数据, 见 dashData.loadNetworkLinks)
  await loadNetworkLinks(nodes.value)
  // 2026-10-01: 不再自动填充后端推测的链路集(同 importDevices 注释: 推测边被误读成
  // "两端直连"); 新视图 = 只导入纳管设备节点, 连线由用户自己画(右键"从此节点连线")。
  // 初始在线起始时间(供存活时长展示): 存活时长是"本会话内"口径 —— 每次进入都从现在起算,
  // 无条件覆盖(避免 persist 序列化出的上一会话陈旧时间戳, 刷新后误显示"存活数小时")
  for (const n of nodes.value) n._onlineSince = (n.status !== 'down') ? Date.now() : 0
  connectSSE()       // 实时告警 + 状态防抖(SSE nodecollect)
  startAlertClean()
  applyQueryFocus()
  ready.value = true // 数据就绪, 关闭加载态
  syncCar()          // 视图轮播: 浏览态 + 已开启 才转(编辑态默认进入时不转)
})

// 跨模块联动入参: ?device=<deviceId> 精确定位; ?focus=<IP/CIDR> 按扫描范围匹配节点 IP
function applyQueryFocus() {
  const q = route.query || {}
  setTimeout(() => {
    if (q.device) { locate(String(q.device)); return }
    const f = q.focus ? String(q.focus) : ''
    if (!f) return
    const pre = f.split('/')[0].split('.').slice(0, 3).join('.')
    const n = nodes.value.find(x => (x.ip || '').indexOf(pre) === 0)
    if (n) locate(n.deviceId)
  }, 300)
}

// 链路活数据统一入口: 后端覆盖(状态/利用率, 只覆盖不增删) + 实画线自动连通测试。
// 2026-10-01: 线上速率补全(syncManualLinkRates)已删 —— 速率只挂在设备节点(真实归属),
// 链路不表达流量(口径见 topoLinkLive.js 头注释)。三个入口都走本函数, 全部幂等。
function syncLinkLive(api) {
  applyApiLinks(links.value, api || S.networkLinks)
  autoCheckManualLinks(nodes.value, links.value, (l) => onCheckLink(l, true))  // 设备在线 → 自动连通测试
}

// 纳管节点状态随 15s 轮询同步 —— 状态经防抖(连续 3 次异常才翻态, 防抖动频繁跳变), 指标直取
// 2026-10-01: 手动链路速率补全/自动连通测试抽到共享模块 topoLinkLive.js
// (大屏拓扑卡 TopoCard 同源复用, 口径见该文件头注释)
watch(() => S.devUpdatedAt, () => {
  for (const n of nodes.value) {
    if (!n.isMonitor) continue
    const d = (S.devices || []).find(x => x.deviceId === n.deviceId)
    if (!d) continue
    n.cpu = d.cpu; n.memory = d.memory
    // 设备真实上下行(SNMP 两帧差分) → 节点名字下方速率标签 + 流量环(2026-10-01:
    // 速率从线上移到设备, 场景按 n.inBps/n.outBps 渲染; 无数据=0=不显示)
    n.inBps = d.inRateBps || 0
    n.outBps = d.outRateBps || 0
    applyNodeStatus(n, d.status)
    if (d.ip) n.ip = d.ip
    if (d.mac) n.mac = d.mac
  }
  // 资产台账手动拖入的节点(A_*, isMonitor=false)按 IP 补全真实速率(见 fillRatesByIP)
  fillRatesByIP(nodes.value, S.devices)
  syncLinkLive()
})

// 2026-10-01: 视图轮播(store.active 周期变化)切到另一套视图时, 新视图的链路速率/
// 光点状态同样要等下一轮 15s 拍才补全 —— 表现为"光点有了又没了"。视图切换立即
// 同步(与 switchView 手动切换共用同一幂等函数)。
watch(curView, () => { syncLinkLive() })

// ===== 实时推送(SSE) + 状态防抖 + 右上角告警缓冲 =====
// 复用 /api/events 的 nodecollect 事件(后端采集引擎已在广播, 前端此前零消费):
//   ① 节点状态走防抖(stepDebounce): 连续 3 次观测到异常才真正翻态, 避免网络抖动导致颜色频繁跳变
//   ② 告警进右上角缓冲(提示蓝/一般黄/严重红), 点击定位放大; 与轮询共用同一 streak 防抖态
const RT = reactive({ alerts: [], connected: false })
const streak = new Map()      // nodeId -> {pending, n}
let es = null
let alertSeq = 0
let cleanT = null
const ALERT_TTL = 120000      // 告警条保留 2 分钟(足够点击定位, 不无限堆积)

function nodeByTarget(target) {
  const t = String(target || '').trim()
  if (!t) return null
  const ns = nodes.value
  return ns.find(n => n.ip === t) || ns.find(n => (n.ips || []).includes(t)) || ns.find(n => n.name === t) || null
}
// 防抖应用: 连续 3 次异常才翻态; 恢复(normal)立即生效。翻态时更新在线起始时间(供存活时长)
function applyNodeStatus(n, raw) {
  if (!n) return
  const st = streak.get(n.nodeId) || { pending: '', n: 0 }
  const next = stepDebounce(n.status, raw, st)
  if (next !== n.status) {
    n.status = next
    if (next !== 'down' && !n._onlineSince) n._onlineSince = Date.now()
    if (next === 'down') n._onlineSince = 0
  }
  streak.set(n.nodeId, st)
}
function pushAlert(a) {
  const item = { id: 'a' + (alertSeq++), at: Date.now(), ...a }
  RT.alerts.unshift(item)
  if (RT.alerts.length > 30) RT.alerts.length = 30
}
// SSE nodecollect: {type, level, task, target, msg, at}; target=设备 IP
function handleCollect(ev) {
  if (!ev) return
  const lv = normAlertLevel(ev.level)
  const n = nodeByTarget(ev.target)
  if (n) {
    const raw = ev.type === 'recover' ? 'normal' : (lv === 'critical' ? 'error' : 'warn')
    applyNodeStatus(n, raw)
  }
  pushAlert({
    level: lv,
    deviceId: n ? n.deviceId : '',
    name: n ? n.name : (ev.target || '?'),
    content: ev.msg || ev.type || t('topo.alertAbnormal'),
    source: 'sse',
  })
}
function connectSSE() {
  try {
    es = new EventSource('/api/events')
    es.addEventListener('nodecollect', (e) => { try { handleCollect(JSON.parse(e.data)) } catch (_) { /* 忽略坏帧 */ } })
    // 链路状态即时推送(后端 5s 节流): 覆盖后必须立刻补全端点速率, 否则 SSE 的
    // "无速率即清空"会压掉补全, 光点又被清掉(与 15s 轮询同口径, 走 syncLinkLive)
    es.addEventListener('topolink', (e) => { try { syncLinkLive(JSON.parse(e.data).links) } catch (_) { /* 忽略坏帧 */ } })
    es.onopen = () => { RT.connected = true }
    es.onerror = () => { RT.connected = false }   // EventSource 会自动重连, 这里只更新指示
  } catch (_) { RT.connected = false }
}
function startAlertClean() {
  cleanT = setInterval(() => {
    const now = Date.now()
    RT.alerts = RT.alerts.filter(a => now - a.at < ALERT_TTL)
  }, 15000)
}
// 选中节点最近一条告警(供属性面板「最近告警」展示)
const lastAlert = computed(() => {
  if (!selId.value || selKind.value !== 'node') return null
  const n = nodes.value.find(x => x.nodeId === selId.value)
  if (!n) return null
  return RT.alerts.find(a => a.deviceId === n.deviceId) || null
})
function onAlertClick(a) {
  if (a.deviceId) { locate(a.deviceId); flashSrc(t('topo.alertLocated', { name: a.name })) }
}

// ===== 选中 / 增删改 =====
const selObj = computed(() => {
  if (!selId.value) return null
  if (selKind.value === 'node') return nodes.value.find(n => n.nodeId === selId.value) || null
  if (selKind.value === 'box') return boxes.value.find(b => b.id === selId.value) || null
  return links.value.find(l => l.linkId === selId.value) || null
})
function onSelect(p) {
  selKind.value = p.kind
  selId.value = p.id
  // 2026-10-01: 浏览模式下点选不自动弹属性面板(保持画面干净, 详情用节点悬浮卡);
  // 编辑模式保持原行为: 选中 → 右侧属性面板滑出(点画布空白或手动 › 收起)
  if (mode.value !== 'browse') inspToggle.value = true
  // 注意: 多选清单在 select 之后由 select-multi 事件统一设置(场景保证顺序), 这里不清
}
function closePanel() { inspToggle.value = false; selKind.value = ''; selId.value = ''; multiItems.value = null }
function onAddNode({ type, x, y }) {
  const n = newNode(type, x, y)
  n.px = Math.round(x); n.py = Math.round(y)   // 钉住放置点(2D 自由摆位, 无自动布局挪动)
  nodes.value.push(n)
  selKind.value = 'node'; selId.value = n.nodeId
  persist()
}
function onAddLink({ fromDeviceId, toDeviceId, fromPort }) {
  if (links.value.some(l => (l.fromDeviceId === fromDeviceId && l.toDeviceId === toDeviceId) ||
    (l.fromDeviceId === toDeviceId && l.toDeviceId === fromDeviceId))) {
    flashSrc(t('topo.linkExists'))
    return
  }
  const a = nodes.value.find(n => n.deviceId === fromDeviceId)
  const b = nodes.value.find(n => n.deviceId === toDeviceId)
  if (!a || !b) return
  const l = newLink(a, b)
  if (fromPort) l.fromPort = fromPort   // 画线时选定的本端网口(2026-10-02)
  links.value.push(l)
  selKind.value = 'link'; selId.value = l.linkId
  persist()
  flashSrc(t('topo.linkCreated', { a: a.name, b: b.name }))
}

// ===== 设备库拖拽生成节点 + 资产绑定(Zabbix 式元素绑定流程, 2026-09-29) =====
const bindNode = ref(null)
const usedDeviceIds = computed(() => nodes.value.map(n => n.deviceId))
function onDropNode({ type, x, y }) {
  const n = newNode(type, x, y)
  n.px = Math.round(x); n.py = Math.round(y)   // 钉住落点(2D 自由摆位: 无自动布局挪动)
  nodes.value.push(n)
  persist()
  bindNode.value = n   // 弹出节点绑定
}
// 设备库"＋"一键添加(2026-09-29 用户要求"设备不是可以添加吗"): 点类型直接落画布中心
// (随机小偏移防重叠), 走与拖拽完全相同的 生成节点→资产绑定 流程
function onQuickAdd(type) {
  onDropNode({ type, x: 540 + Math.random() * 120, y: 300 + Math.random() * 120 })
}
// ===== 链路连通性测试(2026-09-29 用户要求: 连接起来后要测连通, 没连上不算通) =====
// 前端只画线, "通不通"必须由中心端真实探测 —— 调 /api/v2/topology/links/check
// (ICMP echo, 无权限时降级 TCP 端口探测) 测两端 IP, 结果写回链路并持久化:
//   未测 = 灰虚线"未测"; 两端可达 = 绿"已连通"; 否则 = 红"未连通"。
// 2026-10-01: 放开对 _real 线的限制 —— 推测边(系统按网段猜的)用户可手动实测,
// 测过就显示真实结果(实测优先于推测, 并参与 5min 复验)。
// silent=true: 自动测试入口(不弹提示, 结果静默写回, 属性面板里可查) ——
// 2026-09-30 起两端在线的手动链路会自动发起测试, 弹提示会变成每 30s 一条的噪音。
async function onCheckLink(l, silent) {
  if (!l || isChecking(l)) return
  const a = nodes.value.find(n => n.deviceId === l.fromDeviceId)
  const b = nodes.value.find(n => n.deviceId === l.toDeviceId)
  const ips = [a && a.ip, b && b.ip].filter(x => x && /^\d{1,3}(\.\d{1,3}){3}$/.test(x))
  if (ips.length < 2) {
    if (!silent) flashSrc(t('topo.checkNeedIp'))
    return
  }
  l._checking = true            // UI"测试中…"按钮态
  markChecking(l, true)         // 调度器在途标记(纯内存, 不进 LS)
  try {
    const d = await apiV2('/api/v2/topology/links/check', { method: 'POST', body: { ips } })
    l.tested = true
    l.checkedAt = Date.now()
    l.status = d.ok ? 'normal' : 'down'
    l._check = d
    persist()
    if (!silent) flashSrc(d.ok
      ? t('topo.checkPass', { a: a ? a.name : '?', b: b ? b.name : '?' })
      : t('topo.checkFail', { detail: (d.results || []).map(r => r.ip + (r.up ? '✓' : '✗')).join(' / ') }))
  } catch (e) {
    if (!silent) flashSrc(t('topo.checkError', { err: (e && e.message) || e }))
  } finally {
    l._checking = false
    markChecking(l, false)
  }
}

// v2 API 小工具(同域 cookie 鉴权; Resp{code,message,data} 拆包, 与 http.js 同口径)
async function apiV2(path, { method = 'GET', body } = {}) {
  const r = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  if (r.status === 401) { flashSrc(t('topo.loginExpired')); throw new Error(t('topo.notLogged')) }
  if (!r.ok) throw new Error('HTTP ' + r.status)
  const o = await r.json()
  if (o && o.code != null && o.code !== 0) throw new Error(o.message || t('topo.reqFail'))
  return (o && o.data != null) ? o.data : o
}
// 绑定 = 接管该设备: deviceId 改为设备主键(15s 轮询按 deviceId 同步状态),
// 引用旧 deviceId 的链路同步迁移(否则连线关系断掉)。
function onBindAsset(d) {
  const n = bindNode.value
  bindNode.value = null
  if (!n || !d) return
  const oldId = n.deviceId
  n.deviceId = d.deviceId
  for (const l of links.value) {
    if (l.fromDeviceId === oldId) l.fromDeviceId = d.deviceId
    if (l.toDeviceId === oldId) l.toDeviceId = d.deviceId
  }
  n.isMonitor = true
  n.ip = d.ip || n.ip
  n.mac = d.mac || n.mac
  n.status = d.status || 'normal'
  n.cpu = d.cpu || 0
  n.memory = d.memory || 0
  if (d.ips) n.ips = d.ips
  persist()
  flashSrc(t('topo.bindDone', { name: d.name || d.ip }))
}
function onSkipBind() {
  const n = bindNode.value
  bindNode.value = null
  if (n) flashSrc(t('topo.skipBind'))
}
// 删除: 节点删除时级联删关联链路(只剩一端的链路是断线, 留着会误导排障)
function onDelete(p) {
  const nodeId = (p && p.nodeId) || (selKind.value === 'node' ? selId.value : '')
  const linkId = (p && p.linkId) || (selKind.value === 'link' ? selId.value : '')
  const boxId = (p && p.boxId) || (selKind.value === 'box' ? selId.value : '')
  if (nodeId) {
    const n = nodes.value.find(x => x.nodeId === nodeId)
    const devId = n ? n.deviceId : ''
    nodes.value = nodes.value.filter(x => x.nodeId !== nodeId)
    links.value = links.value.filter(l => l.fromDeviceId !== devId && l.toDeviceId !== devId)
  } else if (boxId) {
    boxes.value = boxes.value.filter(b => b.id !== boxId)   // 删框不动框内设备(框只是视觉组织)
  } else if (linkId) {
    links.value = links.value.filter(l => l.linkId !== linkId)
  }
  selKind.value = ''; selId.value = ''; multiItems.value = null
  persist()
}
function onUpdate({ k, v }) {
  if (selObj.value) selObj.value[k] = v   // 直接改对象引用 → 场景实时重渲染
  persist()
}
// (2D 拖拽摆位由场景 emit 'dirty' → onSceneDirty 防抖落盘; 3D 坐标缓存/重置随"3D 三维"移除)
// ===== 端口详情(2026-09-29 用户反馈: 数据必须是真, 主机不该有交换机端口表) =====
// 取数(探针 ifaces / 主机采集 nic 差分 / SNMP 接口表 + 同 IP 兜底)在 topoPorts.js,
// 与链路"按端口绑定"下拉共用(2026-10-02); 这里只管抽屉的展示与筛选状态。
const drillData = ref(null)   // { loading } | { ports: [], note, at } | { note }

// 抽屉内筛选(2026-10-02): 113 口全表滚不完, 关键字 + UP/DOWN 分段是定位的主要手段。
// 每次打开重置(换设备时不应带着上一次的过滤条件)。
const portKw = ref('')
const portFilter = ref('all')   // all | up | down
const portRows = computed(() => {
  const list = (drillData.value && drillData.value.ports) || []
  const kw = portKw.value.trim().toLowerCase()
  return list.filter(p => {
    if (portFilter.value === 'up' && !p.up) return false
    if (portFilter.value === 'down' && p.up) return false
    if (kw && !String(p.port || '').toLowerCase().includes(kw)) return false
    return true
  })
})
const upCount = computed(() => ((drillData.value && drillData.value.ports) || []).filter(p => p.up).length)
const downCount = computed(() => ((drillData.value && drillData.value.ports) || []).filter(p => !p.up).length)

async function onDrill(n) {
  drillNode.value = n
  portKw.value = ''
  portFilter.value = 'all'
  drillData.value = { loading: true }
  // 三数据源(探针 ifaces / 主机采集 nic 差分 / SNMP 接口表)+ 同 IP 兜底在 topoPorts.js,
  // 与链路"按端口绑定"下拉共用同一实现(2026-10-02); 无数据时 note 说明原因(不编造)。
  const d = await fetchNodePorts(n, S.devices)
  drillData.value = d.ports.length ? { ports: d.ports, note: d.note } : { note: d.note }
}

function onTreePick(n) {
  selKind.value = 'node'; selId.value = n.nodeId; multiItems.value = null
  sceneRef.value && sceneRef.value.focusDevice(n.deviceId)
}
function locate(deviceId) {
  const n = nodes.value.find(x => x.deviceId === deviceId)
  if (!n) return
  selKind.value = 'node'; selId.value = n.nodeId; multiItems.value = null
  sceneRef.value && sceneRef.value.focusDevice(deviceId)
}
// ===== 搜索与定位(模糊匹配 + 结果列表; 命中居中放大并高亮) =====
const searchList = ref([])
const showResults = ref(false)
function onKwInput() {
  const k = kw.value.trim().toLowerCase()
  if (!k) { searchList.value = []; showResults.value = false; return }
  searchList.value = nodes.value
    .filter(n => (n.name || '').toLowerCase().includes(k) || (n.ip || '').includes(k) || (n.ips || []).some(i => i.includes(k)))
    .slice(0, 8)
  showResults.value = searchList.value.length > 0
}
function onSearchEnter() {
  if (searchList.value.length) { onPickSearch(searchList.value[0]); return }
  const k = kw.value.trim().toLowerCase()
  const n = nodes.value.find(x => (x.name || '').toLowerCase().includes(k) || (x.ip || '').includes(k))
  if (n) onPickSearch(n); else flashSrc(t('topo.noMatch'))
}
function onPickSearch(n) {
  showResults.value = false
  locate(n.deviceId)
  flashSrc(t('topo.located', { name: n.name }))
}
// ===== 右键菜单动作(来自 TopoScene) =====
// 标记核心节点: 本地持久化(布局结构存 localStorage), 核心节点画布金色高亮环 + 导出时加圈
function onToggleCore(n) {
  n.isCore = !n.isCore
  persist()
  flashSrc(n.isCore ? t('topo.coreMarked') : t('topo.coreUnmarked'))
}
// 更换绑定: 打开右侧面板, 由面板内"绑定资产"下拉完成(名字冗余存, 避免资产删除后显示断链)
function onRebind(n) {
  selKind.value = 'node'; selId.value = n.nodeId
  inspToggle.value = true
  flashSrc(t('topo.rebindHint'))
}
// 设主用/备用链路: 主用=实线, 备用=虚线(本地持久化)
function onToggleBackup(l) {
  l.kind = l.kind === 'backup' ? 'primary' : 'backup'
  persist()
  flashSrc(l.kind === 'backup' ? t('topo.setBackup') : t('topo.setPrimary'))
}
// 配置告警: 该节点对应采集任务/推送规则在节点监控页管理 → 跳转告警推送配置
function onConfigAlert(n) {
  flashSrc(t('topo.alertCfgHint'))
  router.push('/nodemonitor?view=alerts&tab=push')
}
// 导出图片: 导出 2D 画布快照,
// 按当前节点坐标画链路(贝塞尔)+节点(安全色圆+核心圈+名称)到 1200x720 画布下载 PNG。
function onExport() {
  const W = 1200, H = 720
  const cv = document.createElement('canvas')
  cv.width = W; cv.height = H
  const ctx = cv.getContext('2d')
  ctx.fillStyle = '#070d18'; ctx.fillRect(0, 0, W, H)
  // 2026-09-30: 2D 导出按视图摆位坐标(px/py 优先); x/y 是 3D 演示坐标, 不代表 2D 画布
  const px = (n) => (n.px != null ? n.px : (n.x || 0))
  const py = (n) => (n.py != null ? n.py : (n.y || 0))
  for (const l of links.value) {
    const a = nodes.value.find(n => n.deviceId === l.fromDeviceId)
    const b = nodes.value.find(n => n.deviceId === l.toDeviceId)
    if (!a || !b) continue
    const util = l.utilPct != null ? l.utilPct : Math.min(100, Math.round((l.pps || 0) / 60))
    ctx.strokeStyle = LINK_COLOR[l.status] || LINK_COLOR.normal
    ctx.lineWidth = 1.6 + (Math.min(100, util) / 100) * 4.4
    ctx.setLineDash(l.kind === 'backup' || l.status === 'down' ? [9, 7] : [])
    ctx.beginPath()
    const my = (py(a) + py(b)) / 2
    ctx.moveTo(px(a), py(a)); ctx.bezierCurveTo(px(a), my, px(b), my, px(b), py(b)); ctx.stroke()
  }
  ctx.setLineDash([])
  ctx.textAlign = 'center'
  for (const n of nodes.value) {
    ctx.beginPath(); ctx.arc(px(n), py(n), 16, 0, Math.PI * 2)
    ctx.fillStyle = safeColor(n); ctx.fill()
    if (n.isCore) { ctx.lineWidth = 3; ctx.strokeStyle = '#f5c542'; ctx.beginPath(); ctx.arc(px(n), py(n), 21, 0, Math.PI * 2); ctx.stroke() }
    ctx.fillStyle = '#eaf1fb'; ctx.font = '12px sans-serif'
    ctx.fillText(n.name || n.deviceId, px(n), py(n) + 30)
  }
  try {
    const a = document.createElement('a')
    a.href = cv.toDataURL('image/png')
    a.download = 'yugsight_topology_' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + '.png'
    a.click()
    flashSrc(t('topo.exported'))
  } catch (e) { flashSrc(t('topo.exportFail', { err: (e && e.message) || e })) }
}
function batchHide(items) {
  const ids = new Set(items.map(n => n.deviceId))
  nodes.value = nodes.value.filter(n => !ids.has(n.deviceId))
  links.value = links.value.filter(l => !ids.has(l.fromDeviceId) && !ids.has(l.toDeviceId))
  selKind.value = ''; selId.value = ''
  persist()
}

// ===== 链路真实数据(阶段 B, 2026-09-29) ====================================================
// 口径: 链路"集合"由页面掌控(Mock 初值/API 边集 + 用户手增删 + LS 持久化),
// 后端只提供按 (from,to) 匹配的流量/状态字段 —— 覆盖逻辑在共享模块 topoLinkLive.js
// (2026-10-01: 大屏拓扑卡 TopoCard 同源复用, 防两份实现漂移)。
// 轮询兜底(15s) + SSE 即时(topolink 快照, 后端 5s 节流) 走同一固定序函数(覆盖→补全)
watch(() => S.linkUpdatedAt, () => syncLinkLive())

// ===== 底部指标 ====================================================
// 2026-09-29 用户口径"没测过不算通 / 数据必须是真的": Mock 流量系数(applyHour)已删 ——
// 手动链路未测通前没有流量(pps=0), 后端真实链路(_real)自带真实 pps/utilPct,
// 时间轴失去作用对象(与 api 模式同口径禁用), 均值只算有真实数据的链路。
const viewLinks = computed(() => links.value)
const onlineRate = computed(() => {
  if (!nodes.value.length) return 0
  return Math.round(nodes.value.filter(n => n.status !== 'down').length * 100 / nodes.value.length)
})
const avgUtil = computed(() => {
  const real = viewLinks.value.filter(l => l._real && l.utilPct != null)
  if (!real.length) return 0
  return Math.round(real.reduce((a, l) => a + l.utilPct, 0) / real.length)
})
const avgLoss = computed(() => {
  if (!viewLinks.value.length) return 0
  return Math.round(viewLinks.value.reduce((a, l) => a + (l.packetLoss || 0), 0) / viewLinks.value.length * 10) / 10
})
// 心跳指示(2026-10-02 用户要求): 满足其一即红闪 ——
// ① 有实时告警(RT.alerts, 2 分钟窗口) ② 红线(链路 status=down 实测不通) ③ 节点掉线(status=down)
const hbBad = computed(() => {
  if (RT.alerts.length) return true
  for (const n of nodes.value) if (n.status === 'down') return true
  for (const l of viewLinks.value) if (l.status === 'down') return true
  return false
})

// 2026-09-29: sparkPoints/hourPos 随 Mock 曲线一起下线(不展示假数据)
const linkSourceText = computed(() => (shared.linkSource === 'api' ? t('topo.srcApi') + (shared.errLink ? t('topo.srcApiFail') : '') : t('topo.srcMock')))
const srcTip = ref('')
let srcT = null
function flashSrc(s) {
  srcTip.value = s
  if (srcT) clearTimeout(srcT)
  srcT = setTimeout(() => { srcTip.value = '' }, 2400)
}
function fmtBps(v) {
  if (v >= 1e9) return (v / 1e9).toFixed(1) + ' Gb/s'
  if (v >= 1e6) return (v / 1e6).toFixed(1) + ' Mb/s'
  if (v >= 1e3) return Math.round(v / 1e3) + ' Kb/s'
  return v + ' b/s'
}

function goHome() { router.push('/') }
// 返回大屏: 当前模板 id 存在 localStorage(yugsight_bpro_tpl_current), 大屏页会自动还原
function goBigScreen() { router.push('/bigscreen-pro') }
// 一键全屏(2026-09-29 改文档级 + 意图持久化, 见 fullscreen.js): 与大屏同口径,
// 站内互切(返回安全大屏)不退出全屏; 刷新后首次交互自动恢复。
let fsRestoreCleanup = null
async function toggleFullscreen() {
  try {
    if (document.fullscreenElement) await document.exitFullscreen()
    else { await enterFullscreen(); setFsIntent(true) }
  } catch (e) { /* 不支持全屏静默失败 */ }
}
onBeforeUnmount(() => {
  if (fsHandler) document.removeEventListener('fullscreenchange', fsHandler)
  if (fsRestoreCleanup) { fsRestoreCleanup(); fsRestoreCleanup = null }
  if (srcT) clearTimeout(srcT)
  if (cleanT) { clearInterval(cleanT); cleanT = null }
  if (es) { es.close(); es = null }
  // 注意: 不再强制退出全屏 —— 文档级全屏跨页保持(用户没退出就保持,
  // 沉浸式类名由 App.vue 全局监听维护)
})
</script>

<style scoped>
.tp { position: relative; width: 100%; height: 100%; display: flex; flex-direction: column; background: #070d18; color: #cdd6e4; }
/* 顶部 */
.tp-top { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; padding: 8px 14px; border-bottom: 1px solid rgba(56, 132, 255, .22); background: rgba(10, 18, 32, .8); transition: transform .22s ease; }
/* 浏览模式自动隐藏(2026-10-02 用户要求): 顶栏上移滑出文档流(画布顶满),
   鼠标进顶部边缘/栏体滑回(显隐判定在 script onUiMouseMove) */
.tp-top.ui-hidden { position: absolute; left: 0; right: 0; top: 0; z-index: 35; transform: translateY(-101%); border-bottom-color: transparent; }
.tp-crumb { font-size: 12.5px; color: #8295b0; }
.tp-crumb a { color: #38bdf8; text-decoration: none; }
.tp-back { margin-left: 12px; }
.tp-crumb a:hover { text-decoration: underline; }
.tp-search { display: flex; gap: 6px; position: relative; z-index: 30; }
.tp-search input { width: 200px; font-size: 12px; padding: 4px 8px; border-radius: 6px; color: #eaf1fb; background: rgba(255, 255, 255, .06); border: 1px solid rgba(56, 132, 255, .3); }
.tp-search button { font-size: 12px; padding: 4px 12px; border-radius: 6px; cursor: pointer; color: #06121f; background: #3884ff; border: none; }
/* 搜索结果下拉(模糊匹配, 命中高亮安全色圆, 点击定位放大) */
.tp-search-list {
  position: absolute; top: 30px; left: 0; width: 260px; z-index: 40;
  max-height: 260px; overflow-y: auto;
  background: rgba(12, 20, 36, .97); border: 1px solid rgba(56, 132, 255, .4); border-radius: 8px;
  box-shadow: 0 12px 30px rgba(0, 0, 0, .55); backdrop-filter: blur(8px); padding: 4px;
}
.tp-search-list div { display: flex; align-items: center; gap: 7px; padding: 5px 8px; border-radius: 6px; cursor: pointer; font-size: 12px; }
.tp-search-list div:hover { background: rgba(56, 132, 255, .18); }
.tp-search-list i { width: 8px; height: 8px; border-radius: 50%; flex: 0 0 auto; box-shadow: 0 0 6px currentColor; }
.tp-sl-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #dbe6f5; }
.tp-search-list em { font-style: normal; color: #64748b; font-size: 11px; }
.tp-tabs, .tp-mode { display: flex; border: 1px solid rgba(56, 132, 255, .3); border-radius: 6px; overflow: hidden; }
.tp-tabs button, .tp-mode button { font-size: 12px; padding: 4px 12px; cursor: pointer; color: #9fb0c8; background: transparent; border: none; }
.tp-tabs button + button, .tp-mode button + button { border-left: 1px solid rgba(56, 132, 255, .25); }
.tp-tabs button.on, .tp-mode button.on { color: #fff; background: rgba(56, 132, 255, .32); }
.tp-fs { margin-left: auto; font-size: 12px; padding: 4px 14px; border-radius: 6px; cursor: pointer; color: #cdd6e4; background: rgba(56, 132, 255, .16); border: 1px solid rgba(56, 132, 255, .4); }
/* 画布形态标签(2026-09-30: 3D 三维移除后只剩一种画布, "2D 平面"改名"当前画布") */
.tp-canvas-tag { font-size: 12px; color: #9fb0c8; padding: 4px 12px; border: 1px solid rgba(56, 132, 255, .45); border-radius: 6px; background: rgba(56, 132, 255, .12); }
/* 多套拓扑视图保存/加载 */
.tp-views { display: flex; align-items: center; gap: 4px; }
.tp-views select { font-size: 12px; padding: 3px 6px; border-radius: 5px; color: #dbe6f5; background: #162032; border: 1px solid #2a3f5f; max-width: 130px; cursor: pointer; }
.tp-views select:disabled { opacity: .5; cursor: default; }
.tp-views button { font-size: 12px; padding: 3px 10px; border-radius: 5px; cursor: pointer; color: #cdd6e4; background: rgba(56, 132, 255, .16); border: 1px solid rgba(56, 132, 255, .4); }
.tp-views button:hover { background: rgba(56, 132, 255, .32); }
/* 视图删除按钮: 二连击确认态变红提示(2026-09-30) */
.tp-views .tp-v-del { color: #9fb0c8; background: rgba(100, 116, 139, .16); border-color: rgba(100, 116, 139, .45); }
.tp-views .tp-v-del.warn { color: #fff; background: rgba(248, 113, 113, .3); border-color: #f87171; }
/* 视图轮播(2026-09-30 用户要求: 视图多了可以进行轮播设置) */
.tp-v-car { display: inline-flex; align-items: center; gap: 4px; margin-left: 4px; }
.tp-v-car button { font-size: 12px; padding: 3px 10px; border-radius: 5px; cursor: pointer; color: #cdd6e4; background: rgba(56, 132, 255, .16); border: 1px solid rgba(56, 132, 255, .4); }
.tp-v-car button:hover:not(:disabled) { background: rgba(56, 132, 255, .32); }
.tp-v-car button:disabled { opacity: .45; cursor: not-allowed; }
.tp-v-car button.on { color: #06121f; background: #3884ff; font-weight: 700; }
.tp-v-car select { font-size: 12px; padding: 2px 4px; border-radius: 5px; color: #dbe6f5; background: #162032; border: 1px solid #2a3f5f; cursor: pointer; }
/* 加载态 / 空态 */
.tp-state { position: absolute; inset: 0; z-index: 30; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; background: radial-gradient(120% 90% at 50% 0%, #0d1730 0%, #070d18 70%); color: #9fb0c8; font-size: 13px; }
/* 空态·编辑态: 不挡画布(指针事件穿透, 底下 TopoScene2D 可加设备/加框) + 提示移居顶部居中 */
.tp-state.no-block { pointer-events: none; background: transparent; justify-content: flex-start; padding-top: 52px; }
.tp-state.no-block::before { content: ''; position: absolute; top: 36px; left: 50%; transform: translateX(-50%); width: 420px; padding: 8px 16px; border-radius: 10px; background: rgba(7, 13, 24, .82); border: 1px solid rgba(56, 132, 255, .3); }
.tp-state-spin { width: 34px; height: 34px; border-radius: 50%; border: 3px solid rgba(56, 132, 255, .25); border-top-color: #3884ff; animation: tpSpin .8s linear infinite; }
@keyframes tpSpin { to { transform: rotate(360deg); } }
.tp-state-empty { font-size: 16px; color: #cdd6e4; }
.tp-state-sub { font-size: 12px; color: #64748b; }
/* 主体: 画布全幅占满(无内边距/装饰边框/外围留白, 拓扑渲染区 = 整个主体区) */
.tp-body { flex: 1; min-height: 0; position: relative; }
.tp-scene { position: absolute; inset: 0; }
/* 半透明贴边悬浮面板(不占画布空间): 毛玻璃底 + 细边框, 折叠后收成 34px 侧边标签。
   2026-09-29 用户反馈"两栏很模糊看不到东西": 毛玻璃底原来放在 ::before 覆盖层
   (inset:0 + backdrop-filter)上, 面板内容是静态定位, 被玻璃层盖住一起模糊;
   改为直接写在容器上(与 .tp-bottom / .tp-alerts 同口径), 内容画在底之上清晰可读 */
.tp-float {
  position: absolute; top: 12px; bottom: 12px; z-index: 20; width: 220px;
  border-radius: 10px; overflow: hidden; transition: width .22s ease, transform .22s ease, opacity .22s ease;
  background: rgba(10, 18, 32, .78); border: 1px solid rgba(56, 132, 255, .32);
  backdrop-filter: blur(8px); box-shadow: 0 8px 28px rgba(0, 0, 0, .45);
}
.tp-float-left { left: 12px; }
.tp-float-right { right: 12px; width: 272px; }
/* 浏览模式自动隐藏(2026-10-02 用户要求): 侧面板侧滑淡出(边缘热区见 script onUiMouseMove);
   隐藏时保持展开宽度, 避免"先缩再滑"的双段动画 */
.tp-float-left.ui-hidden { width: 220px; transform: translateX(-130%); opacity: 0; pointer-events: none; }
.tp-float-right.ui-hidden { width: 272px; transform: translateX(130%); opacity: 0; pointer-events: none; }
.tp-float:not(.open) { width: 34px; }
.tp-tab {
  position: absolute; left: 0; width: 100%; top: 50%; transform: translateY(-50%); z-index: 2;
  font-size: 11px; padding: 8px 0; color: #9fb0c8; cursor: pointer;
  background: rgba(56, 132, 255, .2); border: none; writing-mode: vertical-rl; letter-spacing: 2px;
}
.tp-tab:hover { color: #fff; background: rgba(56, 132, 255, .38); }
.tp-float.open .tp-tab { top: auto; bottom: 0; transform: none; writing-mode: horizontal-tb; letter-spacing: 0; padding: 5px 0; border-top: 1px solid rgba(56, 132, 255, .3); }
.tp-src { position: absolute; left: 50%; transform: translateX(-50%); top: 10px; z-index: 15; font-size: 12px; color: #fbbf24; background: rgba(10, 18, 32, .92); border: 1px solid rgba(251, 191, 36, .35); border-radius: 6px; padding: 3px 12px; }
/* 右上角实时告警条: SSE nodecollect 实时推送; 提示蓝/一般黄/严重红; 点击定位放大; 右侧面板展开时左移让位 */
.tp-alerts {
  position: absolute; top: 12px; right: calc(12px + var(--ri, 0px)); z-index: 22; width: 280px;
  background: rgba(10, 18, 32, .82); border: 1px solid rgba(56, 132, 255, .35); border-radius: 10px;
  backdrop-filter: blur(8px); box-shadow: 0 8px 24px rgba(0, 0, 0, .45); overflow: hidden;
}
.tp-alerts-h { display: flex; align-items: center; gap: 6px; padding: 6px 12px; font-size: 12px; color: #eaf1fb; border-bottom: 1px solid rgba(255, 255, 255, .08); }
.tp-alerts-h b { color: #fbbf24; }
.tp-conn { margin-left: auto; font-style: normal; font-size: 10px; color: #64748b; border: 1px solid rgba(255, 255, 255, .12); border-radius: 4px; padding: 1px 6px; }
.tp-conn.on { color: #34d399; border-color: rgba(52, 211, 153, .4); }
.tp-alerts-list { display: flex; flex-direction: column; }
.tp-alert { display: flex; align-items: flex-start; gap: 8px; padding: 7px 12px; cursor: pointer; border-bottom: 1px solid rgba(255, 255, 255, .05); animation: tpAlertIn .25s ease; }
.tp-alert:hover { background: rgba(56, 132, 255, .12); }
.tp-alert i { width: 9px; height: 9px; border-radius: 50%; flex: 0 0 auto; margin-top: 3px; box-shadow: 0 0 6px currentColor; }
.tp-alert.lv-info i { color: #38bdf8; } .tp-alert.lv-warning i { color: #fbbf24; } .tp-alert.lv-critical i { color: #f87171; }
.tp-a-b { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.tp-a-b b { font-size: 12px; color: #eaf1fb; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tp-a-b span { font-size: 11px; color: #9fb0c8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tp-alert em { font-style: normal; font-size: 10px; flex: 0 0 auto; margin-top: 2px; }
.tp-alert.lv-info em { color: #38bdf8; } .tp-alert.lv-warning em { color: #fbbf24; } .tp-alert.lv-critical em { color: #f87171; }
@keyframes tpAlertIn { from { opacity: 0; transform: translateX(12px); } to { opacity: 1; transform: none; } }
/* 底部控制栏: 半透明贴边悬浮(给左侧小地图/右侧面板让位, inset 随面板开合变化) */
.tp-bottom {
  position: absolute; bottom: 12px; z-index: 19;
  left: calc(208px + var(--li, 0px)); right: calc(12px + var(--ri, 0px));
  display: flex; align-items: center; gap: 14px; padding: 7px 14px;
  flex-wrap: wrap; row-gap: 6px;   /* 窄窗口按"项"换行, 绝不逐字折行 */
  background: rgba(10, 18, 32, .78); border: 1px solid rgba(56, 132, 255, .3); border-radius: 10px;
  backdrop-filter: blur(8px); box-shadow: 0 6px 20px rgba(0, 0, 0, .4);
}
.tp-stats { display: flex; gap: 12px; font-size: 11.5px; color: #8295b0; flex-wrap: wrap; }
.tp-stats span { white-space: nowrap; }
.tp-stats b { color: #eaf1fb; font-size: 13px; }
/* 精简图例(2026-10-02 用户反馈: 底部文字太啰嗦 —— 只留四色线语义, 说明注释删) */
.tp-legend { display: flex; gap: 12px; align-items: center; font-size: 11px; color: #8295b0; flex-wrap: wrap; margin-left: auto; }
.tp-legend .lg { display: inline-block; width: 14px; height: 3px; border-radius: 2px; vertical-align: middle; margin-right: 4px; }
.tp-legend .lg-green { background: #34d399; }
.tp-legend .lg-red { background: #f87171; }
.tp-legend .lg-untested { background: repeating-linear-gradient(90deg, #64748b 0 3px, transparent 3px 6px); }
.tp-legend .lg-inferred { background: repeating-linear-gradient(90deg, #94a3b8 0 3px, transparent 3px 6px); opacity: .6; }
.tp-src-tag { color: #64748b; white-space: nowrap; }
.tp-src-tag.err { color: #f87171; }
/* 心跳(2026-10-02 用户要求): 正常=绿点缓脉冲; 有告警/红线/节点掉线=红点快闪 */
.tp-hb { display: inline-flex; align-items: center; gap: 6px; font-size: 11.5px; color: #34d399; white-space: nowrap; }
.tp-hb i { width: 8px; height: 8px; border-radius: 50%; background: #34d399; box-shadow: 0 0 6px #34d399; animation: tpHb 2.4s ease-in-out infinite; }
.tp-hb.bad { color: #f87171; }
.tp-hb.bad i { background: #f87171; box-shadow: 0 0 8px #f87171; animation: tpHb .8s ease-in-out infinite; }
@keyframes tpHb { 0%, 100% { opacity: 1; } 50% { opacity: .2; } }
/* 分组盒设置面板(2026-09-29: 层名/层高/业务组 增删改名) */
/* 显示设置(2026-10-02): 与"框 ▾"同形态的下拉勾选 */
.tp-display { position: relative; display: flex; }
.tp-display > button { font-size: 12px; padding: 4px 12px; cursor: pointer; color: #9fb0c8; background: rgba(255, 255, 255, .05); border: 1px solid rgba(56, 132, 255, .35); border-radius: 6px; }
.tp-display > button.on { color: #fff; background: rgba(56, 132, 255, .32); }
.tp-display-panel {
  position: absolute; top: 32px; left: 0; z-index: 45; width: 190px;
  display: flex; flex-direction: column; gap: 8px; padding: 10px 12px;
  background: rgba(12, 20, 36, .98); border: 1px solid rgba(56, 132, 255, .45); border-radius: 8px;
  box-shadow: 0 12px 30px rgba(0, 0, 0, .55); backdrop-filter: blur(8px);
}
.tp-display-panel label { display: flex; align-items: center; gap: 8px; font-size: 12px; color: #dbe6f5; cursor: pointer; }
.tp-groups { position: relative; display: flex; }
.tp-groups > button { font-size: 12px; padding: 4px 12px; cursor: pointer; color: #9fb0c8; background: rgba(255, 255, 255, .05); border: 1px solid rgba(56, 132, 255, .35); border-radius: 6px; }
.tp-groups > button.on { color: #fff; background: rgba(56, 132, 255, .32); }
.tp-groups-panel {
  position: absolute; top: 32px; left: 0; z-index: 45; width: 340px;
  display: flex; flex-direction: column; gap: 10px; padding: 10px 12px;
  background: rgba(12, 20, 36, .98); border: 1px solid rgba(56, 132, 255, .45); border-radius: 8px;
  box-shadow: 0 12px 30px rgba(0, 0, 0, .55); backdrop-filter: blur(8px);
}
.tp-gp-sec { display: flex; flex-direction: column; gap: 5px; }
.tp-gp-h { font-size: 11px; color: #8295b0; letter-spacing: 1px; }
.tp-gp-row { display: flex; gap: 6px; align-items: center; }
.tp-gp-name { flex: 1; min-width: 0; font-size: 12px; padding: 3px 8px; border-radius: 5px; color: #eaf1fb; background: rgba(255, 255, 255, .06); border: 1px solid rgba(56, 132, 255, .3); }
.tp-gp-h { width: 64px; flex: 0 0 auto; font-size: 12px; padding: 3px 6px; border-radius: 5px; color: #eaf1fb; background: rgba(255, 255, 255, .06); border: 1px solid rgba(56, 132, 255, .3); }
.tp-gp-del { font-size: 11px; padding: 3px 8px; border-radius: 5px; cursor: pointer; color: #f87171; background: rgba(248, 113, 113, .1); border: 1px solid rgba(248, 113, 113, .35); }
.tp-gp-del.warn { background: rgba(248, 113, 113, .35); color: #fff; }
.tp-gp-add { align-self: flex-start; font-size: 11.5px; padding: 3px 10px; border-radius: 5px; cursor: pointer; color: #38bdf8; background: rgba(56, 189, 248, .1); border: 1px solid rgba(56, 189, 248, .4); }
.tp-gp-note { font-size: 10.5px; color: #64748b; border-top: 1px dashed rgba(255, 255, 255, .1); padding-top: 6px; }
/* 端口下钻 */
.tp-modal { position: absolute; inset: 0; z-index: 40; display: flex; align-items: center; justify-content: center; background: rgba(4, 8, 16, .55); }
.tp-modal-box { width: 560px; max-width: 92%; background: rgba(12, 20, 36, .98); border: 1px solid rgba(56, 132, 255, .4); border-radius: 10px; padding: 12px 14px; }
.tp-modal-h { display: flex; align-items: center; justify-content: space-between; font-size: 13.5px; color: #eaf1fb; margin-bottom: 8px; }
.tp-modal-h button { background: none; border: none; color: #8295b0; font-size: 16px; cursor: pointer; }

/* ===== 端口详情抽屉(2026-10-02): 弹窗滚不完 → 右侧抽屉 + 表体独立滚动 + 表头吸顶 ===== */
.tp-drawer-mask { position: absolute; inset: 0; z-index: 40; background: rgba(4, 8, 16, .38); }
.tp-drawer {
  position: absolute; top: 0; right: 0; bottom: 0; z-index: 41; width: 520px; max-width: 92%;
  display: flex; flex-direction: column; background: rgba(12, 20, 36, .98);
  border-left: 1px solid rgba(56, 132, 255, .45); box-shadow: -14px 0 40px rgba(0, 0, 0, .5);
}
.tp-dr-h { display: flex; align-items: flex-start; gap: 10px; padding: 12px 14px 10px; border-bottom: 1px solid rgba(255, 255, 255, .08); }
.tp-dr-title { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.tp-dr-title b { font-size: 14px; color: #eaf1fb; }
.tp-dr-sub { font-size: 11.5px; color: #7d8ea8; font-family: var(--mono, monospace); }
.tp-dr-h button { margin-left: auto; background: none; border: none; color: #8295b0; font-size: 18px; line-height: 1; cursor: pointer; }
.tp-dr-h button:hover { color: #fff; }
.tp-dr-tools { display: flex; align-items: center; gap: 8px; padding: 8px 14px; border-bottom: 1px solid rgba(255, 255, 255, .06); }
.tp-dr-kw { flex: 1 1 auto; min-width: 0; background: rgba(255, 255, 255, .06); border: 1px solid rgba(255, 255, 255, .12); border-radius: 6px; padding: 5px 8px; color: #e6eefb; font-size: 12px; }
.tp-dr-kw:focus { outline: none; border-color: rgba(56, 132, 255, .6); }
.tp-dr-seg { display: flex; gap: 4px; flex: 0 0 auto; }
.tp-dr-seg button { padding: 4px 8px; font-size: 11.5px; border-radius: 6px; cursor: pointer; color: #9fb0c8; background: rgba(255, 255, 255, .05); border: 1px solid transparent; }
.tp-dr-seg button:hover { color: #fff; }
.tp-dr-seg button.on { color: #dbeafe; background: rgba(56, 132, 255, .22); border-color: rgba(56, 132, 255, .45); }
.tp-dr-body { flex: 1 1 auto; overflow: auto; padding: 4px 14px 12px; }
.tp-dr-foot { flex: 0 0 auto; padding: 8px 14px; font-size: 11px; color: #64748b; border-top: 1px solid rgba(255, 255, 255, .08); }
.tp-ports { width: 100%; border-collapse: collapse; font-size: 12px; }
.tp-ports th, .tp-ports td { padding: 5px 8px; text-align: left; border-bottom: 1px solid rgba(255, 255, 255, .07); }
.tp-ports th { color: #8295b0; font-weight: 500; }
/* 表头吸顶: 113 行滚动时列名始终可见(否则滚到中部就不知道每列是什么) */
.tp-ports thead th { position: sticky; top: 0; z-index: 2; background: rgba(12, 20, 36, .99); }
.tp-ports td.up { color: #34d399; } .tp-ports td.down { color: #f87171; }
.tp-port-name { font-family: var(--mono, monospace); white-space: nowrap; }
.tp-modal-note { margin-top: 8px; font-size: 11px; color: #64748b; }
</style>

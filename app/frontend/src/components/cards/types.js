// 卡片/组件类型注册表(2026-09-27 安全大屏 Pro 组件库)。
// - CARD_TYPES: 「新建组件」下拉的唯一事实来源(带 group 分组: 基础/统计/图表/高级)
// - CONTENT_COMP: 类型 → 内容组件(由 CanvasCard 的 #front/#back 插槽渲染)
// - CFG: 类型 → 属性面板字段表(右侧属性面板据此渲染, 新增类型无需改页面代码)
// - 工厂函数: 生成默认几何/数据的卡片对象(位置由调用方叠加)
import ScanTaskCard from './ScanTaskCard.vue'
import StatCard from './StatCard.vue'
import TitleCard from './TitleCard.vue'
import NodeCard from './NodeCard.vue'
import MetricCard from './MetricCard.vue'
import RatioCard from './RatioCard.vue'
import StatusCard from './StatusCard.vue'
import VulnLevelCard from './VulnLevelCard.vue'
import TrendChartCard from './TrendChartCard.vue'
import TaskBarsCard from './TaskBarsCard.vue'
import AssetPieCard from './AssetPieCard.vue'
import AlertTopCard from './AlertTopCard.vue'
import NumberRollerCard from './NumberRollerCard.vue'
import Globe3DCard from './Globe3DCard.vue'
import TopoCard from './TopoCard.vue'
import TaskListCard from './TaskListCard.vue'
import { METRIC_OPTIONS, TYPE_OPTIONS } from './dashData.js'
import { COLOR_OPTS } from './chartkit.js'

let _seq = 0
export function uid(p = 'c') {
  return p + '_' + Date.now().toString(36) + (_seq++).toString(36)
}

// 2026-10-04 i18n: 标题/策略/历史等"默认文案"字段一律存词条键, 卡片渲染期 t() 解析
// (用户改过的自由文本不是键 → t() 三级回退原样显示), 切换语言时默认文案跟随刷新。
export function makeScan(over = {}) {
  return {
    id: uid(), type: 'scan', x: 120, y: 120, w: 360, h: 260, z: 1, flipped: false,
    title: 'screen.dftScanTask', status: 'running',
    vulns: { critical: 0, high: 0, medium: 0 }, progress: 0, scope: '—',
    policy: '—', ports: '—', duration: '—', history: '—',
    ...over,
  }
}

export function makeStat(over = {}) {
  return {
    id: uid(), type: 'stat', x: 470, y: 420, w: 320, h: 240, z: 1, flipped: false,
    title: 'screen.dftTasks',
    ...over,
  }
}

export function makeTitle(over = {}) {
  return {
    id: uid(), type: 'title', x: 860, y: 420, w: 380, h: 130, z: 1, flipped: false,
    title: 'screen.dftTitle',
    ...over,
  }
}

export function makeNode(over = {}) {
  return {
    id: uid('node'), type: 'node', x: 1160, y: 60, w: 380, h: 300, z: 1, flipped: false,
    deviceId: '', name: 'screen.dftNode', ip: '', mac: '', layer: 'access', kind: 'server',
    cpu: 0, mem: 0, netUpBps: 0, netDownBps: 0, status: 'normal',
    ...over,
  }
}

// ===== 多行任务列表卡(一张卡展示 3-5 条任务, 释放底部任务组占用的画布空间) =====
export function makeTaskList(over = {}) {
  return {
    id: uid('tl'), type: 'taskList', x: 470, y: 420, w: 380, h: 240, z: 1, flipped: false,
    title: 'screen.dftTaskList', limit: 5, sortBy: 'time', filterStatus: 'all', tasks: [],
    ...over,
  }
}

// ===== 统计卡片三模板 =====
export function makeMetric(over = {}) {
  return {
    id: uid('metric'), type: 'metric', x: 16, y: 16, w: 452, h: 104, z: 1, flipped: false,
    title: 'screen.dftStat', metric: 'vulnRisk', compare: '', color: 'accent', span: 14, note: '',
    ...over,
  }
}
export function makeRatio(over = {}) {
  return {
    id: uid('ratio'), type: 'ratio', x: 470, y: 420, w: 260, h: 240, z: 1, flipped: false,
    title: 'screen.dftRatio', metric: 'assetAlive', total: 'assetTotal', color: 'ok', note: '',
    ...over,
  }
}
export function makeStatusCard(over = {}) {
  return {
    id: uid('status'), type: 'status', x: 470, y: 420, w: 380, h: 200, z: 1, flipped: false,
    title: 'screen.dftStatus', note: '',
    ...over,
  }
}

// ===== 图表组件 =====
export function makeVulnLevel(over = {}) {
  return {
    id: uid('vl'), type: 'vlevel', x: 1216, y: 132, w: 328, h: 197, z: 1, flipped: false,
    title: 'screen.dftVulnLevel', infoIncl: false,
    ...over,
  }
}
export function makeTrend(over = {}) {
  return {
    id: uid('tr'), type: 'trend', x: 860, y: 420, w: 380, h: 220, z: 1, flipped: false,
    title: 'screen.dftTrend', days: 7,
    ...over,
  }
}
export function makeTaskBars(over = {}) {
  return {
    id: uid('tb'), type: 'tbars', x: 1568, y: 132, w: 328, h: 197, z: 1, flipped: false,
    title: 'screen.dftStatusDist',
    ...over,
  }
}
export function makeAssetPie(over = {}) {
  return {
    id: uid('ap'), type: 'apie', x: 1568, y: 341, w: 328, h: 193, z: 1, flipped: false,
    title: 'screen.dftAssetPie',
    ...over,
  }
}
export function makeAlertTop(over = {}) {
  return {
    id: uid('at'), type: 'atop', x: 1216, y: 341, w: 328, h: 193, z: 1, flipped: false,
    title: 'screen.dftAlertTop', limit: 5,
    ...over,
  }
}
export function makeRoller(over = {}) {
  return {
    id: uid('nr'), type: 'roller', x: 16, y: 16, w: 1880, h: 86, z: 1, flipped: false,
    keys: 'vulnTotal,assetAlive,probeOnline,vulnHigh',
    ...over,
  }
}

// ===== 高级组件: 3D 地球态势 =====
export function makeGlobe(over = {}) {
  return {
    id: uid('gl'), type: 'globe', x: 16, y: 132, w: 648, h: 402, z: 1, flipped: false,
    title: 'screen.dftGlobe', maxPoints: 120, hiAt: 50, midAt: 10, custom: '', baseImage: '',
    ...over,
  }
}

// ===== 高级组件: 网络拓扑卡(2026-09-29: 一级菜单/节点监控入口移除后, 大屏卡片是拓扑唯一入口) =====
// view(2026-09-30): 选中的拓扑视图名(多套独立视图, 卡内下拉切换); 空=跟随全局激活视图
export function makeTopo(over = {}) {
  return {
    id: uid('tp'), type: 'topo', x: 720, y: 136, w: 480, h: 400, z: 1, flipped: false,
    title: 'screen.dftTopo', view: '',
    ...over,
  }
}

// 2026-10-04 i18n: label/分组名一律词条键, BigScreenPro 渲染期 t() 解析
export const CARD_TYPES = {
  // 基础卡片
  scan: { group: 'base', label: 'ct.scan', icon: '扫', factory: makeScan },
  title: { group: 'base', label: 'ct.title', icon: '题', factory: makeTitle },
  stat: { group: 'base', label: 'ct.stat', icon: '聚', factory: makeStat },
  node: { group: 'base', label: 'ct.node', icon: '设', factory: makeNode },
  taskList: { group: 'base', label: 'ct.taskList', icon: '列', factory: makeTaskList },
  // 统计卡片
  metric: { group: 'stat', label: 'ct.metric', icon: '数', factory: makeMetric },
  ratio: { group: 'stat', label: 'ct.ratio', icon: '占', factory: makeRatio },
  status: { group: 'stat', label: 'ct.status', icon: '态', factory: makeStatusCard },
  // 图表组件
  trend: { group: 'chart', label: 'ct.trend', icon: '折', factory: makeTrend },
  tbars: { group: 'chart', label: 'ct.tbars', icon: '柱', factory: makeTaskBars },
  apie: { group: 'chart', label: 'ct.apie', icon: '饼', factory: makeAssetPie },
  vlevel: { group: 'chart', label: 'ct.vlevel', icon: '环', factory: makeVulnLevel },
  atop: { group: 'chart', label: 'ct.atop', icon: '警', factory: makeAlertTop },
  roller: { group: 'chart', label: 'ct.roller', icon: '滚', factory: makeRoller },
  // 高级组件
  globe: { group: 'adv', label: 'ct.globe', icon: '球', factory: makeGlobe },
  topo: { group: 'adv', label: 'ct.topo', icon: '拓', factory: makeTopo },
}

export const TYPE_GROUPS = [
  { k: 'base', t: 'tg.base' },
  { k: 'stat', t: 'tg.stat' },
  { k: 'chart', t: 'tg.chart' },
  { k: 'adv', t: 'tg.adv' },
]

export const CONTENT_COMP = {
  scan: ScanTaskCard, stat: StatCard, title: TitleCard,
  node: NodeCard, taskList: TaskListCard,
  metric: MetricCard, ratio: RatioCard, status: StatusCard,
  vlevel: VulnLevelCard, trend: TrendChartCard, tbars: TaskBarsCard,
  apie: AssetPieCard, atop: AlertTopCard, roller: NumberRollerCard,
  globe: Globe3DCard, topo: TopoCard,
}

// ===== 属性面板字段表(右侧面板按 type 渲染, 新增组件类型只改这里) =====
// 2026-10-04 i18n: 字段标签/选项文案一律词条键, BigScreenPro 面板渲染期 t() 解析
const YESNO = [{ v: true, t: 'cfg.yes' }, { v: false, t: 'cfg.no' }]
export const CFG = {
  scan: [
    { k: 'title', t: 'text', l: 'cfg.taskName' },
    { k: 'status', t: 'select', l: 'cfg.status', o: [{ v: 'pending', t: 'cfg.pending' }, { v: 'running', t: 'cfg.running' }, { v: 'done', t: 'cfg.done' }, { v: 'error', t: 'cfg.error' }] },
    { k: 'progress', t: 'number', l: 'cfg.progress' },
    { k: 'scope', t: 'text', l: 'cfg.scope' },
    { k: 'policy', t: 'text', l: 'cfg.policy' },
    { k: 'ports', t: 'text', l: 'cfg.ports' },
    { k: 'duration', t: 'text', l: 'cfg.duration' },
    { k: 'history', t: 'text', l: 'cfg.history' },
  ],
  title: [{ k: 'title', t: 'text', l: 'cfg.titleText' }],
  stat: [{ k: 'title', t: 'text', l: 'cfg.title' }],
  taskList: [
    { k: 'title', t: 'text', l: 'cfg.cardTitle' },
    { k: 'limit', t: 'number', l: 'cfg.limit' },
    { k: 'sortBy', t: 'select', l: 'cfg.sortBy', o: [{ v: 'time', t: 'cfg.sortTime' }, { v: 'progress', t: 'cfg.sortProgress' }] },
    { k: 'filterStatus', t: 'select', l: 'cfg.filterStatus', o: [{ v: 'all', t: 'cfg.all' }, { v: 'pending', t: 'cfg.pending' }, { v: 'running', t: 'cfg.running' }, { v: 'done', t: 'cfg.done' }, { v: 'error', t: 'cfg.error' }] },
  ],
  metric: [
    { k: 'title', t: 'text', l: 'cfg.cardTitle' },
    { k: 'metric', t: 'select', l: 'cfg.metric', o: METRIC_OPTIONS },
    { k: 'compare', t: 'text', l: 'cfg.compare' },
    { k: 'color', t: 'select', l: 'cfg.color', o: COLOR_OPTS },
    { k: 'span', t: 'number', l: 'cfg.span' },
    { k: 'note', t: 'text', l: 'cfg.note' },
  ],
  ratio: [
    { k: 'title', t: 'text', l: 'cfg.cardTitle' },
    { k: 'metric', t: 'select', l: 'cfg.numerator', o: METRIC_OPTIONS },
    { k: 'total', t: 'select', l: 'cfg.denominator', o: METRIC_OPTIONS },
    { k: 'color', t: 'select', l: 'cfg.color', o: COLOR_OPTS },
    { k: 'note', t: 'text', l: 'cfg.catNote' },
  ],
  status: [{ k: 'title', t: 'text', l: 'cfg.cardTitle' }, { k: 'note', t: 'text', l: 'cfg.statusNote' }],
  vlevel: [
    { k: 'title', t: 'text', l: 'cfg.cardTitle' },
    { k: 'infoIncl', t: 'select', l: 'cfg.infoIncl', o: YESNO },
  ],
  trend: [
    { k: 'title', t: 'text', l: 'cfg.cardTitle' },
    { k: 'days', t: 'select', l: 'cfg.days', o: [{ v: 7, t: 'cfg.days7' }, { v: 30, t: 'cfg.days30' }] },
  ],
  tbars: [{ k: 'title', t: 'text', l: 'cfg.cardTitle' }],
  apie: [{ k: 'title', t: 'text', l: 'cfg.cardTitle' }],
  atop: [{ k: 'title', t: 'text', l: 'cfg.cardTitle' }, { k: 'limit', t: 'number', l: 'cfg.limit' }],
  roller: [{ k: 'keys', t: 'text', l: 'cfg.rollerKeys' }],
  globe: [
    { k: 'title', t: 'text', l: 'cfg.cardTitle' },
    { k: 'maxPoints', t: 'number', l: 'cfg.maxPoints' },
    { k: 'hiAt', t: 'number', l: 'cfg.hiAt' },
    { k: 'midAt', t: 'number', l: 'cfg.midAt' },
    { k: 'baseImage', t: 'text', l: 'cfg.baseImage' },
    { k: 'custom', t: 'textarea', l: 'cfg.customPts' },
  ],
  topo: [
    { k: 'title', t: 'text', l: 'cfg.cardTitle' },
    { k: 'view', t: 'text', l: 'cfg.viewName', hint: 'cfg.viewHint' },
  ],
  node: [
    { k: 'name', t: 'text', l: 'cfg.devName' },
    { k: 'deviceId', t: 'text', l: 'cfg.devId' },
    { k: 'ip', t: 'text', l: 'cfg.ip' },
    { k: 'mac', t: 'text', l: 'cfg.mac' },
    { k: 'layer', t: 'select', l: 'cfg.layer', o: [{ v: 'core', t: 'cfg.layerCore' }, { v: 'agg', t: 'cfg.layerAgg' }, { v: 'access', t: 'cfg.layerAccess' }] },
    { k: 'kind', t: 'select', l: 'cfg.kind', o: [{ v: 'router', t: 'cfg.router' }, { v: 'switch', t: 'cfg.switch' }, { v: 'server', t: 'cfg.server' }, { v: 'terminal', t: 'cfg.terminal' }] },
    { k: 'status', t: 'select', l: 'cfg.status', o: [{ v: 'normal', t: 'cfg.normal' }, { v: 'warn', t: 'cfg.warn' }, { v: 'error', t: 'cfg.error' }, { v: 'down', t: 'cfg.down' }] },
    { k: 'cpu', t: 'number', l: 'cfg.cpu' },
    { k: 'mem', t: 'number', l: 'cfg.mem' },
  ],
}

// 批量操作项(2026-09-28): 框选多个元素后右键菜单按此表渲染, 新增对齐动作只改这里。
// k 与 BigScreenPro.applyBatch(k) 的分支一一对应。
// 2026-10-04 i18n: 文案键值化, BigScreenPro 右键菜单渲染期 t() 解析
export const BATCH_ACTIONS = [
  { k: 'left', t: 'ba.left' }, { k: 'right', t: 'ba.right' },
  { k: 'top', t: 'ba.top' }, { k: 'bottom', t: 'ba.bottom' },
  { k: 'hcenter', t: 'ba.hcenter' }, { k: 'vcenter', t: 'ba.vcenter' },
  { k: 'eqw', t: 'ba.eqw' }, { k: 'eqh', t: 'ba.eqh' },
  { k: 'front', t: 'ba.front' }, { k: 'back', t: 'ba.back' },
  { k: 'del', t: 'ba.del', danger: true },
]

// 默认布局(2026-09-27): 顶部通栏 4 指标 + 中部(3D地球/侧边图表, 中间留空) + 底部三组任务卡。
//
// 为什么每组只放 2 张任务卡: 画布是固定 1920×1080 设计坐标系(满幅 letterbox, 不滚动),
// 任务卡低于 170px 高会自动精简为"标题+状态", 3 张/组就必须压到 150px 以下 —— 那会
// 连环形进度和漏洞分级都看不到。够 layouts 的办法只有二选一: 允许画布纵向滚动(改基础
// 框架, 未做), 或做一个"多行任务列表卡"组件(可按需再加)。这里先保证默认每屏信息饱满。
export function defaultCards() {
  return [
    // 顶部通栏: 4 张核心指标卡(同源绑定 overview)
    // key 是模板体系的稳定标识: 内置模板按 key 重排几何/显隐, 不重建实例
    // 2026-09-28 重新校准: 严格对齐 1920×1080, 外边距 16px / 间距 16px, 与 BUILTIN.tpl_overview 完全一致
    makeMetric({ key: 'm1', x: 16, y: 16, w: 460, h: 104, title: 'screen.dcVulnTotal', metric: 'vulnRisk', color: 'danger' }),
    makeMetric({ key: 'm2', x: 492, y: 16, w: 460, h: 104, title: 'screen.dcVulnNew', metric: 'findingToday', color: 'warn' }),
    makeMetric({ key: 'm3', x: 968, y: 16, w: 460, h: 104, title: 'screen.dcTaskDone', metric: 'taskSuccess', color: 'ok' }),
    makeMetric({ key: 'm4', x: 1444, y: 16, w: 460, h: 104, title: 'screen.dcSuccessRate', metric: 'successRate', color: 'accent' }),
    // 中部: 3D 地球 + 网络拓扑卡 + 右侧 2×2 图表(漏洞分级/任务柱状/告警/资产饼图)
    // 拓扑卡(x:720,y:136,w:480,h:400)回填原"拓扑缩略入口卡"预留空位:
    // 2026-09-29 用户要求拓扑只进大屏 —— 一级菜单与节点监控入口移除, 此卡为唯一入口。
    makeGlobe({ key: 'globe', x: 16, y: 136, w: 688, h: 400 }),
    makeTopo({ key: 'topo', x: 720, y: 136, w: 480, h: 400 }),
    makeVulnLevel({ key: 'vl', x: 1216, y: 136, w: 336, h: 192 }),
    makeTaskBars({ key: 'tb', x: 1568, y: 136, w: 336, h: 192 }),
    makeAlertTop({ key: 'at', x: 1216, y: 344, w: 336, h: 192 }),
    makeAssetPie({ key: 'ap', x: 1568, y: 344, w: 336, h: 192 }),
    // 底部: 三组任务卡(进行中 / 高危 / 已完成), 列宽 618
    makeTitle({ key: 'gt1', x: 16, y: 552, w: 618, h: 48, title: 'screen.dcInProgress' }),
    makeScan({ key: 's1', x: 16, y: 612, w: 618, h: 220, title: 'screen.dcFullNet', status: 'running', vulns: { critical: 3, high: 12, medium: 28 }, progress: 64, scope: '192.168.0.0/16', policy: 'screen.dcDeep', ports: '1-65535', duration: '02:14:33', history: 'screen.dcFullNetCnt' }),
    makeScan({ key: 's2', x: 16, y: 844, w: 618, h: 220, title: 'screen.dcDmz', status: 'running', vulns: { critical: 1, high: 5, medium: 9 }, progress: 32, scope: '10.0.5.0/24', policy: 'screen.dcQuick', ports: '1-1024', duration: '00:21:07', history: 'screen.dcDaily' }),
    makeTitle({ key: 'gt2', x: 650, y: 552, w: 618, h: 48, title: 'screen.dcHighTask' }),
    makeScan({ key: 's3', x: 650, y: 612, w: 618, h: 220, title: 'screen.dcDbCheck', status: 'error', vulns: { critical: 7, high: 15, medium: 22 }, progress: 78, scope: '10.0.3.0/24', policy: 'screen.dcDbDeep', ports: '3306,1433,6379', duration: '01:45:12', history: 'screen.dcDbWeek' }),
    makeScan({ key: 's4', x: 650, y: 844, w: 618, h: 220, title: 'screen.dcMwCheck', status: 'error', vulns: { critical: 4, high: 9, medium: 14 }, progress: 51, scope: '10.0.6.0/24', policy: 'screen.dcCve', ports: '8080,8443,443', duration: '00:58:41', history: 'screen.dcMwWeek' }),
    makeTitle({ key: 'gt3', x: 1284, y: 552, w: 618, h: 48, title: 'screen.dcCompleted' }),
    makeScan({ key: 's5', x: 1284, y: 612, w: 618, h: 220, title: 'screen.dcQuarter', status: 'done', vulns: { critical: 0, high: 2, medium: 11 }, progress: 100, scope: '10.0.0.0/8', policy: 'screen.dcCompliance', ports: 'screen.dcAllPorts', duration: '04:32:09', history: 'screen.dcQuarterly' }),
    makeScan({ key: 's6', x: 1284, y: 844, w: 618, h: 220, title: 'screen.dcNewAssets', status: 'done', vulns: { critical: 0, high: 1, medium: 4 }, progress: 100, scope: '10.0.9.0/24', policy: 'screen.dcQuick', ports: '1-10000', duration: '00:12:55', history: 'screen.dcOnDemand' }),
  ]
}

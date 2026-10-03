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
import { t } from '../../i18n'

let _seq = 0
export function uid(p = 'c') {
  return p + '_' + Date.now().toString(36) + (_seq++).toString(36)
}

export function makeScan(over = {}) {
  return {
    id: uid(), type: 'scan', x: 120, y: 120, w: 360, h: 260, z: 1, flipped: false,
    title: t('screen.dftScanTask'), status: 'running',
    vulns: { critical: 0, high: 0, medium: 0 }, progress: 0, scope: '—',
    policy: '—', ports: '—', duration: '—', history: '—',
    ...over,
  }
}

export function makeStat(over = {}) {
  return {
    id: uid(), type: 'stat', x: 470, y: 420, w: 320, h: 240, z: 1, flipped: false,
    title: t('screen.dftTasks'),
    ...over,
  }
}

export function makeTitle(over = {}) {
  return {
    id: uid(), type: 'title', x: 860, y: 420, w: 380, h: 130, z: 1, flipped: false,
    title: t('screen.dftTitle'),
    ...over,
  }
}

export function makeNode(over = {}) {
  return {
    id: uid('node'), type: 'node', x: 1160, y: 60, w: 380, h: 300, z: 1, flipped: false,
    deviceId: '', name: t('screen.dftNode'), ip: '', mac: '', layer: 'access', kind: 'server',
    cpu: 0, mem: 0, netUpBps: 0, netDownBps: 0, status: 'normal',
    ...over,
  }
}

// ===== 多行任务列表卡(一张卡展示 3-5 条任务, 释放底部任务组占用的画布空间) =====
export function makeTaskList(over = {}) {
  return {
    id: uid('tl'), type: 'taskList', x: 470, y: 420, w: 380, h: 240, z: 1, flipped: false,
    title: t('screen.dftTaskList'), limit: 5, sortBy: 'time', filterStatus: 'all', tasks: [],
    ...over,
  }
}

// ===== 统计卡片三模板 =====
export function makeMetric(over = {}) {
  return {
    id: uid('metric'), type: 'metric', x: 16, y: 16, w: 452, h: 104, z: 1, flipped: false,
    title: t('screen.dftStat'), metric: 'vulnRisk', compare: '', color: 'accent', span: 14, note: '',
    ...over,
  }
}
export function makeRatio(over = {}) {
  return {
    id: uid('ratio'), type: 'ratio', x: 470, y: 420, w: 260, h: 240, z: 1, flipped: false,
    title: t('screen.dftRatio'), metric: 'assetAlive', total: 'assetTotal', color: 'ok', note: '',
    ...over,
  }
}
export function makeStatusCard(over = {}) {
  return {
    id: uid('status'), type: 'status', x: 470, y: 420, w: 380, h: 200, z: 1, flipped: false,
    title: t('screen.dftStatus'), note: '',
    ...over,
  }
}

// ===== 图表组件 =====
export function makeVulnLevel(over = {}) {
  return {
    id: uid('vl'), type: 'vlevel', x: 1216, y: 132, w: 328, h: 197, z: 1, flipped: false,
    title: t('screen.dftVulnLevel'), infoIncl: false,
    ...over,
  }
}
export function makeTrend(over = {}) {
  return {
    id: uid('tr'), type: 'trend', x: 860, y: 420, w: 380, h: 220, z: 1, flipped: false,
    title: t('screen.dftTrend'), days: 7,
    ...over,
  }
}
export function makeTaskBars(over = {}) {
  return {
    id: uid('tb'), type: 'tbars', x: 1568, y: 132, w: 328, h: 197, z: 1, flipped: false,
    title: t('screen.dftStatusDist'),
    ...over,
  }
}
export function makeAssetPie(over = {}) {
  return {
    id: uid('ap'), type: 'apie', x: 1568, y: 341, w: 328, h: 193, z: 1, flipped: false,
    title: t('screen.dftAssetPie'),
    ...over,
  }
}
export function makeAlertTop(over = {}) {
  return {
    id: uid('at'), type: 'atop', x: 1216, y: 341, w: 328, h: 193, z: 1, flipped: false,
    title: t('screen.dftAlertTop'), limit: 5,
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
    title: t('screen.dftGlobe'), maxPoints: 120, hiAt: 50, midAt: 10, custom: '', baseImage: '',
    ...over,
  }
}

// ===== 高级组件: 网络拓扑卡(2026-09-29: 一级菜单/节点监控入口移除后, 大屏卡片是拓扑唯一入口) =====
// view(2026-09-30): 选中的拓扑视图名(多套独立视图, 卡内下拉切换); 空=跟随全局激活视图
export function makeTopo(over = {}) {
  return {
    id: uid('tp'), type: 'topo', x: 720, y: 136, w: 480, h: 400, z: 1, flipped: false,
    title: t('screen.dftTopo'), view: '',
    ...over,
  }
}

export const CARD_TYPES = {
  // 基础卡片
  scan: { group: 'base', label: '漏扫任务卡', icon: '扫', factory: makeScan },
  title: { group: 'base', label: '标题说明卡', icon: '题', factory: makeTitle },
  stat: { group: 'base', label: '画布聚合卡', icon: '聚', factory: makeStat },
  node: { group: 'base', label: '节点指标卡', icon: '设', factory: makeNode },
  taskList: { group: 'base', label: '任务列表卡', icon: '列', factory: makeTaskList },
  // 统计卡片
  metric: { group: 'stat', label: '数字指标卡', icon: '数', factory: makeMetric },
  ratio: { group: 'stat', label: '占比统计卡', icon: '占', factory: makeRatio },
  status: { group: 'stat', label: '状态汇总卡', icon: '态', factory: makeStatusCard },
  // 图表组件
  trend: { group: 'chart', label: '折线图(趋势)', icon: '折', factory: makeTrend },
  tbars: { group: 'chart', label: '柱状图(任务)', icon: '柱', factory: makeTaskBars },
  apie: { group: 'chart', label: '饼图(资产)', icon: '饼', factory: makeAssetPie },
  vlevel: { group: 'chart', label: '环形图(漏洞分级)', icon: '环', factory: makeVulnLevel },
  atop: { group: 'chart', label: '告警列表', icon: '警', factory: makeAlertTop },
  roller: { group: 'chart', label: '数字滚动画板', icon: '滚', factory: makeRoller },
  // 高级组件
  globe: { group: 'adv', label: '3D 地球态势', icon: '球', factory: makeGlobe },
  topo: { group: 'adv', label: '网络拓扑卡', icon: '拓', factory: makeTopo },
}

export const TYPE_GROUPS = [
  { k: 'base', t: '基础卡片' },
  { k: 'stat', t: '统计卡片' },
  { k: 'chart', t: '图表组件' },
  { k: 'adv', t: '高级组件' },
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
const YESNO = [{ v: true, t: '是' }, { v: false, t: '否' }]
export const CFG = {
  scan: [
    { k: 'title', t: 'text', l: '任务名称' },
    { k: 'status', t: 'select', l: '状态', o: [{ v: 'pending', t: '待执行' }, { v: 'running', t: '执行中' }, { v: 'done', t: '已完成' }, { v: 'error', t: '异常' }] },
    { k: 'progress', t: 'number', l: '进度%' },
    { k: 'scope', t: 'text', l: '扫描范围' },
    { k: 'policy', t: 'text', l: '扫描策略' },
    { k: 'ports', t: 'text', l: '端口范围' },
    { k: 'duration', t: 'text', l: '执行时长' },
    { k: 'history', t: 'text', l: '历史记录' },
  ],
  title: [{ k: 'title', t: 'text', l: '标题文字' }],
  stat: [{ k: 'title', t: 'text', l: '标题' }],
  taskList: [
    { k: 'title', t: 'text', l: '卡片标题' },
    { k: 'limit', t: 'number', l: '显示条数' },
    { k: 'sortBy', t: 'select', l: '排序规则', o: [{ v: 'time', t: '按时间' }, { v: 'progress', t: '按进度' }] },
    { k: 'filterStatus', t: 'select', l: '状态筛选', o: [{ v: 'all', t: '全部' }, { v: 'pending', t: '待执行' }, { v: 'running', t: '执行中' }, { v: 'done', t: '已完成' }, { v: 'error', t: '异常' }] },
  ],
  metric: [
    { k: 'title', t: 'text', l: '卡片标题' },
    { k: 'metric', t: 'select', l: '数据源字段', o: METRIC_OPTIONS },
    { k: 'compare', t: 'text', l: '环比标签(空=自动)' },
    { k: 'color', t: 'select', l: '颜色主题', o: COLOR_OPTS },
    { k: 'span', t: 'number', l: '趋势点数' },
    { k: 'note', t: 'text', l: '底部说明' },
  ],
  ratio: [
    { k: 'title', t: 'text', l: '卡片标题' },
    { k: 'metric', t: 'select', l: '分子字段', o: METRIC_OPTIONS },
    { k: 'total', t: 'select', l: '分母字段', o: METRIC_OPTIONS },
    { k: 'color', t: 'select', l: '颜色主题', o: COLOR_OPTS },
    { k: 'note', t: 'text', l: '分类说明' },
  ],
  status: [{ k: 'title', t: 'text', l: '卡片标题' }, { k: 'note', t: 'text', l: '状态说明' }],
  vlevel: [
    { k: 'title', t: 'text', l: '卡片标题' },
    { k: 'infoIncl', t: 'select', l: '含信息级', o: YESNO },
  ],
  trend: [
    { k: 'title', t: 'text', l: '卡片标题' },
    { k: 'days', t: 'select', l: '显示范围', o: [{ v: 7, t: '近 7 日' }, { v: 30, t: '近 30 日' }] },
  ],
  tbars: [{ k: 'title', t: 'text', l: '卡片标题' }],
  apie: [{ k: 'title', t: 'text', l: '卡片标题' }],
  atop: [{ k: 'title', t: 'text', l: '卡片标题' }, { k: 'limit', t: 'number', l: '显示条数' }],
  roller: [{ k: 'keys', t: 'text', l: '轮播指标(逗号分隔)' }],
  globe: [
    { k: 'title', t: 'text', l: '卡片标题' },
    { k: 'maxPoints', t: 'number', l: '事件点上限(降采样)' },
    { k: 'hiAt', t: 'number', l: '高危阈值' },
    { k: 'midAt', t: 'number', l: '中危阈值' },
    { k: 'baseImage', t: 'text', l: '地球贴图(可选)' },
    { k: 'custom', t: 'textarea', l: '自定义点位 JSON' },
  ],
  topo: [
    { k: 'title', t: 'text', l: '卡片标题' },
    { k: 'view', t: 'text', l: '视图名(留空=跟随激活视图)', hint: '多套独立拓扑视图, 也可在卡内下拉直接切换' },
  ],
  node: [
    { k: 'name', t: 'text', l: '设备名称' },
    { k: 'deviceId', t: 'text', l: '拓扑设备ID' },
    { k: 'ip', t: 'text', l: 'IP' },
    { k: 'mac', t: 'text', l: 'MAC' },
    { k: 'layer', t: 'select', l: '层级', o: [{ v: 'core', t: '核心层' }, { v: 'agg', t: '汇聚层' }, { v: 'access', t: '接入层' }] },
    { k: 'kind', t: 'select', l: '类型', o: [{ v: 'router', t: '路由器' }, { v: 'switch', t: '交换机' }, { v: 'server', t: '服务器' }, { v: 'terminal', t: '终端' }] },
    { k: 'status', t: 'select', l: '状态', o: [{ v: 'normal', t: '正常' }, { v: 'warn', t: '告警' }, { v: 'error', t: '异常' }, { v: 'down', t: '断开' }] },
    { k: 'cpu', t: 'number', l: 'CPU%' },
    { k: 'mem', t: 'number', l: '内存%' },
  ],
}

// 批量操作项(2026-09-28): 框选多个元素后右键菜单按此表渲染, 新增对齐动作只改这里。
// k 与 BigScreenPro.applyBatch(k) 的分支一一对应。
export const BATCH_ACTIONS = [
  { k: 'left', t: '左对齐' }, { k: 'right', t: '右对齐' },
  { k: 'top', t: '上对齐' }, { k: 'bottom', t: '下对齐' },
  { k: 'hcenter', t: '水平居中' }, { k: 'vcenter', t: '垂直居中' },
  { k: 'eqw', t: '等宽' }, { k: 'eqh', t: '等高' },
  { k: 'front', t: '批量置顶' }, { k: 'back', t: '批量置底' },
  { k: 'del', t: '批量删除', danger: true },
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
    makeMetric({ key: 'm1', x: 16, y: 16, w: 460, h: 104, title: t('screen.dcVulnTotal'), metric: 'vulnRisk', color: 'danger' }),
    makeMetric({ key: 'm2', x: 492, y: 16, w: 460, h: 104, title: t('screen.dcVulnNew'), metric: 'findingToday', color: 'warn' }),
    makeMetric({ key: 'm3', x: 968, y: 16, w: 460, h: 104, title: t('screen.dcTaskDone'), metric: 'taskSuccess', color: 'ok' }),
    makeMetric({ key: 'm4', x: 1444, y: 16, w: 460, h: 104, title: t('screen.dcSuccessRate'), metric: 'successRate', color: 'accent' }),
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
    makeTitle({ key: 'gt1', x: 16, y: 552, w: 618, h: 48, title: t('screen.dcInProgress') }),
    makeScan({ key: 's1', x: 16, y: 612, w: 618, h: 220, title: t('screen.dcFullNet'), status: 'running', vulns: { critical: 3, high: 12, medium: 28 }, progress: 64, scope: '192.168.0.0/16', policy: t('screen.dcDeep'), ports: '1-65535', duration: '02:14:33', history: t('screen.dcFullNetCnt') }),
    makeScan({ key: 's2', x: 16, y: 844, w: 618, h: 220, title: t('screen.dcDmz'), status: 'running', vulns: { critical: 1, high: 5, medium: 9 }, progress: 32, scope: '10.0.5.0/24', policy: t('screen.dcQuick'), ports: '1-1024', duration: '00:21:07', history: t('screen.dcDaily') }),
    makeTitle({ key: 'gt2', x: 650, y: 552, w: 618, h: 48, title: t('screen.dcHighTask') }),
    makeScan({ key: 's3', x: 650, y: 612, w: 618, h: 220, title: t('screen.dcDbCheck'), status: 'error', vulns: { critical: 7, high: 15, medium: 22 }, progress: 78, scope: '10.0.3.0/24', policy: t('screen.dcDbDeep'), ports: '3306,1433,6379', duration: '01:45:12', history: t('screen.dcDbWeek') }),
    makeScan({ key: 's4', x: 650, y: 844, w: 618, h: 220, title: t('screen.dcMwCheck'), status: 'error', vulns: { critical: 4, high: 9, medium: 14 }, progress: 51, scope: '10.0.6.0/24', policy: t('screen.dcCve'), ports: '8080,8443,443', duration: '00:58:41', history: t('screen.dcMwWeek') }),
    makeTitle({ key: 'gt3', x: 1284, y: 552, w: 618, h: 48, title: t('screen.dcCompleted') }),
    makeScan({ key: 's5', x: 1284, y: 612, w: 618, h: 220, title: t('screen.dcQuarter'), status: 'done', vulns: { critical: 0, high: 2, medium: 11 }, progress: 100, scope: '10.0.0.0/8', policy: t('screen.dcCompliance'), ports: t('screen.dcAllPorts'), duration: '04:32:09', history: t('screen.dcQuarterly') }),
    makeScan({ key: 's6', x: 1284, y: 844, w: 618, h: 220, title: t('screen.dcNewAssets'), status: 'done', vulns: { critical: 0, high: 1, medium: 4 }, progress: 100, scope: '10.0.9.0/24', policy: t('screen.dcQuick'), ports: '1-10000', duration: '00:12:55', history: t('screen.dcOnDemand') }),
  ]
}

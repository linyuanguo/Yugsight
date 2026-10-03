<!--
  NodeMonitor.vue 节点监控(2026-09-28 改版: 左侧多级手风琴菜单 + 右侧视图切换;
  2026-09-30 按用户反馈调整总览/协议配置边界)。

  菜单(SideMenu, 多级可缩进手风琴, 展开状态 localStorage 持久化):
    节点监控
    ├─ 设备总览         → 探针节点管理(2026-10-01: 原「纳管设备」只读清单与协议配置的
    │                     监控目标重复, 按用户要求移除; 监控设备看「协议配置 → 监控目标」)
    ├─ 告警日志管理     → AlertLog(页内四 Tab: 告警记录/推送日志/推送配置/异常事件;
    │                     异常事件 2026-09-30 从协议配置并入, AI 分析按钮随之迁移)
    └─ 节点配置(可展开)
       ├─ 协议配置      → 网络设备监控(SNMP) + 主机侧扩展采集 + 网络侧扩展采集
       │                 + 采集全局配置(异常事件卡已移入告警日志)
       └─ 连通性测试    → 本地模拟连通性探测
  (2026-09-29: 「3D 拓扑视图」内嵌入口按用户要求移除, 拓扑唯一入口=安全大屏的网络拓扑卡,
   卡内「⤢ 全屏」进 /topology/3d 独立页)

  路由兼容: 仍是单路由 /nodemonitor, 视图由 query 参数 ?view= 承载
  (overview|alerts|protocol|connectivity, 默认 overview) ——
  与全站 query-tab 口径一致, 刷新/书签不丢视图。
  旧书签不失效: /probes → 本页默认(设备总览); /monitor → ?tab=net → 协议配置。
-->
<template>
  <div class="page nm">
    <PageHeader :title="t('nm.title')" :desc="t('nm.desc')">
    </PageHeader>

    <div class="nm-body">
      <aside class="nm-side">
        <SideMenu :items="menu" :model-value="view" storage-key="yugsight_nodemonitor_menu" @select="setView" />
      </aside>

      <section class="nm-main">
        <!-- 设备总览: 只有探针节点管理(2026-10-01 用户要求: 「纳管设备」只读清单与
             「协议配置 → 监控目标」重复, 已整体移除 —— 监控设备看协议配置即可) -->
        <Probes v-if="view === 'overview'" />

        <!-- 告警日志管理: 页内四 Tab(注册离开守卫, 推送配置未保存时拦截菜单切换) -->
        <AlertLog v-else-if="view === 'alerts'" :set-guard="setAlertsGuard" />

        <!-- 协议配置: 网络设备监控(SNMP) + 主机侧/网络侧扩展采集 + 采集全局配置 -->
        <template v-else-if="view === 'protocol'">
          <Monitor />
          <div class="section-gap"></div>
          <CollectSection side="host" :title="t('nm.hostCollect')" />
          <div class="section-gap"></div>
          <CollectSection side="net" :title="t('nm.netCollect')" />
          <div class="section-gap"></div>
          <NodeCommonCards />
        </template>

        <!-- 连通性测试 -->
        <ConnectivityTest v-else />
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { t } from '../i18n'
import PageHeader from '../components/PageHeader.vue'
import SideMenu from '../components/node/SideMenu.vue'
import Probes from './Probes.vue'
import Monitor from './Monitor.vue'
import CollectSection from '../components/CollectSection.vue'
import NodeCommonCards from '../components/NodeCommonCards.vue'
import AlertLog from './NodeMonitor/AlertLog.vue'
import ConnectivityTest from './NodeMonitor/ConnectivityTest.vue'
// 2026-10-01: MonitoredDevices(纳管设备只读清单)按用户要求移除 —— 与"协议配置 → 监控
// 目标"重复; 组件文件随之删除(仅本页引用过)。

const route = useRoute()
const router = useRouter()

const VIEWS = ['overview', 'alerts', 'protocol', 'connectivity']

// 左侧菜单树: 一级「节点监控」根, 二级 4 项, 节点配置下三级 2 项
const menu = [{
  key: 'root',
  label: 'nm.mRoot',
  children: [
    { key: 'overview', label: 'nm.mOverview' },
    { key: 'alerts', label: 'nm.mAlerts' },
    { key: 'settings', label: 'nm.mSettings', children: [
      { key: 'protocol', label: 'nm.mProtocol' },
      { key: 'connectivity', label: 'nm.mConn' }
    ] }
  ]
}]

// view 解析: 新 ?view= 优先; 旧 ?tab=net(/monitor 重定向遗留)映射到协议配置
const view = computed(() => {
  const v = route.query.view
  if (VIEWS.includes(v)) return v
  if (route.query.tab === 'net') return 'protocol'
  return 'overview'
})

// 告警日志管理的离开守卫: AlertLog 挂载时注册/卸载时注销(返回 false = 拦截)。
// 必须在路由变化【之前】询问 —— vue-router 的 replace 是异步的, 若用路由 watcher
// 事后拦截再顶回路由, 中间态(view=overview)的重渲染已先一步卸载 AlertLog,
// 表单重挂载清零, 未保存修改全丢(2026-09-28 真机排查确认)。
const alertsLeaveGuard = ref(null)
function setAlertsGuard(fn) { alertsLeaveGuard.value = fn }

function setView(key) {
  if (key === view.value) return
  if (view.value === 'alerts' && alertsLeaveGuard.value && !alertsLeaveGuard.value()) return
  router.replace({ path: '/nodemonitor', query: key === 'overview' ? {} : { view: key } })
}
</script>

<style scoped>
.nm-body { display: flex; gap: 16px; align-items: flex-start; }
.nm-side {
  width: 216px; flex-shrink: 0;
  position: sticky; top: 70px;
}
.nm-main { flex: 1; min-width: 0; }
.section-gap { height: 16px; }
@media (max-width: 900px) {
  .nm-body { flex-direction: column; }
  .nm-side { width: 100%; position: static; }
}
</style>

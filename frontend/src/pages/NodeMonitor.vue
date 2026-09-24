<!--
  NodeMonitor.vue 节点监控(阶段 1, 菜单: 诊断与观测)。

  两个 Tab(与 Engrules 同一 URL query 承载 tab 的口径, 刷新/书签不丢 tab):
    探针节点管理: yugsight-agent 分布式探针(注册/在线/版本/任务下发/日志/下载)
                  + 主机侧扩展采集(WinRM/SSH/主机SNMP, 无代理场景)。
    网络设备监控: SNMP(monitor 包, 既有) + 扩展采集协议(ICMP/NetFlow/NETCONF/RESTCONF)。

  底部公共区: 采集全局配置 + 异常事件(NodeCommonCards, 两 Tab 共用)。

  探针功能整体从原"探针管理"(系统配置组)迁移到此, SNMP 监控从原"网络监控"
  菜单合并到此 —— 原 /probes、/monitor 路由保留为重定向, 旧书签不失效。
-->
<template>
  <div class="page">
    <PageHeader
      title="节点监控"
      desc="主机侧(探针 + WinRM/SSH/SNMP)与网络侧(SNMP + ICMP/NetFlow/NETCONF/RESTCONF)统一采集底座">
    </PageHeader>

    <div class="tabs">
      <div class="tab" :class="{ active: tab === 'probe' }" @click="setTab('probe')">探针节点管理</div>
      <div class="tab" :class="{ active: tab === 'net' }" @click="setTab('net')">网络设备监控</div>
    </div>

    <!-- 探针节点管理 -->
    <template v-if="tab === 'probe'">
      <Probes />
      <div class="section-gap"></div>
      <CollectSection side="host" title="主机侧扩展采集(无代理)" />
    </template>

    <!-- 网络设备监控 -->
    <template v-else>
      <Monitor />
      <div class="section-gap"></div>
      <CollectSection side="net" title="网络侧扩展采集(SNMP 之外)" />
    </template>

    <!-- 公共区: 采集配置 + 异常事件(两 Tab 共用, 常驻) -->
    <div class="section-gap"></div>
    <NodeCommonCards />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import Probes from './Probes.vue'
import Monitor from './Monitor.vue'
import CollectSection from '../components/CollectSection.vue'
import NodeCommonCards from '../components/NodeCommonCards.vue'

const route = useRoute()
const router = useRouter()

// 只有 'net' 是网络设备 Tab, 其它取值(含空)落到探针 Tab —— 旧书签 /nodemonitor 不失效
const tab = computed(() => (route.query.tab === 'net' ? 'net' : 'probe'))

// replace 而非 push: 切 Tab 不堆历史(后退应是离开本页)
function setTab(t) {
  if (t === tab.value) return
  router.replace({ path: '/nodemonitor', query: t === 'net' ? { tab: 'net' } : {} })
}
</script>

<style scoped>
.section-gap { height: 16px; }
</style>

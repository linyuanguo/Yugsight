<template>
  <div>
    <PageHeader title="版权信息" desc="版本与版权归属"></PageHeader>

    <div class="card cp-card">
      <div class="cp-logo">YS</div>
      <div class="cp-name">Yugsight</div>
      <div class="cp-ver mono">v{{ version || '…' }}</div>
      <div class="cp-cn">安服管理平台</div>

      <div class="cp-div"></div>

      <p class="cp-line">Copyright © 2026 yugo. 版权所有。</p>
      <p class="cp-line muted">MIT License</p>

      <p class="cp-line small" style="margin-top:16px">
        Yugsight(御视) 安全运维一体化平台(安服管理平台)—— 集资产探测、端口/服务指纹、
        弱口令检测、漏洞扫描与综合研判于一体的安全运维工具。
      </p>
      <p class="cp-line small">
        本软件由作者 yugo 借助 CodeBuddy 辅助开发, 作者已投入实质性劳动与智力成果,
        依法对本软件及其源代码、文档享有著作权, 并对其真实性负责。
      </p>
      <p class="cp-line small muted" style="margin-top:16px">
        许可范围: 本软件依据 MIT License 提供。在不违反该许可证的前提下, 任何人可自由使用、
        复制、修改、合并、发布、再授权及商业用途, 但须保留原作者版权声明与本许可文件副本。
      </p>
      <p class="cp-line small muted">
        免责声明: 本软件及其生成的报告/结论仅用于合法的安全测试与运维目的, 使用方须确保已获得
        被测系统所有者的明确授权; 结论仅供安全加固参考, 不构成对任何系统安全状态的保证。
        作者对因使用或无法使用本软件导致的任何直接、间接、附带或后果性损失
        (含数据丢失、利润损失、业务中断)不承担责任。
      </p>
      <p class="cp-line small muted">
        未经著作权人书面许可, 不得复制、传播本软件或本报告的全部或部分内容,
        或用于本软件授权范围之外的用途。
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import { api } from '../api/http'

// 版本号: 版本从顶栏移到本页后, 这里是它唯一的常驻展示位(2026-09-25)。
// 走 /api/info 的 version 字段 —— 与构建注入(main.appVersion)同源, 不会漂移。
const version = ref('')
onMounted(async () => {
  try {
    const d = await api('/api/info')
    version.value = (d && d.version) || ''
  } catch (e) { /* 未登录/服务异常: 显示占位 */ }
})
</script>

<style scoped>
.cp-card {
  max-width: 560px;
  margin: 24px auto;
  text-align: center;
  padding: 44px 32px;
}
.cp-logo {
  width: 72px; height: 72px;
  margin: 0 auto 14px;
  border-radius: 18px;
  background: linear-gradient(135deg, #4f46e5, #7c3aed);
  color: #fff;
  font-size: 30px; font-weight: 700;
  display: flex; align-items: center; justify-content: center;
  letter-spacing: 1px;
}
.cp-name { font-size: 26px; font-weight: 700; color: var(--text-1, #1f2937); }
.cp-ver { font-size: 15px; color: var(--accent, #4f46e5); margin-top: 4px; }
.cp-cn { font-size: 14px; color: var(--text-3, #6b7280); margin-top: 2px; }
.cp-div { height: 1px; background: var(--border, #e5e7eb); margin: 22px 0; }
.cp-line { margin: 6px 0; font-size: 14px; color: var(--text-2, #374151); }
.cp-line.muted { color: var(--text-3, #6b7280); }
.cp-line.small { font-size: 12px; }
</style>

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 构建产物 dist/ 经 go:embed 嵌入 Go 二进制, 静态资源固定在 /app/assets/ 下由主程序服务;
// base 用 /app/ 绝对路径: 主页 / 与 /app/ 访问时资源都能正确解析(单文件 exe 离线可加载)。
// 注意: 若改回 './' 相对路径, 从主页 / 访问会因 ./assets 解析成 /assets 404 导致空白页。
// dev 模式下前端挂在 http://localhost:5173/app/ 下开发。
export default defineConfig({
  base: '/app/',
  plugins: [vue()],
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    chunkSizeWarningLimit: 1024,
    // 2026-09-29: 所有页面 chunk 的 CSS 合并为单文件(由 index.html head 阻塞引用)。
    // 此前每个懒加载页面各带一份 css, 随 chunk 运行时注入 —— 首次访问时 DOM 先渲染、
    // css 后到, 页面短暂无样式"排版乱"(用户反馈: 刚打开乱, 刷新几次就正常 —— 刷新后
    // css 已进缓存不再闪烁)。合并后首帧之前全部样式必然到位, 从根上消除 FOUC;
    // JS 仍按页分包(懒加载不变), 仅 css 不再拆分(全部 ~144KB, 内网加载无感)。
    cssCodeSplit: false
  },
  server: {
    // 开发模式(dev)代理到本机 Yugsight 主程序, 便于不打包联调
    proxy: {
      '/api': 'http://127.0.0.1:8420'
    }
  }
})

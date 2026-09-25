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
    chunkSizeWarningLimit: 1024
  },
  server: {
    // 开发模式(dev)代理到本机 Yugsight 主程序, 便于不打包联调
    proxy: {
      '/api': 'http://127.0.0.1:8420'
    }
  }
})

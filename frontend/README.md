# Yugsight Vue3 前端

Vue3 + vue-router(hash 路由) + Vite, 无 UI 框架 / 无图表库依赖, 统一深色主题(与经典页面 web/index.html 同色系)。

## 构建

```
cd frontend
npm install
npm run build   # 产物输出到 frontend/dist/
```

`dist/` 经 `go:embed` 嵌入 Go 二进制(`vue_ui.go`), **必须先构建 dist 再 `go build`**, 否则编译报错。
`dist/` 需随仓库提交(go:embed 源), 仅 `node_modules/` 忽略。

## 挂载

- 主程序以 `/app/` 子路径提供本前端(单文件 exe 离线可加载)
- `-ui=vue` 启动时, 主页 `/` 也切换到本前端(默认 `old`, 不影响原有流程)
- 开发模式: `npm run dev`, API 代理到本机 `http://127.0.0.1:8420`

## 页面

登录 / 首页仪表盘 / 资产管理 / 扫描任务管理 / 实时扫描控制台 / 引擎状态 /
探针管理(占位) / 漏洞列表+详情 / 白名单管理 / 授权管理 / 独立安全大屏(图表占位)。

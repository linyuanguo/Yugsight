package main

// static_api.go 静态下载通道: /static/<文件名>。
//
// 用途: 给登录页的"安装证书"(YugsightCertTool.exe)与"手动导入"(rootCA.crt)提供
// 同源下载。这两样不是业务接口, 只是"文件取货口", 所以:
//
//   - 服务 exe 同目录 static/ 下的**直接子文件**(不递归子目录 —— 该目录只放
//     单文件的下载物, 子目录没有意义, 也顺带缩小攻击面);
//   - 不鉴权(与登录页的探针安装落地页同口径: 未登录的操作者也要能下载);
//   - 目录穿越防护: 请求路径里出现 "/" 或 ".." 直接 404, 且解析后必须仍落在
//     static/ 内, 否则 404(双保险)。
//
// 文件来源(详见 build.ps1 与 tls.go 的 generateCertPair):
//   - YugsightCertTool.exe: 构建时交叉编译进 dist/static/;
//   - rootCA.crt: 运行期自动签发时写入 dist/data/cert/(无 static 副本 —— 2026-09-29
//     起 rootCA 只保留 data/cert/ 一份, /static/rootCA.crt 直接读 data/cert/rootCA.crt)。
//
// 两者缺失时各自 404(登录页按钮/链接会相应降级), 不报错。

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleStatic 处理 /static/ 下的文件下载。
func handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	name = strings.Trim(name, "/")
	// 只允许直接子文件: 含路径分隔符或空名一律 404(不递归, 不空目录)
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") ||
		strings.Contains(name, "\\") || strings.HasPrefix(name, ".") {
		http.NotFound(w, r)
		return
	}
	// rootCA.crt 是唯一一个"不在 static/ 而在 data/cert/"的下载物: 公钥(根证书)本就
	// 公开下载, 直接读 data/cert/rootCA.crt, 避免 data/cert/ 与 static/ 各存一份副本
	// (2026-09-29 用户要求 rootCA 只留一份, cert/ 归入 data/)。仅这一个文件名精确
	// 放行 —— server.pem / server-key.pem 等凭据绝不在此通道暴露(它们不在 static/
	// 且不走本特例)。
	base := filepath.Join(exeDir(), "static")
	if name == "rootCA.crt" {
		base = filepath.Join(exeDir(), "data", "cert")
	}
	full := filepath.Join(base, name)
	// 目录穿越双保险: 解析后必须仍落在 base(data/cert/ 或 static/)内
	rel, err := filepath.Rel(base, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	// octet-stream + no-store: 二进制下载不缓存(证书/工具每次都要拿最新的)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	// ServeContent 支持 Range 断点续传(大文件下载中断可续)
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

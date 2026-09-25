// blob_verify_test.go 下载缓存完整性校验(blobOK)的回归测试。
//
// 【缺陷背景 - 由真实冒烟暴露】
// 缓存复用原判定只有 "文件存在且 Size()>0"。实测启动自动补装时, bin/.engmgr-tmp 里
// 躺着一个 215KB 的 trivy zip 残片(真实包 50MB+, 显然是上次下载中断留下的), 被当成
// 完整包复用 → 解包失败 → 而下次重试仍然复用同一个残片, 形成**永久自锁**: 用户点多少次
// "重新安装"都不可能成功, 日志里也看不到任何下载动作, 极难定位。
//
// 这组用例把"残片必须被识别为不可用"钉死, 同时保证正常包不被误判(误判会导致每次
// 都重新下载几百 MB, 比原缺陷更糟)。
package engmgr

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// blobZip 生成一个最小合法 zip(内含一个条目)。
//
// 名字带 blob 前缀是为了避开 engmgr_test.go 里已有的 makeZip/makeTarGz —— 同包内
// 重名会直接编译失败(不区分文件), 而那两个的签名是多文件 map, 不适合这里复用。
func blobZip(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// blobTarGz 生成一个最小合法 tar.gz(命名理由同 blobZip)
func blobTarGz(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestBlobOKRejectsTruncatedZip 截断的 zip 必须被判为不可用。
//
// 用例构造的是"写了一半"的真实形态: 保留 zip 头部若干字节, EOCD(中央目录结束记录)
// 丢失 —— 这正是下载中断 99% 的样子。zip.OpenReader 找不到 EOCD 会直接报错。
func TestBlobOKRejectsTruncatedZip(t *testing.T) {
	dir := t.TempDir()
	full := blobZip(t, "trivy.exe", string(bytes.Repeat([]byte("x"), 4096)))

	// 前置: 完整包必须通过(否则"拒绝残片"这条断言毫无意义 —— 恒真)
	good := filepath.Join(dir, "trivy_1.0.0_windows-64bit.zip")
	if err := os.WriteFile(good, full, 0o644); err != nil {
		t.Fatal(err)
	}
	if !blobOK(good, filepath.Base(good)) {
		t.Fatal("前置条件不成立: 完整 zip 应通过校验")
	}

	// 截断: 只留前 1/3 字节(模拟下载中断)
	cut := filepath.Join(dir, "trunc_1.0.0_windows-64bit.zip")
	if err := os.WriteFile(cut, full[:len(full)/3], 0o644); err != nil {
		t.Fatal(err)
	}
	if blobOK(cut, filepath.Base(cut)) {
		t.Fatal("截断的 zip 不应通过校验(否则会形成永久自锁: 每次复用同一个坏文件)")
	}
}

// TestBlobOKRejectsTruncatedTarGz 截断的 tar.gz 同样必须被判为不可用。
func TestBlobOKRejectsTruncatedTarGz(t *testing.T) {
	dir := t.TempDir()
	full := blobTarGz(t, "trivy", string(bytes.Repeat([]byte("y"), 200<<10))) // 200KB, 足够跨过 64KB 探测点

	good := filepath.Join(dir, "trivy_1.0.0_Linux-64bit.tar.gz")
	if err := os.WriteFile(good, full, 0o644); err != nil {
		t.Fatal(err)
	}
	if !blobOK(good, filepath.Base(good)) {
		t.Fatal("前置条件不成立: 完整 tar.gz 应通过校验")
	}

	// 截断到 1/4: gzip 流在中途结束, 读的时候会报 unexpected EOF
	cut := filepath.Join(dir, "trunc_Linux-64bit.tar.gz")
	if err := os.WriteFile(cut, full[:len(full)/4], 0o644); err != nil {
		t.Fatal(err)
	}
	if blobOK(cut, filepath.Base(cut)) {
		t.Fatal("截断的 tar.gz 不应通过校验")
	}
}

// TestBlobOKRejectsEmptyAndMissing 空文件与不存在的文件一律不可用
func TestBlobOKRejectsEmptyAndMissing(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.zip")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if blobOK(empty, "empty.zip") {
		t.Fatal("空文件不应通过校验")
	}
	if blobOK(filepath.Join(dir, "nope.zip"), "nope.zip") {
		t.Fatal("不存在的文件不应通过校验")
	}
}

// TestBlobOKRejectsGarbageWithZipExt 后缀是 .zip 但内容不是 zip(常见的半截 HTML 错误页)
func TestBlobOKRejectsGarbageWithZipExt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "junk_1.0.0_windows-64bit.zip")
	// 模拟"下载到的是上游的错误页/断流内容", 而非压缩包
	if err := os.WriteFile(p, []byte("<html><body>502 Bad Gateway</body></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if blobOK(p, filepath.Base(p)) {
		t.Fatal("非 zip 内容不应通过校验")
	}
}

// TestBlobOKSFXSizeFloor SFX 安装器(.exe)无结构可验, 但明显过小的必须拒绝。
//
// 为什么单独测这条: nmap 的包只提供 setup.exe, 它没有可解析的归档结构, 只能靠体积
// 下限兜底。若这条失效, 一个 2KB 的错误响应会被当成安装器并进入解包流程。
func TestBlobOKSFXSizeFloor(t *testing.T) {
	dir := t.TempDir()
	tiny := filepath.Join(dir, "nmap-7.99-setup.exe")
	if err := os.WriteFile(tiny, bytes.Repeat([]byte{0}, 2048), 0o644); err != nil {
		t.Fatal(err)
	}
	if blobOK(tiny, filepath.Base(tiny)) {
		t.Fatal("2KB 的 .exe 不可能是完整安装器, 应被拒绝")
	}
	// 超过下限的(这里造 2MB)应放行 —— 结构无法验证, 交由解包阶段报错
	big := filepath.Join(dir, "nmap-7.99-setup-big.exe")
	if err := os.WriteFile(big, bytes.Repeat([]byte{0}, 2<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if !blobOK(big, filepath.Base(big)) {
		t.Fatal("超过体积下限的 .exe 应放行(SFX 无结构可验, 交给解包阶段)")
	}
}

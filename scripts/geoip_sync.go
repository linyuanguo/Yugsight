// geoip_sync.go 把 ip2region 开源数据(免注册, GitHub raw)转成 Yugsight 的紧凑 TSV。
//
// 用法(仓库根目录执行):
//
//	go run scripts/geoip_sync.go                        # 下载 v4+v6 源并生成 build/geoip/*.tsv
//	go run scripts/geoip_sync.go --in4 a.txt --in6 b.txt # 用本地源文件(离线)
//	go run scripts/geoip_sync.go --out build/geoip      # 指定输出目录
//	go run scripts/geoip_sync.go --v6-prefix 20         # v6 聚合前缀(默认 20, 越小越细越大)
//
// 产物:
//
//	geoip4.tsv  start \t end \t country \t region \t city   (十进制 uint32, 相邻同址段已合并)
//	geoip6.tsv  startHex \t endHex \t country               (按 /N 前缀聚合, 仅国家粒度)
//
// 设计说明:
//   - 断点续传: raw.githubusercontent 在弱网下频繁断连, 每次重试带 Range 续传;
//   - v4 全量约 52 万行(转后 ~20MB); v6 全量 77MB 源 → 按 /20 前缀聚合后仅千余行,
//     内网部署里 v6 公共 IP 极少, 城市级 v6 数据体积/收益不成比例(精度声明: 展示近似);
//   - 源文件格式: start|end|country|region|city|isp|cc (ip2region 官方 source txt)。
//
// 【踩坑记录】第一版手写行读取器(buf 预分配 len=0, Read 不增长 len)会把整个文件
// 读成 0 行 —— 这类"看起来在跑、实际数据全丢"的静默失败比崩溃难查得多, 故直接用
// bufio.Scanner(带 1MB 缓冲), 不造轮子。
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	flOut      = flag.String("out", "build/geoip", "输出目录")
	flIn4      = flag.String("in4", "", "本地 v4 源文件(提供则跳过下载)")
	flIn6      = flag.String("in6", "", "本地 v6 源文件(提供则跳过下载)")
	flV6Prefix = flag.Int("v6-prefix", 20, "v6 聚合前缀位数")
	flSkipV6   = flag.Bool("skip-v6", false, "不处理 v6")
	flSkipV4   = flag.Bool("skip-v4", false, "不处理 v4")
)

const (
	baseV4   = "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ipv4_source.txt"
	baseV6   = "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ipv6_source.txt"
	maxRound = 200 // 续传轮数上限
)

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	if err := os.MkdirAll(*flOut, 0o755); err != nil {
		log.Fatalf("创建输出目录失败: %v", err)
	}

	if !*flSkipV4 {
		src := *flIn4
		if src == "" {
			src = download(baseV4, *flOut+"/ipv4_source.txt")
		}
		if src == "" {
			log.Printf("v4 源不可用, 跳过 geoip4.tsv(运行时降级为空表)")
		} else {
			n := convertV4(src, *flOut+"/geoip4.tsv")
			log.Printf("geoip4.tsv 生成: %d 段", n)
		}
	}
	if !*flSkipV6 {
		src := *flIn6
		if src == "" {
			src = download(baseV6, *flOut+"/ipv6_source.txt")
		}
		if src == "" {
			log.Printf("v6 源不可用, 跳过 geoip6.tsv(运行时降级为空表)")
		} else {
			n := convertV6(src, *flOut+"/geoip6.tsv", *flV6Prefix)
			log.Printf("geoip6.tsv 生成: %d 段(/%d 前缀)", n, *flV6Prefix)
		}
	}
	log.Println("完成。geoip 包运行时按 exe 同目录 geoip/ 查找这些文件")
}

// download 断点续传下载。返回本地路径; 彻底失败返回 ""(不 fatal: 数据可选, 缺失降级)。
func download(url, dst string) string {
	client := &http.Client{Timeout: 180 * time.Second}
	for round := 0; round < maxRound; round++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return ""
		}
		req.Header.Set("User-Agent", "Yugsight-GeoIP-Sync/1.0")
		if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", fi.Size()))
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("下载第 %d 轮失败: %v (重试)", round+1, err)
			time.Sleep(2 * time.Second)
			continue
		}
		mode := os.O_CREATE | os.O_WRONLY
		if resp.StatusCode == http.StatusPartialContent {
			mode |= os.O_APPEND
		}
		f, err := os.OpenFile(dst, mode, 0o644)
		if err != nil {
			resp.Body.Close()
			return ""
		}
		n, err := io.Copy(f, resp.Body)
		f.Close()
		resp.Body.Close()
		if err != nil {
			log.Printf("第 %d 轮传输 %d 字节后中断: %v (续传)", round+1, n, err)
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.StatusCode == http.StatusOK {
			log.Printf("下载完成: %s", dst)
			return dst
		}
		if resp.StatusCode == http.StatusPartialContent {
			log.Printf("第 %d 轮完成 %d 字节(206, 继续)", round+1, n)
			continue
		}
		log.Printf("下载状态异常: %d", resp.StatusCode)
		return ""
	}
	log.Printf("下载超过 %d 轮仍未完成, 放弃(当前进度保留在 %s)", maxRound, dst)
	return ""
}

// newScanner 1MB 缓冲的扫描器(源文件单行 < 128B, 足够)。
func newScanner(f *os.File) *bufio.Scanner {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	return sc
}

type v4Row struct {
	start, end uint32
	country, region, city string
}

// convertV4 解析 ip2region v4 源 → 紧凑 TSV。
// 源行: start|end|country|region|city|isp|cc
//  1. country 为空/"0"/"Reserved" 的行丢弃(保留段由 geoip 包私有段判定兜底);
//  2. 相邻且同 (country,region,city) 的段合并 —— 压缩体积, 二分次数不变。
func convertV4(src, dst string) int {
	f, err := os.Open(src)
	if err != nil {
		log.Printf("打开 %s 失败: %v", src, err)
		return 0
	}
	defer f.Close()

	var rows []v4Row
	sc := newScanner(f)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" {
			continue
		}
		p := strings.Split(t, "|")
		if len(p) < 7 {
			continue
		}
		country := clean(p[2])
		if country == "" || country == "Reserved" {
			continue
		}
		s, err1 := ipToU32(p[0])
		e, err2 := ipToU32(p[1])
		if err1 != nil || err2 != nil || s > e {
			continue
		}
		row := v4Row{start: s, end: e, country: country, region: clean(p[3]), city: clean(p[4])}
		// 合并相邻同址段
		if n := len(rows); n > 0 {
			prev := &rows[n-1]
			if prev.end+1 == row.start && prev.country == row.country &&
				prev.region == row.region && prev.city == row.city {
				prev.end = row.end
				continue
			}
		}
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		log.Printf("读取 %s 中断: %v (已处理 %d 段)", src, err, len(rows))
	}

	out, err := os.Create(dst)
	if err != nil {
		log.Printf("创建 %s 失败: %v", dst, err)
		return 0
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	fmt.Fprintln(w, "# geoip4.tsv  start \t end \t country \t region \t city (十进制 uint32)")
	for _, r := range rows {
		fmt.Fprintf(w, "%d\t%d\t%s\t%s\t%s\n", r.start, r.end, r.country, r.region, r.city)
	}
	w.Flush()
	return len(rows)
}

func ipToU32(s string) (uint32, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return 0, fmt.Errorf("非法 IP: %s", s)
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, fmt.Errorf("非 IPv4: %s", s)
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), nil
}

func clean(s string) string {
	s = strings.TrimSpace(s)
	if s == "0" {
		return ""
	}
	return s
}

// convertV6 解析 v6 源 → 按 /N 前缀聚合的国家表。
// 源文件按地址升序, 单遍扫描; 每个前缀取组内首个有效国家。
func convertV6(src, dst string, prefix int) int {
	if prefix < 8 || prefix > 56 {
		log.Printf("v6-prefix %d 超出 [8,56], 放弃", prefix)
		return 0
	}
	f, err := os.Open(src)
	if err != nil {
		log.Printf("打开 %s 失败: %v", src, err)
		return 0
	}
	defer f.Close()

	type v6Row struct {
		start, end [16]byte
		country    string
	}
	var rows []v6Row
	var lastPrefix [16]byte
	haveLast := false
	sc := newScanner(f)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" {
			continue
		}
		p := strings.Split(t, "|")
		if len(p) < 7 {
			continue
		}
		start := net.ParseIP(strings.TrimSpace(p[0]))
		if start == nil {
			continue
		}
		s16 := start.To16()
		if s16 == nil {
			continue
		}
		country := clean(p[2])
		if country == "" || country == "Reserved" {
			continue
		}
		// 前缀 = 前 prefix 位: 完整字节保留, 部分字节只留高位, 其余清零
		var pre [16]byte
		copy(pre[:], s16)
		full, rem := prefix/8, prefix%8
		for i := full; i < 16; i++ {
			if i == full && rem > 0 {
				shift := uint(8 - rem)
				pre[i] = pre[i] >> shift << shift
			} else {
				pre[i] = 0
			}
		}
		// 前缀段尾 = 前缀之后的位全 1(前缀位本身保留, 不能写全 1 ——
		// 那样会把前缀字节的高位也变成 1, 段直接错到相邻前缀)
		var endPre [16]byte
		copy(endPre[:], pre[:])
		for i := full; i < 16; i++ {
			endPre[i] = 0xff
		}
		if rem > 0 {
			// byte[full] 是前缀的部分字节: 高 rem 位是前缀(保留),
			// 低 (8-rem) 位置 1
			endPre[full] = pre[full] | (0xff >> uint(rem))
		}
		// 前缀变化(或首行) → 开新组
		if !haveLast || pre != lastPrefix {
			rows = append(rows, v6Row{start: pre, end: endPre, country: country})
			haveLast = true
		} else if rows[len(rows)-1].country == "" {
			rows[len(rows)-1].country = country
		}
		lastPrefix = pre
	}
	if err := sc.Err(); err != nil {
		log.Printf("读取 %s 中断: %v (已处理 %d 段)", src, err, len(rows))
	}

	out, err := os.Create(dst)
	if err != nil {
		log.Printf("创建 %s 失败: %v", dst, err)
		return 0
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	fmt.Fprintf(w, "# geoip6.tsv  start \t end \t country (/前缀 %d 聚合)\n", prefix)
	n := 0
	for _, r := range rows {
		if r.country == "" {
			continue
		}
		fmt.Fprintf(w, "%x\t%x\t%s\n", r.start, r.end, r.country)
		n++
	}
	w.Flush()
	return n
}

// 保证 strconv 被引用(部分平台构建下避免误删 import)
var _ = strconv.Itoa

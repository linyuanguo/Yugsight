// geoip.go IP 地理映射(城市级, 纯标准库, 零依赖)。
//
// ===== 数据来源与形态 =====
//
// 数据文件放 build/geoip/(仓库资源目录, 不打包进二进制, 由 scripts/build.ps1
// 镜像到 exe 同目录 geoip/):
//
//   geoip4.tsv   IPv4 段表: start \t end \t 国家 \t 区域 \t 城市
//                (start/end 为十进制 uint32; 空串 = 未知)
//   geoip6.tsv   IPv6 段表: startHex16 \t endHex16 \t 国家
//                (前缀级粗粒度, 仅国家 —— 内网部署里 v6 公共 IP 极少,
//                 城市级 v6 数据源体积过大不随包分发, 需要时自行生成)
//   city_geo.tsv 城市坐标表: 城市 \t 纬度 \t 经度(静态表, 展示近似点)
//
// 段表由 scripts/geoip_sync.go 从 ip2region 开源数据(免注册)转换而来;
// 缺失时 Load 记 slog 告警并降级为空表 —— 查询一律返回 unknown, 不报错
// (项目规则 3/4: 外部资源可选, 缺失降级不崩溃)。
//
// ===== 查询口径 =====
//
//   - IPv4: uint32 二分(段表按 start 升序);
//   - IPv6: 16 字节字典序二分;
//   - 私有/内网段(10/8, 172.16/12, 192.168/16, 127/8, 169.254/16,
//     fc00::/7, fe80::/10, ::1)返回 Private=true, 不报错 —— 内网部署里
//     绝大多数 IP 都是私有段, "查不到"是常态不是异常;
//   - 精度声明: 城市级仅作展示近似点, 不是精确地理坐标。
package geoip

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Location 一次 IP 查询的结果。
type Location struct {
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
	Region  string `json:"region,omitempty"`
	City    string `json:"city,omitempty"`
	// Lat/Lon 城市坐标(展示近似点); Known=false 时无意义。
	Lat   float64 `json:"lat,omitempty"`
	Lon   float64 `json:"lon,omitempty"`
	// Known = 段表命中(地理信息有效); Private = 私有/内网段。
	Known   bool   `json:"known"`
	Private bool   `json:"private,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// v4Range 一条 IPv4 段记录。
type v4Range struct {
	start, end uint32
	ci, ri, si int // 字符串池下标: country / region / city (-1 = 空)
}

// v6Range 一条 IPv6 段记录(仅国家粒度)。
type v6Range struct {
	start, end [16]byte
	ci          int
}

// DB 加载后的内存映射。整体只读(加载后不再修改), 可并发调用 Lookup。
type DB struct {
	mu      sync.RWMutex
	loaded4 bool
	loaded6 bool
	v4      []v4Range
	v6      []v6Range
	pool    []string // 去重字符串池
	// cities: 城市名(含去"市"后缀变体) → 坐标
	cities map[string]geo
	// provinces: 省份 → 省会名(兜底: 城市查不到用省会坐标)
	provinces map[string]string
}

type geo struct {
	lat, lon float64
}

// New 空 DB(未加载)。Lookup 对空 DB 返回 unknown(不 panic)。
func New() *DB {
	return &DB{
		cities:    map[string]geo{},
		provinces: map[string]string{},
	}
}

// Loaded 数据加载状态(v4/v6 分别报告, 供 API 展示)。
func (db *DB) Loaded() (v4, v6 bool, v4Count, v6Count int) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.loaded4, db.loaded6, len(db.v4), len(db.v6)
}

// intern 字符串入池, 返回下标。调用方必须持锁。
func (db *DB) intern(s string) int {
	if s == "" {
		return -1
	}
	for i, p := range db.pool {
		if p == s {
			return i
		}
	}
	db.pool = append(db.pool, s)
	return len(db.pool) - 1
}

// Load 从目录加载全部数据文件。缺文件跳过并记入 warnings(降级不报错);
// 目录本身不存在时返回 (db, ["目录不存在:..."]) 由调用方决定是否告警。
func Load(dir string) (*DB, []string) {
	db := New()
	var warnings []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return db, []string{"geoip 数据目录不存在: " + dir + " (IP 地理查询将全部返回 unknown)"}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case strings.HasSuffix(name, "geoip4.tsv"):
			if w := loadV4(db, dir+"/"+name); w != "" {
				warnings = append(warnings, w)
			}
		case strings.HasSuffix(name, "geoip6.tsv"):
			if w := loadV6(db, dir+"/"+name); w != "" {
				warnings = append(warnings, w)
			}
		case strings.HasSuffix(name, "city_geo.tsv"):
			if w := loadCities(db, dir+"/"+name); w != "" {
				warnings = append(warnings, w)
			}
		}
	}
	// 内置省会坐标表兜底: city_geo.tsv 缺失时, "城市查不到用省会兜底"
	// 的链路依然可用(省会坐标是硬编码的最小可用集)。
	for p, c := range provinceCapitals {
		if _, ok := db.cities[c]; !ok {
			db.cities[c] = geo{lat: cLat[p], lon: cLon[p]}
			db.cities[strings.TrimSuffix(c, "市")] = geo{lat: cLat[p], lon: cLon[p]}
		}
		db.provinces[p] = c
	}
	// 段表缺失是真正的降级(查询全 unknown), 需要告警; city 表缺失有内置兜底, 不算降级。
	if !db.loaded4 {
		warnings = append(warnings, "geoip4.tsv 缺失: IPv4 地理查询将全部返回 unknown")
	}
	if !db.loaded6 {
		warnings = append(warnings, "geoip6.tsv 缺失: IPv6 地理查询将全部返回 unknown")
	}
	return db, warnings
}

// loadV4 读 geoip4.tsv。行: start \t end \t country \t region \t city
func loadV4(db *DB, path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "geoip4.tsv 不可读: " + err.Error()
	}
	defer f.Close()
	var (
		rows  []v4Range
		bad   int
		sc    = bufio.NewScanner(f)
		scBig = make([]byte, 0, 1024*1024)
	)
	sc.Buffer(scBig, 1024*1024)
	for sc.Scan() {
		line := chompLine(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) != 5 {
			bad++
			continue
		}
		s, e1 := strconv.ParseUint(p[0], 10, 32)
		e, e2 := strconv.ParseUint(p[1], 10, 32)
		if e1 != nil || e2 != nil || s > e {
			bad++
			continue
		}
		// ci/ri/si 初始 -1(空字段); 结构体零值是 0 会误指向 pool[0], 必须显式置 -1
		r := v4Range{start: uint32(s), end: uint32(e), ci: -1, ri: -1, si: -1}
		if p[2] != "" && p[2] != "0" && p[2] != "Reserved" {
			r.ci = db.intern(p[2])
		}
		if p[3] != "" && p[3] != "0" {
			r.ri = db.intern(p[3])
		}
		if p[4] != "" && p[4] != "0" {
			r.si = db.intern(p[4])
		}
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		return "geoip4.tsv 读取失败: " + err.Error()
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].start < rows[j].start })
	db.mu.Lock()
	db.v4, db.loaded4 = rows, true
	db.mu.Unlock()
	if len(rows) == 0 {
		return "geoip4.tsv 无有效段(IPv4 地理查询将全部返回 unknown)"
	}
	if bad > 0 {
		return fmt.Sprintf("geoip4.tsv 已加载 %d 段, %d 行格式异常被跳过", len(rows), bad)
	}
	return ""
}

// loadV6 读 geoip6.tsv。行: startHex \t endHex \t country
func loadV6(db *DB, path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "geoip6.tsv 不可读: " + err.Error()
	}
	defer f.Close()
	var (
		rows []v6Range
		bad  int
		sc   = bufio.NewScanner(f)
	)
	for sc.Scan() {
		line := chompLine(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) != 3 {
			bad++
			continue
		}
		s, err1 := hexToIP16(p[0])
		e, err2 := hexToIP16(p[1])
		if err1 != nil || err2 != nil || bytesCmp(s, e) > 0 {
			bad++
			continue
		}
		r := v6Range{start: s, end: e, ci: -1} // ci 初始 -1(同 v4, 防误指 pool[0])
		if p[2] != "" && p[2] != "0" && p[2] != "Reserved" {
			r.ci = db.intern(p[2])
		}
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		return "geoip6.tsv 读取失败: " + err.Error()
	}
	sort.Slice(rows, func(i, j int) bool { return bytesCmp(rows[i].start, rows[j].start) < 0 })
	db.mu.Lock()
	db.v6, db.loaded6 = rows, true
	db.mu.Unlock()
	if len(rows) == 0 {
		return "geoip6.tsv 无有效段(IPv6 地理查询将全部返回 unknown)"
	}
	if bad > 0 {
		return fmt.Sprintf("geoip6.tsv 已加载 %d 段, %d 行格式异常被跳过", len(rows), bad)
	}
	return ""
}

// loadCities 读 city_geo.tsv。行: 城市 \t 纬度 \t 经度
func loadCities(db *DB, path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "city_geo.tsv 不可读: " + err.Error()
	}
	defer f.Close()
	var (
		n, bad int
		sc      = bufio.NewScanner(f)
	)
	for sc.Scan() {
		line := chompLine(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) != 3 {
			bad++
			continue
		}
		lat, e1 := strconv.ParseFloat(p[1], 64)
		lon, e2 := strconv.ParseFloat(p[2], 64)
		if e1 != nil || e2 != nil || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
			bad++
			continue
		}
		city := p[0]
		g := geo{lat: lat, lon: lon}
		db.cities[city] = g
		// 去"市"后缀变体: 段表里"福州市"与坐标表"福州"都要能对上
		if c2 := strings.TrimSuffix(city, "市"); c2 != city {
			if _, ok := db.cities[c2]; !ok {
				db.cities[c2] = g
			}
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return "city_geo.tsv 读取失败: " + err.Error()
	}
	if n == 0 {
		return "city_geo.tsv 无有效城市(省会兜底仍可用)"
	}
	return ""
}

// chompLine 只去掉行尾换行符(\n 已被 Scanner 剥离, 这里处理 \r)。
// 【关键】绝不能用 strings.TrimSpace —— 空字段行以 \t 结尾(如 "...city 为空"),
// TrimSpace 会把那个尾部 \t 吃掉, 5 字段变 4 字段, 整行被误判丢弃(实测丢了 10 万行)。
func chompLine(s string) string {
	if i := len(s) - 1; i >= 0 && s[i] == '\r' {
		return s[:i]
	}
	return s
}

// hexToIP16 32 位十六进制串 → 16 字节。
func hexToIP16(s string) ([16]byte, error) {
	var b [16]byte
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 32 {
		return b, fmt.Errorf("IPv6 hex 长度 %d 非 32", len(s))
	}
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return b, err
		}
		b[i] = byte(v)
	}
	return b, nil
}

func bytesCmp(a, b [16]byte) int {
	for i := 0; i < 16; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// isPrivate 私有/内网段判定。
func isPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		a, b := ip4[0], ip4[1]
		switch {
		case a == 10:
			return true
		case a == 172 && b >= 16 && b <= 31:
			return true
		case a == 192 && b == 168:
			return true
		case a == 127:
			return true
		case a == 169 && b == 254:
			return true
		case a == 0:
			return true
		case a >= 224: // 组播/保留
			return true
		}
		return false
	}
	// IPv6: fc00::/7 (ULA) + fe80::/10 (链路本地) + ::1
	if ip[0]&0xfe == 0xfc || (ip[0] == 0xfe && ip[1]&0xc0 == 0x80) {
		return true
	}
	if ip16 := ip.To16(); ip16 != nil && isLoopbackV6(ip16) {
		return true
	}
	return false
}

// isLoopbackV6 是否 ::1。
func isLoopbackV6(ip16 []byte) bool {
	for i := 0; i < 15; i++ {
		if ip16[i] != 0 {
			return false
		}
	}
	return ip16[15] == 1
}

// Lookup 查询一个 IP 的地理位置。永不返回 error(查不到=unknown 降级)。
func (db *DB) Lookup(s string) *Location {
	loc := &Location{IP: s}
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		loc.Reason = "非法 IP"
		return loc
	}
	if isPrivate(ip) {
		loc.Private = true
		loc.Reason = "私有/内网段"
		return loc
	}
	db.mu.RLock()
	defer db.mu.RUnlock()

	var country, region, city string
	if ip4 := ip.To4(); ip4 != nil && db.loaded4 {
		n := len(db.v4)
		lo, hi := 0, n
		v := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		for lo < hi {
			mid := (lo + hi) >> 1
			if db.v4[mid].start > v {
				hi = mid
			} else {
				lo = mid + 1
			}
		}
		if lo > 0 {
			r := db.v4[lo-1]
			if v >= r.start && v <= r.end {
				country = db.str(r.ci)
				region = db.str(r.ri)
				city = db.str(r.si)
				loc.Country, loc.Region, loc.City = country, region, city
				loc.Known = true
			}
		}
	} else if ip6 := ip.To16(); db.loaded6 {
		var v [16]byte
		copy(v[:], ip6)
		n := len(db.v6)
		lo, hi := 0, n
		for lo < hi {
			mid := (lo + hi) >> 1
			if bytesCmp(db.v6[mid].start, v) > 0 {
				hi = mid
			} else {
				lo = mid + 1
			}
		}
		if lo > 0 {
			r := db.v6[lo-1]
			if bytesCmp(v, r.start) >= 0 && bytesCmp(v, r.end) <= 0 {
				country = db.str(r.ci)
				loc.Country, loc.Known = country, true
			}
		}
	}

	if !loc.Known {
		loc.Reason = "未收录"
		return loc
	}
	// 坐标解析: 城市 → 省会 → 国家重心(仅中国有省会兜底, 外国城市用国家重心)
	if g, ok := db.cities[city]; ok {
		loc.Lat, loc.Lon = g.lat, g.lon
		return loc
	}
	if cap, ok := db.provinces[region]; ok {
		if g, ok2 := db.cities[cap]; ok2 {
			loc.Lat, loc.Lon = g.lat, g.lon
			return loc
		}
	}
	if g, ok := countryCenters[country]; ok {
		loc.Lat, loc.Lon = g.lat, g.lon
	}
	return loc
}

// str 取池内字符串(调用方持读锁)。
func (db *DB) str(i int) string {
	if i < 0 || i >= len(db.pool) {
		return ""
	}
	return db.pool[i]
}

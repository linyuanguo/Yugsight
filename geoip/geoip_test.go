// geoip 包契约测试: 段表二分 / 私有段 / 缺失降级 / 省会兜底。
// 全部离线(临时目录小 TSV), 不依赖真实数据文件。
package geoip

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTmp 建临时 geoip 目录。
func writeTmp(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// 段表: 1.0.0.0-1.0.0.255 澳洲, 1.0.1.0-1.0.3.255 中国福建省福州市
const sample4 = "# comment\n" +
	"0\t4294967295\tReserved\t0\t0\n" + // 全量 Reserved 行(country 置空 → 不会命中)
	"16777216\t16777471\tAustralia\tQueensland\t0\n" +
	"16777472\t16778239\t中国\t福建省\t福州市\n" +
	"16778240\t16779007\t中国\t广东省\t广州市\n"

const sample6 = "20010200000000000000000000000000\t20010200ffffffffffffffffffffffff\tJapan\n"

const sampleCity = "福州市\t26.07\t119.30\n" +
	"福州\t26.07\t119.30\n"

func TestLookupV4(t *testing.T) {
	dir := writeTmp(t, map[string]string{
		"geoip4.tsv":   sample4,
		"geoip6.tsv":   sample6,
		"city_geo.tsv": sampleCity,
	})
	db, warnings := Load(dir)
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	// 命中中国段(1.0.1.0 - 1.0.3.255)
	loc := db.Lookup("1.0.2.55")
	if !loc.Known || loc.Country != "中国" || loc.Region != "福建省" || loc.City != "福州市" {
		t.Fatalf("1.0.2.55 = %+v", loc)
	}
	if loc.Lat != 26.07 || loc.Lon != 119.30 {
		t.Fatalf("福州市坐标应来自 city_geo.tsv: lat=%v lon=%v", loc.Lat, loc.Lon)
	}
	// 命中澳洲段(city=0 → 空, 坐标用国家重心)
	loc = db.Lookup("1.0.0.10")
	if !loc.Known || loc.Country != "Australia" || loc.City != "" {
		t.Fatalf("1.0.0.10 = %+v", loc)
	}
	g := countryCenters["Australia"]
	if loc.Lat != g.lat || loc.Lon != g.lon {
		t.Fatalf("外国城市缺省应用国家重心: got lat=%v lon=%v want %v %v", loc.Lat, loc.Lon, g.lat, g.lon)
	}
	// 段边界: 1.0.3.255 仍在福建段内
	loc = db.Lookup("1.0.3.255")
	if !loc.Known || loc.City != "福州市" {
		t.Fatalf("上边界 1.0.3.255 = %+v", loc)
	}
	// 未收录
	loc = db.Lookup("8.8.8.8")
	if loc.Known || loc.Private || loc.Reason == "" {
		t.Fatalf("8.8.8.8 应未收录: %+v", loc)
	}
}

func TestLookupV6(t *testing.T) {
	dir := writeTmp(t, map[string]string{
		"geoip4.tsv": sample4,
		"geoip6.tsv": sample6,
	})
	db, _ := Load(dir)
	loc := db.Lookup("2001:200::1")
	if !loc.Known || loc.Country != "Japan" {
		t.Fatalf("2001:200::1 = %+v", loc)
	}
	// 前缀之外
	loc = db.Lookup("2001:201::1")
	if loc.Known {
		t.Fatalf("2001:201::1 应未收录: %+v", loc)
	}
}

func TestPrivateRanges(t *testing.T) {
	db := New()
	cases := []string{
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"127.0.0.1", "169.254.1.1", "224.0.0.1", "0.1.1.1",
		"fc00::1", "fd12:3456::1", "fe80::1", "::1",
	}
	for _, ip := range cases {
		loc := db.Lookup(ip)
		if !loc.Private {
			t.Fatalf("%s 应判为私有段: %+v", ip, loc)
		}
		if loc.Known {
			t.Fatalf("%s 私有段不应 Known: %+v", ip, loc)
		}
	}
	// 公共段不误判
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"} {
		if loc := db.Lookup(ip); loc.Private {
			t.Fatalf("%s 不应判为私有段: %+v", ip, loc)
		}
	}
	// 边界: 172.15/172.32 不是私有
	if loc := db.Lookup("172.15.0.1"); loc.Private {
		t.Fatalf("172.15.0.1 不应私有: %+v", loc)
	}
	if loc := db.Lookup("172.32.0.1"); loc.Private {
		t.Fatalf("172.32.0.1 不应私有: %+v", loc)
	}
}

func TestMissingDirDegrade(t *testing.T) {
	db, warnings := Load(filepath.Join(t.TempDir(), "no-such-dir"))
	if len(warnings) == 0 {
		t.Fatal("目录缺失应有 warning")
	}
	loc := db.Lookup("8.8.8.8")
	// 降级: 不 panic, 返回未收录
	if loc.Known || loc.Private == false && loc.Reason == "" {
		t.Fatalf("空 DB 查询应未收录: %+v", loc)
	}
}

func TestEmptyDBNeverPanics(t *testing.T) {
	db := New()
	for _, ip := range []string{"", "abc", "1.2.3", "1.2.3.4.5", "2001:db8::1", "::"} {
		_ = db.Lookup(ip)
	}
}

// 省会兜底: 城市查不到时用省会坐标(内置表)。
func TestProvinceCapitalFallback(t *testing.T) {
	dir := writeTmp(t, map[string]string{
		// 只有段表, 没有 city_geo.tsv —— 省会兜底走内置表
		"geoip4.tsv": sample4,
	})
	db, _ := Load(dir)
	loc := db.Lookup("1.0.2.55") // 福建省福州市
	if !loc.Known {
		t.Fatalf("应命中段: %+v", loc)
	}
	want := cLat["福建省"]
	if loc.Lat != want || loc.Lon != cLon["福建省"] {
		t.Fatalf("城市查不到应落省会坐标: got (%v,%v) want 福州 (%v,%v)",
			loc.Lat, loc.Lon, want, cLon["福建省"])
	}
}

// 非法 TSV 行不拖垮加载。
func TestBadRowsSkipped(t *testing.T) {
	dir := writeTmp(t, map[string]string{
		"geoip4.tsv": "badline\n16777216\tx\t中国\t福建省\t福州市\n16777472\t16777216\t中国\t福建省\t福州市\n16777216\t16777471\t中国\t福建省\t福州市\n",
	})
	db, warnings := Load(dir)
	if len(warnings) == 0 {
		t.Fatal("格式异常行应产生 warning")
	}
	// 合法行(1.0.0.0-1.0.0.255)仍可用
	loc := db.Lookup("1.0.0.10")
	if !loc.Known || loc.City != "福州市" {
		t.Fatalf("合法行应可用: %+v", loc)
	}
}

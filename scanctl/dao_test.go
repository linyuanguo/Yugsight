//go:build !windows || windows

package scanctl

import (
	"errors"
	"path/filepath"
	"testing"

	"yugsight/models"
)

// testEntity 测试用实体
type testEntity struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (e testEntity) EntityID() string { return e.Key }
func (e testEntity) Validate() error  { return nil }

// TestFileDAOCRUD 文件 DAO: 增删查 + 顺序稳定 + 幂等覆盖
func TestFileDAOCRUD(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d.jsonl")
	d, err := NewFileDAO[testEntity](p, func() testEntity { return testEntity{} })
	if err != nil {
		t.Fatal(err)
	}
	if d.Count() != 0 {
		t.Fatal("新文件应为空集")
	}
	if err := d.Add(testEntity{Key: "a", Value: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Add(testEntity{Key: "b", Value: "2"}); err != nil {
		t.Fatal(err)
	}
	// 幂等覆盖(同 ID 不重复)
	if err := d.Add(testEntity{Key: "a", Value: "3"}); err != nil {
		t.Fatal(err)
	}
	if d.Count() != 2 {
		t.Fatalf("Count = %d, want 2", d.Count())
	}
	e, err := d.Get("a")
	if err != nil || e.Value != "3" {
		t.Fatalf("Get(a) = %+v %v, want Value=3", e, err)
	}
	if _, err := d.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("不存在应返回 ErrNotFound, got %v", err)
	}
	if _, err := d.Remove("b"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := d.Remove("b"); ok {
		t.Fatal("重复删除不应成功")
	}
	if d.Count() != 1 {
		t.Fatalf("删除后 Count = %d, want 1", d.Count())
	}
	// List 顺序 = 入库顺序
	lst, _ := d.List()
	if len(lst) != 1 || lst[0].Key != "a" {
		t.Fatalf("List 顺序错误: %+v", lst)
	}
}

// TestFileDAOPersist 文件 DAO: 重载恢复 + 空 ID 拒绝
func TestFileDAOPersist(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d.jsonl")
	d1, _ := NewFileDAO[testEntity](p, func() testEntity { return testEntity{} })
	_ = d1.Add(testEntity{Key: "x", Value: "v"})

	d2, err := NewFileDAO[testEntity](p, func() testEntity { return testEntity{} })
	if err != nil {
		t.Fatal(err)
	}
	if d2.Count() != 1 {
		t.Fatalf("重载 Count = %d, want 1", d2.Count())
	}
	if err := d2.Add(testEntity{Key: "", Value: "bad"}); err == nil {
		t.Fatal("空 ID 应拒绝")
	}
}

// TestMemDAOCRUD 内存 DAO(第二后端, 验证接口双实现)
func TestMemDAOCRUD(t *testing.T) {
	var d DAO[testEntity] = NewMemDAO[testEntity](func() testEntity { return testEntity{} },
		testEntity{Key: "seed", Value: "s"})
	if d.Count() != 1 {
		t.Fatal("seed 应入库")
	}
	if err := d.Add(testEntity{Key: "m", Value: "v"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Get("seed"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Remove("seed"); err != nil {
		t.Fatal(err)
	}
	if d.Count() != 1 {
		t.Fatalf("Count = %d, want 1", d.Count())
	}
}

// TestModelsVulnFPFields 统一漏洞模型携带误报字段(3.2 扩展)
func TestModelsVulnFPFields(t *testing.T) {
	v := &models.Vuln{AssetIP: "10.0.0.1", CVE: "CVE-1", Title: "t"}
	v.FalsePositive = true
	v.FPNote = "备注"
	if !v.FalsePositive || v.FPNote != "备注" {
		t.Fatal("误报字段应可读写")
	}
}

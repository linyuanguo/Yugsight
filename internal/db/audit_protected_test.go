package db

import (
	"testing"
	"time"
)

// TestAuditProtectedPenta 渗透审计(penta.*)不可删除 —— 合规硬要求。
//
// 守的契约: 四个删除路径(单条删 / 手工清空 / 按天裁剪 / 超上限自动裁剪)
// 都不能碰 penta.* 记录, 同时普通记录仍可正常删除(保护不能变成"日志删不动")。
func TestAuditProtectedPenta(t *testing.T) {
	d := openTestDB(t)

	now := time.Now()
	pentaRec := AuditLog{ID: "al-penta-1", UserID: "admin", Action: "penta.task.run", Target: "10.0.0.5", Detail: "tpl=redis-unauth", CreatedAt: now}
	normalRec := AuditLog{ID: "al-normal-1", UserID: "admin", Action: "scan.start", Target: "10.0.0.9", CreatedAt: now}
	if err := d.Audits().Append(pentaRec); err != nil {
		t.Fatal(err)
	}
	if err := d.Audits().Append(normalRec); err != nil {
		t.Fatal(err)
	}

	// 1) 单条删: penta 记录拒绝, 普通记录放行
	if _, err := d.Audits().Delete(pentaRec.ID); err == nil {
		t.Fatal("渗透审计单条删除应被拒绝")
	}
	if ok, err := d.Audits().Delete(normalRec.ID); err != nil || !ok {
		t.Fatalf("普通审计单条删除应成功: ok=%v err=%v", ok, err)
	}

	// 2) 按天裁剪: 渗透记录虽超期也不删
	oldPenta := AuditLog{ID: "al-old-penta", UserID: "admin", Action: "penta.command", Target: "10.0.0.5", Detail: "step=ping", CreatedAt: now.AddDate(0, 0, -100)}
	oldNormal := AuditLog{ID: "al-old-normal", UserID: "admin", Action: "login.success", CreatedAt: now.AddDate(0, 0, -100)}
	_ = d.Audits().Append(oldPenta)
	_ = d.Audits().Append(oldNormal)
	deleted := d.Audits().PruneOlderThan(now.AddDate(0, 0, -90))
	if deleted != 1 {
		t.Fatalf("按天裁剪应只删普通记录 1 条, 实际 %d", deleted)
	}
	if _, err := d.Audits().Get(oldPenta.ID); err != nil {
		t.Fatal("超期的渗透审计记录必须保留")
	}

	// 3) 手工清空: 此时表内只剩两条 penta 保护记录, 清空必须 0 删除且记录全在
	n, err := d.Audits().DeleteAll()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("清空不应删除受保护记录, 实际 %d", n)
	}
	if _, err := d.Audits().Get(oldPenta.ID); err != nil {
		t.Fatal("手工清空后渗透审计记录必须仍在")
	}
	if _, err := d.Audits().Get(pentaRec.ID); err != nil {
		t.Fatal("手工清空后渗透审计记录必须仍在(第二条)")
	}

	// 4) 超上限自动裁剪: 最旧的 6 条是 penta(受保护), 裁剪预算应全部落在普通记录上
	d2 := openTestDB(t)
	for i := 0; i < maxAuditEntries+10; i++ {
		act := "scan.start"
		if i < 6 {
			act = "penta.task.run"
		}
		if err := d2.Audits().Append(AuditLog{UserID: "u", Action: act, CreatedAt: time.Now().Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := d2.Audits().List()
	if len(list) > maxAuditEntries {
		t.Fatalf("自动裁剪未生效: %d 条", len(list))
	}
	pentaLeft, normalLeft := 0, 0
	for _, l := range list {
		switch {
		case l.Action == "penta.task.run":
			pentaLeft++
		case l.Action == "scan.start":
			normalLeft++
		}
	}
	if pentaLeft != 6 { // 6 条 penta 必须全部存活(裁剪预算先给普通记录)
		t.Fatalf("自动裁剪后渗透审计应全部保留, 实际 %d", pentaLeft)
	}
	if normalLeft != maxAuditEntries-6 {
		t.Fatalf("自动裁剪后普通记录应剩 %d 条, 实际 %d", maxAuditEntries-6, normalLeft)
	}
}

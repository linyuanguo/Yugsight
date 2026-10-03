package main

// 守资产存活状态合并的契约(2026-09-25 修"明明存活却显示未存活"):
// 既有资产行 upsert 时 Alive 字段必须参与合并 ——
// ① 本轮确认存活 → 覆盖历史 false(修前该字段完全不合并, 存活永远写不进去)
// ② 本轮无存活观测(false 零值) → 不覆盖历史 true(资产徽章 = 曾观测到存活)。

import (
	"testing"

	"yugsight/internal/models"
)

func TestUpsertProbeAssetAliveMerge(t *testing.T) {
	_, d := newV2TestEnv(t)
	dao := d.Assets()
	if isNilDAO(dao) {
		t.Fatal("资产 DAO 不可用")
	}

	// ① 首轮确认存活
	if err := upsertProbeAsset(dao, "", &models.Asset{IP: "10.9.9.1", Alive: true, Ports: []int{80}}); err != nil {
		t.Fatalf("首轮写入: %v", err)
	}
	cur, err := dao.FindByIP("10.9.9.1")
	if err != nil || len(cur) != 1 || !cur[0].Alive {
		t.Fatalf("首轮应判存活: %+v err=%v", cur, err)
	}

	// ② 次轮无存活观测(Alive=false 零值, 仅更新端口) → 历史 true 保留
	if err := upsertProbeAsset(dao, "", &models.Asset{IP: "10.9.9.1", Ports: []int{443}}); err != nil {
		t.Fatalf("次轮: %v", err)
	}
	cur, _ = dao.FindByIP("10.9.9.1")
	if len(cur) != 1 || !cur[0].Alive {
		t.Fatalf("无观测的 false 不应覆盖历史存活: %+v", cur)
	}
	if len(cur[0].Ports) != 2 {
		t.Fatalf("端口应合并: %+v", cur[0].Ports)
	}

	// ③ 既有行历史 false(未探测过), 本轮确认存活 → 必须翻成 true(修前 bug)
	if err := upsertProbeAsset(dao, "", &models.Asset{IP: "10.9.9.2"}); err != nil {
		t.Fatalf("建行: %v", err)
	}
	if err := upsertProbeAsset(dao, "", &models.Asset{IP: "10.9.9.2", Alive: true, Ports: []int{22}}); err != nil {
		t.Fatalf("存活回写: %v", err)
	}
	cur, _ = dao.FindByIP("10.9.9.2")
	if len(cur) != 1 || !cur[0].Alive {
		t.Fatalf("本轮确认存活应覆盖历史 false(修前该字段不合并): %+v", cur)
	}
}

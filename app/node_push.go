// node_push.go 节点告警推送装配层(2026-09-28: 打通真实告警与推送链路)。
//
// 闭环: 采集引擎异常事件(离线/恢复/阈值越限) → 告警落表(node_alerts, 含推送状态)
// → 后端匹配推送规则(级别/时段/免打扰/延迟/目标) → 发送 Webhook(企业微信/钉钉/飞书)
// → 推送结果写日志(push_logs, 关联告警 ID) + 回写告警推送状态。
//
// 架构边界(与 node_api.go 同一装配模式):
//   - 触发与规则匹配全部在采集事件钩子(collectOnEvent)内完成后端侧闭环,
//     前端只展示 + 手动重推(POST /api/node/push/retry);
//   - 配置走 settings.json 的 nodepush 节(targets + rules, writeSection 合并写),
//     不落 db —— 与中心端"配置一律 settings.json"口径一致;
//   - 落库走注入的 v2DB()(双 nil 守卫: 库未就绪/Close 后 DAO 置 nil);
//   - 路由挂**根 mux**(前端 v2dash 按 /api/node/push/* 直连, 不在 /api/v2/ 子树,
//     与 /api/dashboard/flows 同模式; 挂 v2 会永远 404)。
//
// 默认零行为(规则 5): nodepush 节缺失 = 无目标, 告警照常落表但推送状态停在
// "未推送", 不发任何外连。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"yugsight/internal/collect"
	"yugsight/internal/db"
	"yugsight/internal/server"
)

// ===== 配置(settings.json 的 nodepush 节) =====

// pushTarget 一个推送目标(企业微信/钉钉/飞书 Webhook)。
type pushTarget struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"` // wecom / dingtalk / feishu
	Webhook   string    `json:"webhook"`
	Note      string    `json:"note,omitempty"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
}

// pushRules 推送规则(字段与前端 PushRuleConfig 表单一一对应, 字段顺序与
// 前端 normalizeRules 的固定键序一致 —— 前端按自己的键序补默认值, 这里保序
// 是为了"恢复已保存"直接回显时不出意外)。
type pushRules struct {
	Levels      []string `json:"levels"`      // 推送的告警级别(critical/warning/info; 空=不推)
	DelaySec    int      `json:"delaySec"`    // 告警延迟(秒, 默认 30)
	Window      string   `json:"window"`      // all / work / custom
	WorkStart   string   `json:"workStart"`   // 工作时段开始 HH:MM
	WorkEnd     string   `json:"workEnd"`     // 工作时段结束 HH:MM
	CustomStart string   `json:"customStart"` // 自定义时段开始
	CustomEnd   string   `json:"customEnd"`   // 自定义时段结束
	Dnd         bool     `json:"dnd"`         // 免打扰开关
	DndStart    string   `json:"dndStart"`    // 免打扰开始(支持跨天, 如 22:00)
	DndEnd      string   `json:"dndEnd"`      // 免打扰结束(如 08:00)
	TargetIds   []string `json:"targetIds"`   // 关联的推送目标 id(空=不推任何目标)
}

type nodePushConfig struct {
	Targets []pushTarget `json:"targets"`
	Rules   pushRules    `json:"rules"`
	// Enabled 告警推送总开关(2026-09-28: 大屏轻量入口用, 见 hPushSwitch)。
	// 用 *bool 区分"未写"(nil=开, 保持存量用户行为不变) 与 显式 false(关):
	// 直接 bool 零值会把升级前的老库全部静默关掉, 违背"不改变既有推送行为"。
	Enabled *bool `json:"enabled,omitempty"`
}

// pushMasterOn 总开关判定: nil(未写)=开。
func pushMasterOn(cfg nodePushConfig) bool {
	return cfg.Enabled == nil || *cfg.Enabled
}

// loadNodePushCfg 读 nodepush 节并补默认值。缺失 = 空配置(无目标 → 不推送)。
func loadNodePushCfg() nodePushConfig {
	var cfg nodePushConfig
	b, ok := section(secNodePush, "")
	if !ok || len(b) == 0 {
		return nodePushConfig{Rules: defaultPushRules()}
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		nodeLogLine("nodepush 节解析失败, 按空配置处理(不推送): " + err.Error())
		return nodePushConfig{Rules: defaultPushRules()}
	}
	// 用户手写部分配置时缺字段 → 逐字段补默认(与前端 defaultRules 同口径)。
	// 注意不能整段覆盖: 那会把已保存的规则冲回默认(2026-09-28 测试暴露)。
	if len(cfg.Rules.Levels) == 0 {
		cfg.Rules.Levels = defaultPushRules().Levels
	}
	if cfg.Rules.DelaySec < 0 {
		cfg.Rules.DelaySec = 30
	}
	if cfg.Rules.Window != "work" && cfg.Rules.Window != "custom" {
		cfg.Rules.Window = "all"
	}
	d := defaultPushRules()
	if cfg.Rules.WorkStart == "" {
		cfg.Rules.WorkStart = d.WorkStart
	}
	if cfg.Rules.WorkEnd == "" {
		cfg.Rules.WorkEnd = d.WorkEnd
	}
	if cfg.Rules.CustomStart == "" {
		cfg.Rules.CustomStart = d.CustomStart
	}
	if cfg.Rules.CustomEnd == "" {
		cfg.Rules.CustomEnd = d.CustomEnd
	}
	if cfg.Rules.DndStart == "" {
		cfg.Rules.DndStart = d.DndStart
	}
	if cfg.Rules.DndEnd == "" {
		cfg.Rules.DndEnd = d.DndEnd
	}
	return cfg
}

// defaultPushRules 规则默认值(与前端 defaultRules 同一口径)。
func defaultPushRules() pushRules {
	return pushRules{
		Levels: []string{"critical", "warning", "info"},
		DelaySec:   30,
		Window:     "all",
		WorkStart:  "09:00", WorkEnd: "18:00",
		CustomStart: "09:00", CustomEnd: "18:00",
		Dnd: false, DndStart: "22:00", DndEnd: "08:00",
	}
}

// saveNodePushCfg 合并写 nodepush 节(保留其它节与注释)并刷新缓存。
func saveNodePushCfg(cfg nodePushConfig) error {
	if err := writeSection(secNodePush, cfg); err != nil {
		return err
	}
	resetSettingsCache()
	return nil
}

// ===== 告警生成(采集事件 → 告警表) =====

// 告警推送状态口径(与前端 PUSH_STATUS 一致)。
const (
	alertUnpushed = "unpushed" // 未推送
	alertPushed   = "pushed"   // 推送成功(至少一个目标成功)
	alertFailed   = "failed"   // 推送失败(所有目标失败)

	logSuccess = "success"
	logFailed  = "failed"
	logSkipped = "skipped"
)

// maxPushDelay 推送延迟上限(误配置防护: 时段计算异常时最晚 24h 内补发)。
const maxPushDelay = 24 * time.Hour

// onNodeAlert 采集异常事件 → 告警落表 + 触发推送闭环(装配层注入 collect 包,
// 调用点见 node_api.go 的 collectOnEvent)。
//
// 顶层 recover: 该钩子跑在采集引擎 goroutine 里, panic 会带走整轮采集循环
// (与 taskRecorder 回调同一红线)。
func onNodeAlert(ev *collect.Event) {
	defer func() {
		if r := recover(); r != nil {
			nodeLogLine(fmt.Sprintf("告警处理 panic(已恢复, 不影响采集): %v", r))
		}
	}()
	d := v2DB()
	if d == nil {
		return
	}
	dao := d.NodeAlerts()
	if dao == nil {
		return
	}

	a := &db.NodeAlert{
		ID:         newAlertID(ev),
		TaskID:     ev.TaskID,
		Source:     alertSource(ev),
		Device:     alertDevice(ev),
		IP:         alertIP(ev.Target),
		Level:      alertLevel(ev.Level),
		Type:       ev.Type,
		Content:    ev.Msg,
		At:         ev.At,
		PushStatus: alertUnpushed,
	}
	if _, err := dao.Upsert(a); err != nil {
		nodeLogLine("告警落库失败 " + a.ID + ": " + err.Error())
		return
	}
	// 裁剪: 30 天 + 3000 条双限(告警是排障线索, 比采集轮次留久)
	_, _ = dao.PruneByTime(time.Now().Add(-30 * 24 * time.Hour))
	_, _ = dao.PruneKeep(3000)

	scheduleAlertPush(a)
}

// newAlertID 告警 ID: na + 任务 + 毫秒时间戳 + 4 位随机(同任务同毫秒多条不撞)。
// randHex 复用 auth.go 的既有实现(同包, 不重复定义)。
func newAlertID(ev *collect.Event) string {
	return fmt.Sprintf("na-%s-%d-%s", ev.TaskID, ev.At.UnixMilli(), randHex(2))
}

// alertLevel 采集事件级别 → 前端三级口径(collect 用 warn, 前端用 warning)。
func alertLevel(evLevel string) string {
	if evLevel == collect.EvtWarn {
		return "warning"
	}
	return evLevel
}

// alertSource 事件归属 → 告警来源(device 设备 / link 链路)。
// 探针类告警(source=probe)来自探针框架, 采集引擎不产生。
func alertSource(ev *collect.Event) string {
	if ev.Side == collect.SideNet {
		return "link"
	}
	return "device"
}

// alertDevice 设备名称: 取采集任务名(页面建任务时填的), 缺失回退目标。
func alertDevice(ev *collect.Event) string {
	if e := instanceCollect(); e != nil {
		for _, t := range e.Config().Tasks {
			if t.ID == ev.TaskID && strings.TrimSpace(t.Name) != "" {
				return strings.TrimSpace(t.Name)
			}
		}
	}
	return ev.Target
}

// alertIP 从目标串提取 IP 展示(host:port / URL / 裸 IP 都归一成 IP)。
func alertIP(target string) string {
	s := strings.TrimSpace(target)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	for _, c := range []byte{'/', '#', '?'} {
		if i := strings.IndexByte(s, c); i >= 0 {
			s = s[:i]
		}
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

// ===== 规则匹配与推送调度 =====

// scheduleAlertPush 按当前规则决定是否推送、何时推送。
// 不推送的情形都落 skipped 日志(未配置目标/规则未关联目标), 让"为什么没推"可追溯;
// 级别不匹配与时段外不写日志(用户主动过滤, 写日志只会刷屏)。
func scheduleAlertPush(a *db.NodeAlert) {
	cfg := loadNodePushCfg()
	r := cfg.Rules

	// 0. 总开关: 关 = 不推任何告警也不写日志(与级别不匹配/时段外同口径 ——
	// 用户主动关的, 写 skipped 日志只会刷屏)。
	if !pushMasterOn(cfg) {
		return
	}
	// 1. 级别过滤: 空 levels = 不推任何告警(前端"全部取消 = 不推送"同语义)
	if !containsStr(r.Levels, a.Level) {
		return
	}
	now := time.Now()
	// 2. 推送时段: 窗外不推(不做补发 —— 时段语义是"这些时间不打扰")
	if !inPushWindow(r, now) {
		return
	}
	// 3. 目标: 规则关联的启用目标; 空 = 不推(写 skipped 日志说明原因)
	targets := ruleTargets(cfg, r)
	if len(targets) == 0 {
		writePushLog(a.ID, a, "", logSkipped, "规则未关联推送目标(或关联目标均已停用)")
		return
	}
	// 4. 延迟 + 免打扰: 推送时刻落在免打扰窗内 → 顺延到窗外(支持跨天)
	pushAt := now.Add(time.Duration(r.DelaySec) * time.Second)
	if r.Dnd {
		if t := nextOutsideDnd(pushAt, r.DndStart, r.DndEnd); t.After(pushAt) {
			pushAt = t
		}
	}
	delay := pushAt.Sub(now)
	if delay < 0 {
		delay = 0
	}
	if delay > maxPushDelay {
		delay = maxPushDelay
	}
	time.AfterFunc(delay, func() {
		defer func() {
			if r := recover(); r != nil {
				nodeLogLine(fmt.Sprintf("推送执行 panic(已恢复): %v", r))
			}
		}()
		doPushAlert(a.ID)
	})
}

// ruleTargets 规则关联的启用目标(按规则内顺序)。
func ruleTargets(cfg nodePushConfig, r pushRules) []pushTarget {
	if len(r.TargetIds) == 0 {
		return nil
	}
	want := make(map[string]bool, len(r.TargetIds))
	for _, id := range r.TargetIds {
		want[id] = true
	}
	out := make([]pushTarget, 0, len(r.TargetIds))
	for _, t := range cfg.Targets {
		if want[t.ID] && t.Enabled {
			out = append(out, t)
		}
	}
	return out
}

// pushMu 串行化推送执行(自动推送与手动重推不交错; Webhook 限速由平台侧保证,
// 这里只防同一进程内并发打同一 Webhook)。
var pushMu sync.Mutex

// doPushAlert 对一条告警执行推送(遍历规则目标), 回写告警推送状态并逐目标写日志。
// 自动推送(定时)与手动重推(retry 接口)共用本入口。
func doPushAlert(alertID string) {
	pushMu.Lock()
	defer pushMu.Unlock()

	// 总开关守卫: 自动推送的调度入口已挡(不写日志); 这里再挡一道是防手动重推
	// 等其它入口绕过(手动重推在 handler 层会先回 409, 这里是兜底)。
	cfg0 := loadNodePushCfg()
	if !pushMasterOn(cfg0) {
		return
	}
	d := v2DB()
	if d == nil {
		return
	}
	dao := d.NodeAlerts()
	if dao == nil {
		return
	}
	a, err := dao.Get(alertID)
	if err != nil {
		return // 告警已被裁剪, 推送无主
	}
	cfg := loadNodePushCfg()
	targets := ruleTargets(cfg, cfg.Rules)
	if len(targets) == 0 {
		writePushLog(a.ID, a, "", logSkipped, "规则未关联推送目标(或关联目标均已停用)")
		return
	}

	okCount := 0
	for _, t := range targets {
		reason := sendToTarget(t, a)
		status := logSuccess
		if reason != "" {
			status = logFailed
		} else {
			okCount++
		}
		writePushLog(a.ID, a, t.Name, status, reason)
	}

	status := alertPushed
	if okCount == 0 {
		status = alertFailed
	}
	now := time.Now()
	a.PushStatus = status
	a.PushedAt = &now
	if err := dao.Update(a); err != nil {
		nodeLogLine("告警推送状态回写失败 " + a.ID + ": " + err.Error())
	}
	nodeLogLine(fmt.Sprintf("告警 %s 推送完成: %s(目标 %d, 成功 %d)",
		a.ID, status, len(targets), okCount))
}

// writePushLog 写一条推送日志(跳过类目标名为空), 并做双限裁剪。
// alertID 空 = 无主记录(测试推送), 前端"关联告警"列显示"-"。
func writePushLog(alertID string, a *db.NodeAlert, target, status, reason string) {
	d := v2DB()
	if d == nil {
		return
	}
	dao := d.PushLogs()
	if dao == nil {
		return
	}
	base := alertID
	if base == "" {
		base = "none"
	}
	l := &db.PushLog{
		ID:      fmt.Sprintf("pl-%s-%s-%d-%s", base, target, time.Now().UnixMilli(), randHex(2)),
		AlertID: alertID,
		At:      time.Now(),
		Level:   a.Level,
		Content: a.Content,
		Target:  target,
		Status:  status,
		Reason:  reason,
	}
	if _, err := dao.Upsert(l); err != nil {
		nodeLogLine("推送日志落库失败 " + l.ID + ": " + err.Error())
		return
	}
	_, _ = dao.PruneByTime(time.Now().Add(-30 * 24 * time.Hour))
	_, _ = dao.PruneKeep(10000)
}

// ===== 消息模板(三级卡片: 紧急=红 / 重要=橙 / 提示=蓝) =====

type levelCard struct {
	label string // 紧急 / 重要 / 提示
	emoji string
	color string // 飞书卡片模板色: red / orange / blue
	hex   string // 钉钉 markdown font 色(十六进制)
}

var levelCards = map[string]levelCard{
	"critical": {label: "紧急", emoji: "🚨", color: "red", hex: "#FF5252"},
	"warning":  {label: "重要", emoji: "⚠️", color: "orange", hex: "#FF9800"},
	"info":     {label: "提示", emoji: "ℹ️", color: "blue", hex: "#409EFF"},
}

func cardOf(level string) levelCard {
	if c, ok := levelCards[level]; ok {
		return c
	}
	return levelCards["info"]
}

// alertDetailLink 告警详情跳转链接(前端 hash 路由: /app/#/nodemonitor?view=alerts
// &tab=records&alertId=)。UI 地址未就绪(服务启动早期)返回空串, 消息省略链接行。
func alertDetailLink(alertID string) string {
	u := GetUIURL()
	if u == "" {
		return ""
	}
	return strings.TrimRight(u, "/") + "/app/#/nodemonitor?view=alerts&tab=records&alertId=" + alertID
}

// buildPushBody 按目标类型构造 Webhook 消息体。
// 内容五要素(任务口径): 告警级别 / 设备名称/IP / 告警内容 / 发生时间 / 详情跳转链接。
func buildPushBody(t pushTarget, a *db.NodeAlert) ([]byte, error) {
	c := cardOf(a.Level)
	device := strings.TrimSpace(a.Device)
	if device == "" {
		device = a.IP
	}
	if a.IP != "" && device != a.IP {
		device += " (" + a.IP + ")"
	}
	atStr := a.At.Format("2006-01-02 15:04:05")
	link := alertDetailLink(a.ID)

	switch t.Type {
	case "wecom":
		// 企业微信 markdown: 支持 ## / > / ** / [链接](url); font 色只有
		// info/warning/comment 三档(无红), 用 emoji 区分级别。
		md := fmt.Sprintf("## %s 【%s告警】\n> **设备**: %s\n> **内容**: %s\n> **时间**: %s",
			c.emoji, c.label, device, a.Content, atStr)
		if link != "" {
			md += "\n> [查看详情](" + link + ")"
		}
		return json.Marshal(map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]string{"content": md},
		})
	case "dingtalk":
		// 钉钉 markdown: <font color="#RRGGBB"> 支持任意十六进制色
		title := c.label + "告警 · " + device
		md := fmt.Sprintf("## <font color=\"%s\">%s 【%s告警】</font>\n> **设备**: %s\n> **内容**: %s\n> **时间**: %s",
			c.hex, c.emoji, c.label, device, a.Content, atStr)
		if link != "" {
			md += "\n> [查看详情](" + link + ")"
		}
		return json.Marshal(map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]string{"title": title, "text": md},
		})
	case "feishu":
		// 飞书交互卡片: header.template 直接对应三级卡片色(红/橙/蓝),
		// 详情链接做卡片按钮。
		elements := []any{
			map[string]any{
				"tag":  "div",
				"text": map[string]string{"tag": "lark_md", "content": fmt.Sprintf("**设备**: %s\n**内容**: %s\n**时间**: %s", device, a.Content, atStr)},
			},
			map[string]any{"tag": "hr"},
		}
		if link != "" {
			elements = append(elements, map[string]any{
				"tag": "action",
				"actions": []any{map[string]any{
					"tag":     "button",
					"text":    map[string]string{"tag": "plain_text", "content": "查看详情"},
					"type":    "primary",
					"url":     link,
				}},
			})
		}
		return json.Marshal(map[string]any{
			"msg_type": "interactive",
			"card": map[string]any{
				"config": map[string]any{"wide_screen_mode": true},
				"header": map[string]any{
					"template": c.color,
					"title":    map[string]string{"tag": "plain_text", "content": c.label + "告警 · " + device},
				},
				"elements": elements,
			},
		})
	default:
		return nil, fmt.Errorf("未知推送类型: %s", t.Type)
	}
}

// sendToTarget 向单个目标发送; 返回空串=成功, 非空=失败原因(写进推送日志)。
func sendToTarget(t pushTarget, a *db.NodeAlert) string {
	if !t.Enabled {
		return "目标已停用"
	}
	body, err := buildPushBody(t, a)
	if err != nil {
		return "消息构造失败: " + err.Error()
	}
	return doPostWebhook(t.Webhook, body)
}

// doPostWebhook 发送 Webhook(10s 超时), 解析三平台回执。
// 企业微信/钉钉: errcode=0 成功; 飞书: code=0 成功; 2xx 且无错误字段 = 成功。
func doPostWebhook(webhook string, body []byte) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return "请求构造失败: " + err.Error()
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "发送失败: " + err.Error()
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, io.LimitReader(resp.Body, 8*1024))
	txt := strings.TrimSpace(buf.String())
	if resp.StatusCode >= 400 {
		return fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncateStr(txt, 200))
	}
	return webhookErrOf(txt)
}

// webhookErrOf 解析平台回执, 返回空串=成功。
func webhookErrOf(txt string) string {
	if txt == "" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(txt), &m); err != nil {
		return "响应非 JSON: " + truncateStr(txt, 200)
	}
	if code, ok := m["errcode"]; ok { // wecom / dingtalk
		if f, ok2 := code.(float64); ok2 && f == 0 {
			return ""
		}
		return fmt.Sprintf("errcode=%v %v", code, m["errmsg"])
	}
	if code, ok := m["code"]; ok { // feishu
		if f, ok2 := code.(float64); ok2 && f == 0 {
			return ""
		}
		return fmt.Sprintf("code=%v %v", code, m["msg"])
	}
	return ""
}

// truncateStr / containsStr 复用 report_api.go / report_raw_api.go 的既有实现(同包)。

// ===== 时间窗判定(工作时段/自定义/免打扰, 均支持跨天) =====

// parseHM 解析 "HH:MM"。
func parseHM(s string) (hour, minute int, ok bool) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// inPushWindow 当前时刻是否在推送时段内。时间解析失败 = 全天(不误伤推送)。
func inPushWindow(r pushRules, now time.Time) bool {
	if r.Window == "work" {
		return inTimeRange(now, r.WorkStart, r.WorkEnd)
	}
	if r.Window == "custom" {
		return inTimeRange(now, r.CustomStart, r.CustomEnd)
	}
	return true
}

// inTimeRange 时刻是否落在 [start, end) 内(支持跨天, 如 22:00-08:00)。
func inTimeRange(now time.Time, start, end string) bool {
	sh, sm, ok1 := parseHM(start)
	eh, em, ok2 := parseHM(end)
	if !ok1 || !ok2 {
		return true
	}
	sMin, eMin := sh*60+sm, eh*60+em
	if sMin == eMin {
		return true
	}
	nMin := now.Hour()*60 + now.Minute()
	if sMin < eMin {
		return nMin >= sMin && nMin < eMin
	}
	return nMin >= sMin || nMin < eMin // 跨天
}

// nextOutsideDnd 返回落在免打扰窗外(或窗外之后)的第一个时刻, 用于免打扰补发。
// now 已在窗外 = 原样返回。
func nextOutsideDnd(now time.Time, start, end string) time.Time {
	sh, sm, ok1 := parseHM(start)
	eh, em, ok2 := parseHM(end)
	if !ok1 || !ok2 {
		return now
	}
	sMin, eMin := sh*60+sm, eh*60+em
	if sMin == eMin {
		return now
	}
	at := func(dayOffset int, mMin int) time.Time {
		return time.Date(now.Year(), now.Month(), now.Day()+dayOffset, mMin/60, mMin%60, 0, 0, now.Location())
	}
	nMin := now.Hour()*60 + now.Minute()
	if sMin < eMin { // 当天 [sMin, eMin)
		if nMin >= sMin && nMin < eMin {
			return at(0, eMin)
		}
		return now
	}
	// 跨天: [sMin, 24:00) ∪ [00:00, eMin)
	if nMin >= sMin {
		return at(1, eMin)
	}
	if nMin < eMin {
		return at(0, eMin)
	}
	return now
}

// ===== 路由与 handler(挂根 mux, 前端 v2dash 按 /api/node/push/* 直连) =====

func registerNodePushRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/node/push/targets", requireAuth(hPushTargets))
	mux.HandleFunc("POST /api/node/push/target", requireAuth(adminOrOperator(hPushTargetCreate)))
	mux.HandleFunc("PUT /api/node/push/target/{id}", requireAuth(adminOrOperator(hPushTargetUpdate)))
	mux.HandleFunc("DELETE /api/node/push/target/{id}", requireAuth(adminOrOperator(hPushTargetDelete)))
	mux.HandleFunc("GET /api/node/push/rules", requireAuth(hPushRulesGet))
	mux.HandleFunc("PUT /api/node/push/rules", requireAuth(adminOrOperator(hPushRulesPut)))
	// 告警推送总开关 + 状态概览(2026-09-28: 3D 拓扑页「告警设置」轻量推送入口用;
	// 大屏拓扑卡已删除, 消费方仅剩封存的 topo3d/PushStatusPanel —— 第三阶段对接时恢复)
	mux.HandleFunc("PUT /api/node/push/switch", requireAuth(adminOrOperator(hPushSwitch)))
	mux.HandleFunc("GET /api/node/push/stat", requireAuth(hPushStat))
	mux.HandleFunc("POST /api/node/push/test", requireAuth(adminOrOperator(hPushTest)))
	mux.HandleFunc("GET /api/node/push/logs", requireAuth(hPushLogs))
	mux.HandleFunc("GET /api/node/push/alerts", requireAuth(hPushAlerts))
	mux.HandleFunc("POST /api/node/push/retry", requireAuth(adminOrOperator(hPushRetry)))
	mux.HandleFunc("POST /api/node/push/alerts/{id}/handled", requireAuth(adminOrOperator(hPushAlertHandled)))
}

// ---- 推送目标 CRUD ----

func hPushTargets(w http.ResponseWriter, r *http.Request) {
	cfg := loadNodePushCfg()
	list := cfg.Targets
	if list == nil {
		list = []pushTarget{}
	}
	server.OK(w, map[string]any{"list": list, "total": len(list)})
}

// validPushTarget 校验目标字段(名称 1-20, 类型白名单, Webhook 合法 http/https URL)。
func validPushTarget(name, typ, webhook string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("推送名称必填")
	}
	if len([]rune(name)) > 20 {
		return fmt.Errorf("推送名称不能超过 20 个字符")
	}
	if typ != "wecom" && typ != "dingtalk" && typ != "feishu" {
		return errors.New("未知推送类型: " + typ)
	}
	u, err := url.Parse(strings.TrimSpace(webhook))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("Webhook 必须是合法的 http/https 地址")
	}
	return nil
}

func hPushTargetCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Webhook string `json:"webhook"`
		Note    string `json:"note"`
		Enabled *bool  `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := validPushTarget(in.Name, in.Type, in.Webhook); err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	cfg := loadNodePushCfg()
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	t := pushTarget{
		ID:        "pt-" + randHex(4),
		Name:      strings.TrimSpace(in.Name),
		Type:      in.Type,
		Webhook:   strings.TrimSpace(in.Webhook),
		Note:      strings.TrimSpace(in.Note),
		Enabled:   enabled,
		CreatedAt: time.Now(),
	}
	cfg.Targets = append(cfg.Targets, t)
	if err := saveNodePushCfg(cfg); err != nil {
		server.FailInternal(w, "保存失败: "+err.Error())
		return
	}
	logAudit(v2DB(), r, "nodepush.target.create", t.ID, "type="+t.Type)
	server.OK(w, t)
}

func hPushTargetUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Webhook string `json:"webhook"`
		Note    string `json:"note"`
		Enabled *bool  `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := validPushTarget(in.Name, in.Type, in.Webhook); err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	cfg := loadNodePushCfg()
	for i := range cfg.Targets {
		if cfg.Targets[i].ID == id {
			cfg.Targets[i].Name = strings.TrimSpace(in.Name)
			cfg.Targets[i].Type = in.Type
			cfg.Targets[i].Webhook = strings.TrimSpace(in.Webhook)
			cfg.Targets[i].Note = strings.TrimSpace(in.Note)
			if in.Enabled != nil {
				cfg.Targets[i].Enabled = *in.Enabled
			}
			if err := saveNodePushCfg(cfg); err != nil {
				server.FailInternal(w, "保存失败: "+err.Error())
				return
			}
			logAudit(v2DB(), r, "nodepush.target.update", id, "")
			server.OK(w, cfg.Targets[i])
			return
		}
	}
	server.FailNotFound(w, "目标不存在: "+id)
}

func hPushTargetDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cfg := loadNodePushCfg()
	found := false
	out := make([]pushTarget, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		if t.ID == id {
			found = true
			continue
		}
		out = append(out, t)
	}
	if !found {
		server.FailNotFound(w, "目标不存在: "+id)
		return
	}
	cfg.Targets = out
	// 级联清理: 规则里对该目标的关联一并清除(前端删除弹窗已承诺此行为)
	newIds := make([]string, 0, len(cfg.Rules.TargetIds))
	for _, tid := range cfg.Rules.TargetIds {
		if tid != id {
			newIds = append(newIds, tid)
		}
	}
	cfg.Rules.TargetIds = newIds
	if err := saveNodePushCfg(cfg); err != nil {
		server.FailInternal(w, "保存失败: "+err.Error())
		return
	}
	logAudit(v2DB(), r, "nodepush.target.delete", id, "")
	server.OK(w, map[string]any{"id": id, "deleted": true})
}

// ---- 推送规则 ----

func hPushRulesGet(w http.ResponseWriter, r *http.Request) {
	server.OK(w, loadNodePushCfg().Rules)
}

func hPushRulesPut(w http.ResponseWriter, r *http.Request) {
	var in pushRules
	if !decodeJSON(w, r, &in) {
		return
	}
	// 级别白名单(去重保序; 空数组合法 = 不推送任何告警)
	seen := map[string]bool{}
	levels := make([]string, 0, len(in.Levels))
	for _, l := range in.Levels {
		if l != "critical" && l != "warning" && l != "info" {
			server.FailBadRequest(w, "未知告警级别: "+l)
			return
		}
		if !seen[l] {
			seen[l] = true
			levels = append(levels, l)
		}
	}
	in.Levels = levels
	if in.DelaySec < 0 || in.DelaySec > 3600 {
		server.FailBadRequest(w, "延迟需在 0 - 3600 秒之间")
		return
	}
	if in.Window != "all" && in.Window != "work" && in.Window != "custom" {
		server.FailBadRequest(w, "推送时段必须是 all / work / custom")
		return
	}
	if in.Window == "custom" {
		if _, _, ok := parseHM(in.CustomStart); !ok {
			server.FailBadRequest(w, "自定义开始时间格式应为 HH:MM")
			return
		}
		if _, _, ok := parseHM(in.CustomEnd); !ok {
			server.FailBadRequest(w, "自定义结束时间格式应为 HH:MM")
			return
		}
	}
	if in.Dnd {
		if _, _, ok := parseHM(in.DndStart); !ok {
			server.FailBadRequest(w, "免打扰开始时间格式应为 HH:MM")
			return
		}
		if _, _, ok := parseHM(in.DndEnd); !ok {
			server.FailBadRequest(w, "免打扰结束时间格式应为 HH:MM")
			return
		}
	}
	// 目标 id 只保留实际存在的(删目标后前端残留 id 由此兜底清除)
	cfg := loadNodePushCfg()
	exist := make(map[string]bool, len(cfg.Targets))
	for _, t := range cfg.Targets {
		exist[t.ID] = true
	}
	ids := make([]string, 0, len(in.TargetIds))
	for _, tid := range in.TargetIds {
		if exist[tid] {
			ids = append(ids, tid)
		}
	}
	in.TargetIds = ids

	cfg.Rules = in
	if err := saveNodePushCfg(cfg); err != nil {
		server.FailInternal(w, "保存失败: "+err.Error())
		return
	}
	logAudit(v2DB(), r, "nodepush.rules.save", "", fmt.Sprintf("levels=%d delay=%ds window=%s targets=%d",
		len(in.Levels), in.DelaySec, in.Window, len(in.TargetIds)))
	server.OK(w, map[string]any{"saved": true})
}

// ---- 告警推送总开关(大屏轻量入口: 只给开关, 完整配置在节点监控侧) ----

// hPushSwitch PUT /api/node/push/switch body {enabled} → {enabled}
// 只改 nodepush 节的 enabled 字段, 目标/规则原样保留(读改写, 不动其它字段)。
func hPushSwitch(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	cfg := loadNodePushCfg()
	cfg.Enabled = &in.Enabled
	if err := saveNodePushCfg(cfg); err != nil {
		server.FailInternal(w, "保存失败: "+err.Error())
		return
	}
	logAudit(v2DB(), r, "nodepush.switch", "", fmt.Sprintf("enabled=%t", in.Enabled))
	server.OK(w, map[string]any{"enabled": in.Enabled})
}

// hPushStat GET /api/node/push/stat → {enabled, todayPushed, todayFailed}
// 推送状态概览(大屏浏览模式只读展示): 今天(本地 0 点起)的推送日志按状态计数。
// 日志表上限 10000 条且 30 天裁剪, 全量拉回内存计数无压力(与 hPushLogs 同口径)。
func hPushStat(w http.ResponseWriter, r *http.Request) {
	cfg := loadNodePushCfg()
	out := map[string]any{
		"enabled":     pushMasterOn(cfg),
		"todayPushed": 0,
		"todayFailed": 0,
	}
	d := v2DB()
	if d == nil {
		server.OK(w, out) // 库不可用: 开关状态如实返回, 计数归零(降级不报错)
		return
	}
	dao := d.PushLogs()
	if dao == nil {
		server.OK(w, out)
		return
	}
	rows, err := dao.List()
	if err != nil {
		server.FailInternal(w, "查询失败: "+err.Error())
		return
	}
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	pushed, failed := 0, 0
	for _, l := range rows {
		if l.At.Before(start) {
			continue
		}
		switch l.Status {
		case logSuccess:
			pushed++
		case logFailed:
			failed++
		}
	}
	out["todayPushed"] = pushed
	out["todayFailed"] = failed
	server.OK(w, out)
}

// ---- 测试推送(前端触发, 后端真实发送一条测试告警) ----

func hPushTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TargetID string `json:"targetId"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	cfg := loadNodePushCfg()
	var t *pushTarget
	for i := range cfg.Targets {
		if cfg.Targets[i].ID == in.TargetID {
			t = &cfg.Targets[i]
			break
		}
	}
	if t == nil {
		server.FailNotFound(w, "目标不存在: "+in.TargetID)
		return
	}
	if !t.Enabled {
		server.Fail(w, http.StatusConflict, server.CodeConflict, "目标已停用, 请先启用再测试")
		return
	}
	// 测试告警不落告警表(那是真实告警台账), 只写推送日志(alertId 空 = 无主记录,
	// 前端"关联告警"列显示"-")—— 测试推送也是推送动作, 应可在推送日志中追溯
	a := &db.NodeAlert{
		ID:      "test-" + randHex(3),
		Device:  "推送测试",
		Level:   "info",
		Content: "这是 Yugsight 节点监控的测试推送消息, 收到即表示 Webhook 配置正确, 请忽略。",
		At:      time.Now(),
	}
	reason := sendToTarget(*t, a)
	status := logSuccess
	if reason != "" {
		status = logFailed
	}
	writePushLog("", a, t.Name, status, reason)
	server.OK(w, map[string]any{
		"success": reason == "",
		"message": reason,
	})
}

// ---- 推送日志(分页 + 时间/状态/级别/目标 筛选) ----

func hPushLogs(w http.ResponseWriter, r *http.Request) {
	d := v2DB()
	if d == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "数据库不可用")
		return
	}
	dao := d.PushLogs()
	if dao == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "推送日志表不可用")
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(q.Get("size"))
	if size <= 0 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	start, _ := time.Parse(time.RFC3339, q.Get("start"))
	hasStart := q.Get("start") != ""
	end, _ := time.Parse(time.RFC3339, q.Get("end"))
	hasEnd := q.Get("end") != ""
	status := strings.TrimSpace(q.Get("status"))
	level := strings.TrimSpace(q.Get("level"))
	target := strings.TrimSpace(q.Get("target"))

	rows, err := dao.List()
	if err != nil {
		server.FailInternal(w, "查询失败: "+err.Error())
		return
	}
	// 新在前(存储序=入库序=时间升序)
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	// 2026-10-02 用户口径: 筛选选项基于当前数据里实际存在的 —— 回带推送日志
	// 全量里真实存在的状态/级别/目标(无数据的选项不出现, 后期有了再出现)。
	// 聚合按未过滤全量(不随筛选条件收缩, 选项是"数据里有什么"不是"当前筛选出了什么")
	stFacet := map[string]int{}
	lvFacet := map[string]int{}
	tgFacet := map[string]int{}
	for _, l := range rows {
		if l == nil {
			continue
		}
		stFacet[l.Status]++
		if l.Level != "" {
			lvFacet[l.Level]++
		}
		if l.Target != "" {
			tgFacet[l.Target]++
		}
	}
	statusFacet := make([]map[string]any, 0)
	for _, st := range []string{"success", "failed", "skipped"} {
		if stFacet[st] > 0 {
			statusFacet = append(statusFacet, map[string]any{"id": st, "count": stFacet[st]})
		}
	}
	levelFacet := make([]map[string]any, 0)
	for _, lv := range []string{"critical", "warning", "info"} {
		if lvFacet[lv] > 0 {
			levelFacet = append(levelFacet, map[string]any{"id": lv, "count": lvFacet[lv]})
		}
	}
	targetFacet := make([]string, 0, len(tgFacet))
	for tg := range tgFacet {
		targetFacet = append(targetFacet, tg)
	}
	sort.Strings(targetFacet)

	out := make([]*db.PushLog, 0, len(rows))
	for _, l := range rows {
		if hasStart && !l.At.After(start) {
			continue
		}
		if hasEnd && l.At.After(end) {
			continue
		}
		if status != "" && l.Status != status {
			continue
		}
		if level != "" && l.Level != level {
			continue
		}
		if target != "" && l.Target != target {
			continue
		}
		out = append(out, l)
	}
	total := len(out)
	from := (page - 1) * size
	if from >= total {
		out = out[:0]
	} else {
		to := from + size
		if to > total {
			to = total
		}
		out = out[from:to]
	}
	server.OK(w, map[string]any{"list": out, "total": total, "page": page, "size": size,
		"statuses": statusFacet, "levels": levelFacet, "targets": targetFacet})
}

// ---- 告警记录(列表 + 处理标记) ----

func hPushAlerts(w http.ResponseWriter, r *http.Request) {
	d := v2DB()
	if d == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "数据库不可用")
		return
	}
	dao := d.NodeAlerts()
	if dao == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "告警表不可用")
		return
	}
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := dao.TailNewest(limit)
	if err != nil {
		server.FailInternal(w, "查询失败: "+err.Error())
		return
	}
	total, _ := dao.Count()
	server.OK(w, map[string]any{"list": rows, "total": total})
}

// ---- 手动重推(前端对推送失败的告警触发) ----

func hPushRetry(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AlertID string `json:"alertId"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	id := strings.TrimSpace(in.AlertID)
	if id == "" {
		server.FailBadRequest(w, "alertId 必填")
		return
	}
	d := v2DB()
	if d == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "数据库不可用")
		return
	}
	dao := d.NodeAlerts()
	if dao == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "告警表不可用")
		return
	}
	a, err := dao.Get(id)
	if err != nil {
		server.FailNotFound(w, "告警不存在(可能已被裁剪): "+id)
		return
	}
	cfg := loadNodePushCfg()
	if !pushMasterOn(cfg) {
		server.Fail(w, http.StatusConflict, server.CodeConflict, "告警推送总开关已关闭, 请先开启再重推")
		return
	}
	if len(ruleTargets(cfg, cfg.Rules)) == 0 {
		server.Fail(w, http.StatusConflict, server.CodeConflict,
			"当前规则未关联可用推送目标, 请先在「推送配置」中添加并关联目标")
		return
	}
	doPushAlert(id)
	// 回读终态(推送同步执行, 此时状态已定)
	if a2, err2 := dao.Get(id); err2 == nil {
		server.OK(w, map[string]any{"alertId": id, "status": a2.PushStatus})
	} else {
		server.OK(w, map[string]any{"alertId": id, "status": alertFailed})
	}
	logAudit(v2DB(), r, "nodepush.retry", id, "status="+a.PushStatus)
}

// ---- 告警处理标记(确认/忽略, 撤销 = 空串) ----

func hPushAlertHandled(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Handled string `json:"handled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	h := strings.TrimSpace(in.Handled)
	if h != "" && h != "confirmed" && h != "ignored" {
		server.FailBadRequest(w, "handled 必须是 空 / confirmed / ignored")
		return
	}
	d := v2DB()
	if d == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "数据库不可用")
		return
	}
	dao := d.NodeAlerts()
	if dao == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "告警表不可用")
		return
	}
	a, err := dao.Get(id)
	if err != nil {
		server.FailNotFound(w, "告警不存在: "+id)
		return
	}
	a.Handled = h
	if err := dao.Update(a); err != nil {
		server.FailInternal(w, "保存失败: "+err.Error())
		return
	}
	server.OK(w, map[string]any{"id": id, "handled": h})
}

// Package models Yugsight 全局统一数据模型（第一阶段：核心数据模型与归一化层）。
//
// 提供跨来源、跨引擎的标准 Asset(资产) 与 Vuln(漏洞) 结构体，
// 作为归一化层(normalizer)、Web API、报告模块、大屏查询的唯一数据契约。
//
// 本包仅依赖 Go 标准库，可独立工作，不依赖外部引擎(bin)与探针节点。
package models

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"time"
)

// Asset 统一资产模型（主机维度：一台主机一条记录）。
//
// 字段与规范对齐：IP / MAC / 主机名 / 操作系统 / 端口列表 /
// 服务名称 / 版本 / Banner / 探针节点 ID / 探测时间 / 资产标签。
// Service / Version / Banner 指主机主服务（首个开放端口），完整端口列表见 Ports。
type Asset struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	MAC       string    `json:"mac,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	OS        string    `json:"os,omitempty"`
	Ports     []int     `json:"ports,omitempty"`
	Service   string    `json:"service,omitempty"`
	Version   string    `json:"version,omitempty"`
	Banner    string    `json:"banner,omitempty"`
	ProbeNode string    `json:"probeNode,omitempty"`
	FoundAt   time.Time `json:"foundAt"`
	Tags      []string  `json:"tags,omitempty"`
	// Alive 存活态: 最近一轮探测该主机是否有响应。
	//
	// 这里刻意不新增"在线/离线"枚举: 资产表的语义是"发现过的资产"而非"实时在线表",
	// 存活与否是"最近一次探测结论", 布尔值足够表达且不引入状态机(状态机会让
	// "从未探测过"与"探测失败"难以区分)。大屏的资产总量/存活资产即由此区分。
	// 零值 false = 未探测 / 未响应, 与 db 弱类型字段一致, 不影响既有数据反序列化
	// (老记录缺该字段即为 false)。
	Alive bool `json:"alive,omitempty"`
}

// NewAsset 构造统一资产（自动归一化 IP 并计算稳定 ID）。
func NewAsset(ip string) *Asset {
	a := &Asset{IP: NormIP(ip), FoundAt: time.Now()}
	a.ID = a.StableID()
	return a
}

// StableID 稳定资产 ID：归一化 IP 的 SHA1 前 16 位，
// 跨扫描不变，可作数据库主键 / 关联键。
func (a *Asset) StableID() string {
	sum := sha1.Sum([]byte(a.Key()))
	return hex.EncodeToString(sum[:])[:16]
}

// Key 资产归一化键：归一化后的 IP。
func (a *Asset) Key() string {
	return NormIP(a.IP)
}

// NormIP 归一化 IP / 主机标识：去首尾空白 + 转小写（统一各来源口径）。
func NormIP(ip string) string {
	return strings.ToLower(strings.TrimSpace(ip))
}

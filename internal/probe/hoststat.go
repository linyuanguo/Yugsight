package probe

// hoststat.go 阶段 4 中心端运行状态: 轻量主机负载采集入口。
//
// 与 CollectNodeInfo 复用同一套平台采集实现(memStatsOS 等), 但这里单独开
// 轻量接口供"高频轮询"场景使用(首页仪表盘 5 秒一次): CollectNodeInfo 会连带
// 触发外部引擎版本探测(每个引擎一次 --version 子进程, 单项 5 秒超时), 每秒
// 级调用会拉起一批子进程; 而内存/磁盘/网卡信息是纯系统调用, 代价可忽略。
//
// 全部"尽力而为"语义: 任一子项采集失败只返回 ok=false, 不返回错误、不中断
// 调用方 —— 面板是常驻展示, 单项数据源挂了不应让整条请求失败(项目规则 4)。

// MemStats 系统物理内存总量/已用(字节)。
func MemStats() (total, used uint64, ok bool) { return memStatsOS() }

// DiskStats 返回 path 所在分区的总容量与用户可用空间(字节)。
//
// 为什么不直接用 diskStatsOS: 它固定读 C 盘, 而中心端数据(data/ logs/ bin/)
// 在 exe 同目录 —— 运维最关心的是数据所在盘还剩多少, 而非系统盘。
// 平台实现见 hoststat_windows.go / hoststat_other.go, 失败回退到默认盘。
func DiskStats(path string) (total, free uint64, ok bool) {
	return diskStatsFor(path)
}

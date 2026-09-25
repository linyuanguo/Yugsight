package weakpass

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ===== 测试脚手架 =====

// testRate 用例里用的"事实上不限速"的速率。
//
// 注意 Config.Rate=0 会被 withDefaults 补成 DefaultRate(1/s), 用例就会真的等上
// 1 秒 —— 那是生产语义, 不该让单测付出真实时钟代价。要"不限速"就写大速率。
const testRate = 1000

// pipeDialer 用 net.Pipe 造一个"替身服务"的建连器: 每次建连都新建一对管道,
// 服务端逻辑跑在独立 goroutine。
//
// 为什么不用真实 listener: 项目运行环境会拦回环连接, 真实 listener 用例会变成
// 环境性失败; net.Pipe 完全在内存里, 不受网络策略影响(项目规则 12)。
func pipeDialer(t *testing.T, srv func(conn net.Conn)) Dialer {
	t.Helper()
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		client, server := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			srv(server)
		}()
		t.Cleanup(func() {
			client.Close()
			<-done
		})
		return client, nil
	}
}

func newTestEngine(cfg Config, d Dialer) *Engine {
	e := New(cfg)
	e.SetDialer(d)
	return e
}

// ===== 默认关闭: 零连接 =====

// TestDisabledMakesNoConnection 守"默认关闭零影响"这条硬约束。
//
// 判据不是"返回了错误", 而是**建连器一次都没被调用** —— 只断言前者的话,
// 一个"先连上再判断开关"的实现也能通过, 那就不是零影响了。
func TestDisabledMakesNoConnection(t *testing.T) {
	calls := 0
	e := New(Config{}) // 零值 = 关闭
	e.SetDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls++
		return nil, &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}
	})
	res := e.Check(context.Background(), Target{Host: "192.168.1.10", Port: 6379, Service: "redis"})
	if calls != 0 {
		t.Fatalf("未启用时不得发起任何连接, 实际拨号 %d 次", calls)
	}
	if res.Stopped != "disabled" || res.OK {
		t.Fatalf("期望 disabled 且未命中, 实际 stopped=%s ok=%v", res.Stopped, res.OK)
	}
	if e.AuditCount() != 0 {
		t.Fatalf("未启用时不应产生审计记录, 实际 %d 条", e.AuditCount())
	}
}

// ===== 白名单 =====

func TestWhitelist(t *testing.T) {
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24", "10.0.0.5"}},
		pipeDialer(t, func(net.Conn) {}))

	// 白名单内: 允许(这里只验放行判定, 不关心协议结果)
	if !e.Allowed("192.168.1.10") {
		t.Fatal("192.168.1.10 应放行")
	}
	if !e.Allowed("10.0.0.5") { // 单 IP 写法
		t.Fatal("10.0.0.5 应放行")
	}
	if e.Allowed("10.0.0.6") {
		t.Fatal("10.0.0.6 不在白名单, 应拒绝")
	}

	// 白名单外: 直接拒绝且不建连
	calls := 0
	e.SetDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls++
		return nil, os.ErrDeadlineExceeded
	})
	res := e.Check(context.Background(), Target{Host: "172.16.0.9", Port: 6379, Service: "redis"})
	if calls != 0 {
		t.Fatalf("白名单外不得发起连接, 实际 %d 次", calls)
	}
	if res.Stopped != "not-allowed" {
		t.Fatalf("期望 not-allowed, 实际 %s", res.Stopped)
	}
}

// TestEmptyWhitelistDeniesAll 白名单为空必须拒绝一切(fail-closed)。
func TestEmptyWhitelistDeniesAll(t *testing.T) {
	e := newTestEngine(Config{Enabled: true}, pipeDialer(t, func(net.Conn) {}))
	if e.Allowed("127.0.0.1") {
		t.Fatal("白名单为空时不得放行任何目标")
	}
	res := e.Check(context.Background(), Target{Host: "127.0.0.1", Port: 6379, Service: "redis"})
	if res.Stopped != "not-allowed" {
		t.Fatalf("期望 not-allowed, 实际 %s", res.Stopped)
	}
}

// ===== 不支持的协议: 明确报, 不伪造 =====

// TestUnsupportedProtocolIsExplicit 守住契约: 不在注册表里的协议必须显式标记
// unsupported 且给出点名协议的错误说明 —— 绝不能静默当成"检测通过"。
//
// 用 UnsupportedProtocols() 而不是写死协议名: 该函数与注册表是同一份事实来源,
// 日后补齐某个协议时只需改注册表, 本用例自动跟随(反之, 若有人把已实现的协议
// 留在 UnsupportedProtocols() 里, 用例会因它其实能跑而失败)。
func TestUnsupportedProtocolIsExplicit(t *testing.T) {
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}},
		pipeDialer(t, func(net.Conn) {}))
	for _, svc := range UnsupportedProtocols() {
		res := e.Check(context.Background(), Target{Host: "192.168.1.10", Port: 1433, Service: svc})
		if !res.Unsupported {
			t.Fatalf("%s 应标记为不支持", svc)
		}
		if res.Stopped != "unsupported" || res.OK {
			t.Fatalf("%s 期望 unsupported 且不命中, 实际 stopped=%s ok=%v", svc, res.Stopped, res.OK)
		}
		if !strings.Contains(res.Error, svc) {
			t.Fatalf("%s 的错误说明应点名协议, 实际: %s", svc, res.Error)
		}
	}
}

// TestRegistryAndUnsupportedAreDisjoint 注册表与"不支持列表"不能有交集:
// 同一协议同时出现在两边, 会让人无法判断到底支持不支持(状态接口会把两个列表
// 都返给前端, 前端也会同时展示)。
func TestRegistryAndUnsupportedAreDisjoint(t *testing.T) {
	unsupported := make(map[string]bool)
	for _, s := range UnsupportedProtocols() {
		unsupported[s] = true
	}
	for _, s := range Supported() {
		if unsupported[s] {
			t.Fatalf("协议 %s 同时出现在已支持与不支持列表中", s)
		}
	}
	if len(Supported()) == 0 {
		t.Fatal("已支持协议列表为空")
	}
}

// ===== 限速与上限 =====

// TestBucketRateLimit 令牌桶: 同一时刻第二次尝试必须被挡住并给出等待时长。
func TestBucketRateLimit(t *testing.T) {
	fixed := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	b := &bucket{last: fixed, tokens: 1}
	if wait, reason := b.take(fixed, 1, 100); reason != "" {
		t.Fatalf("首个令牌应放行, 实际 wait=%v reason=%s", wait, reason)
	}
	wait, reason := b.take(fixed, 1, 100)
	if reason != "rate" {
		t.Fatalf("同一时刻第二次尝试应限速, 实际 reason=%s", reason)
	}
	if wait != time.Second {
		t.Fatalf("速率 1/s 时等待应为 1s, 实际 %v", wait)
	}
	// 等满一个周期后应恢复
	if _, reason := b.take(fixed.Add(time.Second), 1, 100); reason != "" {
		t.Fatalf("等待 1s 后应放行, 实际 reason=%s", reason)
	}
}

func TestBucketMaxTry(t *testing.T) {
	fixed := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	b := &bucket{last: fixed, tokens: 1}
	for i := 0; i < 3; i++ {
		if _, reason := b.take(fixed.Add(time.Duration(i)*time.Second), 1, 3); reason != "" {
			t.Fatalf("第 %d 次应放行, 实际 %s", i+1, reason)
		}
	}
	if _, reason := b.take(fixed.Add(3*time.Second), 1, 3); reason != "maxtry" {
		t.Fatalf("超过上限应报 maxtry, 实际 %s", reason)
	}
}

// TestMaxTryStopsCheck 守"每目标尝试上限"在真实检测流程里生效(不限速, 保证确定性)。
func TestMaxTryStopsCheck(t *testing.T) {
	tried := 0
	e := newTestEngine(Config{
		Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate, MaxTry: 3, TimeoutMs: 500,
	}, pipeDialer(t, func(c net.Conn) {
		tried++
		// 替身: 一律拒绝认证
		buf := make([]byte, 256)
		c.Read(buf)
		c.Write([]byte("-ERR invalid password\r\n"))
	}))
	res := e.Check(context.Background(), Target{Host: "192.168.1.10", Port: 6379, Service: "redis"})
	if res.Stopped != "maxtry" {
		t.Fatalf("期望 maxtry, 实际 %s (%s)", res.Stopped, res.Error)
	}
	if res.Attempts != 3 || tried != 3 {
		t.Fatalf("尝试次数应为 3, 实际 attempts=%d dial=%d", res.Attempts, tried)
	}
	if e.AuditCount() != 3 {
		t.Fatalf("每次尝试都应留审计, 实际 %d 条", e.AuditCount())
	}
}

// TestRateLimitIsPerTarget 限速按 host:port 独立计数, 不同服务不互相挤占额度。
func TestRateLimitIsPerTarget(t *testing.T) {
	fixed := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: 1, MaxTry: 10}, nil)
	e.SetNow(func() time.Time { return fixed })
	if _, reason := e.take("192.168.1.10:6379"); reason != "" {
		t.Fatalf("A 首次应放行, 实际 %s", reason)
	}
	if _, reason := e.take("192.168.1.10:3306"); reason != "" {
		t.Fatalf("B(不同端口)首适应放行, 实际 %s", reason)
	}
}

// ===== 协议: Redis =====

func TestRedisUnauthorized(t *testing.T) {
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate, TimeoutMs: 500},
		pipeDialer(t, func(c net.Conn) {
			buf := make([]byte, 256)
			for {
				n, err := c.Read(buf)
				if n == 0 || err != nil {
					return
				}
				if strings.HasPrefix(string(buf[:n]), "PING") {
					c.Write([]byte("+PONG\r\n"))
					continue
				}
				c.Write([]byte("-ERR Client sent AUTH, but no password is set\r\n"))
			}
		}))
	res := e.CheckWith(context.Background(),
		Target{Host: "192.168.1.10", Port: 6379, Service: "redis"},
		Options{Dict: []string{"wrongpass"}})
	if !res.OK || !res.EmptyPass {
		t.Fatalf("PING 即通过应判为免认证命中, 实际 ok=%v empty=%v", res.OK, res.EmptyPass)
	}
	if res.Stopped != "found" {
		t.Fatalf("期望 found, 实际 %s", res.Stopped)
	}
}

func TestRedisWeakPassword(t *testing.T) {
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate, TimeoutMs: 500},
		pipeDialer(t, func(c net.Conn) {
			buf := make([]byte, 256)
			for {
				n, err := c.Read(buf)
				if n == 0 || err != nil {
					return
				}
				cmd := strings.TrimSpace(string(buf[:n]))
				if cmd == "PING" {
					c.Write([]byte("-NOAUTH Authentication required.\r\n"))
					continue
				}
				if cmd == "AUTH 123456" {
					c.Write([]byte("+OK\r\n"))
					continue
				}
				c.Write([]byte("-WRONGPASS invalid username-password pair\r\n"))
			}
		}))
	res := e.CheckWith(context.Background(),
		Target{Host: "192.168.1.10", Port: 6379, Service: "redis"},
		Options{Dict: []string{"admin", "123456", "root"}})
	if !res.OK || res.Password != "123456" {
		t.Fatalf("应命中 123456, 实际 ok=%v pass=%q", res.OK, res.Password)
	}
	if res.EmptyPass {
		t.Fatal("命中非空口令时 EmptyPass 应为 false")
	}
	// 命中即停: 空口令 + admin 未中, 第 3 次命中 123456
	if res.Attempts != 3 {
		t.Fatalf("命中即停, 尝试次数应为 3, 实际 %d", res.Attempts)
	}
}

// ===== 协议: MySQL =====

// mysqlHandshake 构造一个可用的 Initial Handshake 包(测试替身用)。
func mysqlHandshake(nonce string) []byte {
	p := []byte{10}
	p = append(p, []byte("5.7.44-log")...)
	p = append(p, 0)
	var id [4]byte
	binary.LittleEndian.PutUint32(id[:], 1)
	p = append(p, id[:]...)
	p = append(p, []byte(nonce[:8])...)
	p = append(p, 0) // filler
	var caps [2]byte
	binary.LittleEndian.PutUint16(caps[:], uint16(mysqlCapSecureConn|mysqlCapProtocol41))
	p = append(p, caps[:]...)
	p = append(p, 33) // charset
	p = append(p, 0, 0)
	// 能力位高 16 位: 声明 PLUGIN_AUTH
	var capsHi [2]byte
	binary.LittleEndian.PutUint16(capsHi[:], uint16(mysqlCapPluginAuth>>16))
	p = append(p, capsHi[:]...)
	p = append(p, 21) // auth_plugin_data_len = 8 + 13
	p = append(p, make([]byte, 10)...)
	p = append(p, []byte(nonce[8:20])...)
	p = append(p, []byte("mysql_native_password")...)
	p = append(p, 0)
	return p
}

func TestMySQLWeakPassword(t *testing.T) {
	const nonce = "0123456789abcdefghij"
	// 期望的 20 字节认证串(与 mysqlScramble 同算法, 独立实现一遍做交叉校验)
	want := func(pass string) string {
		h1 := sha1.Sum([]byte(pass))
		h2 := sha1.Sum(h1[:])
		h := sha1.New()
		h.Write([]byte(nonce))
		h.Write(h2[:])
		h3 := h.Sum(nil)
		out := make([]byte, 20)
		for i := range out {
			out[i] = h1[i] ^ h3[i]
		}
		return string(out)
	}
	weak := "123456"

	gotUser := ""
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate, TimeoutMs: 500},
		pipeDialer(t, func(c net.Conn) {
			if err := writeMySQLPacket(c, mysqlHandshake(nonce), 0); err != nil {
				return
			}
			resp, err := readMySQLPacket(c)
			if err != nil {
				return
			}
			// 从 Handshake Response 41 里取用户名与认证串
			rest := resp[32:]
			i := indexZero(rest)
			if i < 0 {
				return
			}
			gotUser = string(rest[:i])
			rest = rest[i+1:]
			if len(rest) == 0 {
				return
			}
			authLen := int(rest[0])
			auth := rest[1 : 1+authLen]
			if authLen == 0 {
				// 空口令一律拒绝(该账号确实有口令)
				_ = writeMySQLPacket(c, []byte{0xFF, 0x15, 0x04, '#', '2', '8', '0', '0', '0', 'A', 'c', 'c', 'e', 's', 's', ' ', 'd', 'e', 'n', 'i', 'e', 'd'}, 2)
				return
			}
			if string(auth) == want(weak) {
				_ = writeMySQLPacket(c, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, 2)
				return
			}
			_ = writeMySQLPacket(c, []byte{0xFF, 0x15, 0x04, '#', '2', '8', '0', '0', '0', 'A', 'c', 'c', 'e', 's', 's', ' ', 'd', 'e', 'n', 'i', 'e', 'd'}, 2)
		}))
	res := e.CheckWith(context.Background(),
		Target{Host: "192.168.1.10", Port: 3306, Service: "mysql", User: "root"},
		Options{Dict: []string{"root", weak}})
	if gotUser != "root" {
		t.Fatalf("握手应带上用户名 root, 实际 %q", gotUser)
	}
	if !res.OK || res.Password != weak {
		t.Fatalf("应命中 %s, 实际 ok=%v pass=%q (%s)", weak, res.OK, res.Password, res.Error)
	}
}

// TestMySQLCachingSHA2Explicit 服务端要求别的认证插件时必须明确报错, 不能回 false。
func TestMySQLCachingSHA2Explicit(t *testing.T) {
	const nonce = "0123456789abcdefghij"
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate, TimeoutMs: 500},
		pipeDialer(t, func(c net.Conn) {
			if err := writeMySQLPacket(c, mysqlHandshake(nonce), 0); err != nil {
				return
			}
			if _, err := readMySQLPacket(c); err != nil {
				return
			}
			p := append([]byte{0xFE}, []byte("caching_sha2_password")...)
			_ = writeMySQLPacket(c, append(p, 0), 2)
		}))
	res := e.CheckWith(context.Background(),
		Target{Host: "192.168.1.10", Port: 3306, Service: "mysql", User: "root"},
		Options{Dict: []string{"123456"}})
	if res.OK {
		t.Fatal("要求其它认证插件时不得判为命中")
	}
	if !strings.Contains(res.Error, "caching_sha2_password") {
		t.Fatalf("错误说明应点名插件, 实际: %s", res.Error)
	}
}

// ===== 协议: Telnet =====

func TestTelnetLoginSuccess(t *testing.T) {
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate, TimeoutMs: 800},
		pipeDialer(t, func(c net.Conn) {
			c.Write([]byte("Welcome\r\nlogin: "))
			buf := make([]byte, 256)
			c.Read(buf)
			c.Write([]byte("Password: "))
			n, _ := c.Read(buf)
			if strings.TrimSpace(string(buf[:n])) == "toor" {
				c.Write([]byte("\r\nLast login: Mon\r\n[root@host ~]# "))
				return
			}
			c.Write([]byte("\r\nLogin incorrect\r\nlogin: "))
		}))
	res := e.CheckWith(context.Background(),
		Target{Host: "192.168.1.10", Port: 23, Service: "telnet", User: "root"},
		Options{Dict: []string{"wrong", "toor"}, EmptyPass: boolPtr(false)})
	if !res.OK || res.Password != "toor" {
		t.Fatalf("应命中 toor, 实际 ok=%v pass=%q (%s)", res.OK, res.Password, res.Error)
	}
}

func TestTelnetLoginFailure(t *testing.T) {
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate, TimeoutMs: 800},
		pipeDialer(t, func(c net.Conn) {
			c.Write([]byte("login: "))
			buf := make([]byte, 256)
			c.Read(buf)
			c.Write([]byte("Password: "))
			c.Read(buf)
			c.Write([]byte("\r\nLogin incorrect\r\nlogin: "))
		}))
	res := e.CheckWith(context.Background(),
		Target{Host: "192.168.1.10", Port: 23, Service: "telnet", User: "root"},
		Options{Dict: []string{"toor"}, EmptyPass: boolPtr(false)})
	if res.OK {
		t.Fatal("登录失败不得判为命中")
	}
	if res.Stopped != "done" {
		t.Fatalf("期望 done, 实际 %s", res.Stopped)
	}
}

// TestTelnetNoAuthPrompt 连上直接给 shell = 免认证。
func TestTelnetNoAuthPrompt(t *testing.T) {
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate, TimeoutMs: 800},
		pipeDialer(t, func(c net.Conn) {
			c.Write([]byte("BusyBox v1.30\r\n~ # "))
		}))
	res := e.CheckWith(context.Background(),
		Target{Host: "192.168.1.10", Port: 23, Service: "telnet", User: "root"},
		Options{Dict: []string{"toor"}})
	if !res.OK || !res.EmptyPass {
		t.Fatalf("直给 shell 应判免认证, 实际 ok=%v empty=%v", res.OK, res.EmptyPass)
	}
}

// ===== 协议: FTP =====

func TestFTP(t *testing.T) {
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate, TimeoutMs: 500},
		pipeDialer(t, func(c net.Conn) {
			c.Write([]byte("220 FTP ready\r\n"))
			buf := make([]byte, 256)
			c.Read(buf)
			c.Write([]byte("331 Password required\r\n"))
			c.Read(buf)
			c.Write([]byte("230 Login successful\r\n"))
		}))
	res := e.CheckWith(context.Background(),
		Target{Host: "192.168.1.10", Port: 21, Service: "ftp", User: "ftp"},
		Options{Dict: []string{"anything"}, EmptyPass: boolPtr(false)})
	if !res.OK {
		t.Fatalf("230 应判登录成功, 实际 %s", res.Error)
	}
}

// ===== 字典 =====

func TestBuiltinDict(t *testing.T) {
	if err := BuiltinLoadErr(); err != nil {
		t.Fatalf("内置字典读取失败: %v", err)
	}
	d := BuiltinDict()
	if len(d) < 100 {
		t.Fatalf("内置字典应至少 100 条, 实际 %d", len(d))
	}
	seen := map[string]bool{}
	for _, p := range d {
		if seen[p] {
			t.Fatalf("字典存在重复项: %q", p)
		}
		seen[p] = true
	}
	if !seen["123456"] || !seen["admin"] {
		t.Fatal("字典缺少最常见的口令样本")
	}
}

func TestUserDictFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dict.txt")
	if err := os.WriteFile(path, []byte("# 注释行\r\nfromfile\r\n123456\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(Config{Enabled: true, DictFile: path, Rate: testRate}, nil)
	dict := e.loadDict()
	has := map[string]bool{}
	for _, p := range dict {
		has[p] = true
	}
	if !has["fromfile"] {
		t.Fatal("用户字典条目未合并")
	}
	if !has["123456"] {
		t.Fatal("内置字典条目丢失")
	}
	// 去重: 123456 同时在内建与用户字典, 只应出现一次
	n := 0
	for _, p := range dict {
		if p == "123456" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("123456 应去重只保留一条, 实际 %d 条", n)
	}

	// 文件缺失: 降级为内置字典, 不报错
	e2 := newTestEngine(Config{Enabled: true, DictFile: filepath.Join(dir, "nope.txt"), Rate: testRate}, nil)
	if len(e2.loadDict()) < 100 {
		t.Fatal("用户字典缺失时应降级为内置字典")
	}
}

// ===== 审计 =====

// TestAuditNeverStoresFailedPassword 审计不得把失败尝试的明文口令写进记录。
func TestAuditNeverStoresFailedPassword(t *testing.T) {
	e := newTestEngine(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}, Rate: testRate, TimeoutMs: 500},
		pipeDialer(t, func(c net.Conn) {
			buf := make([]byte, 256)
			c.Read(buf)
			c.Write([]byte("-WRONGPASS\r\n"))
		}))
	_ = e.CheckWith(context.Background(),
		Target{Host: "192.168.1.10", Port: 6379, Service: "redis"},
		Options{Dict: []string{"secret1", "secret2"}})
	for _, a := range e.Audit(0) {
		if a.OK {
			t.Fatal("替身一律拒绝, 不应有命中记录")
		}
		if a.Password != "" {
			t.Fatalf("失败尝试不得记录明文口令, 实际记录了 %q", a.Password)
		}
		if a.Target != "192.168.1.10:6379" {
			t.Fatalf("审计目标口径应为 host:port, 实际 %q", a.Target)
		}
	}
}

func boolPtr(b bool) *bool { return &b }

// TestSetConfig 运行时整体替换配置: 白名单变更立即生效(Allowed 随之变化),
// 零值字段回落安全默认(Rate=0 不会把限速打开放宽 —— 那是 withDefaults 的
// 底线, 管理端误提交 0 不该变成"无限速爆破")。
func TestSetConfig(t *testing.T) {
	e := New(Config{Enabled: true, Targets: []string{"10.0.0.0/8"}})
	if !e.Allowed("10.1.2.3") || e.Allowed("192.168.1.5") {
		t.Fatal("初始白名单 10.0.0.0/8 判定错误")
	}

	// 换成 192.168.1.0/24: 旧目标失权, 新目标放行
	e.SetConfig(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}})
	if e.Allowed("10.1.2.3") {
		t.Fatal("白名单替换后, 旧目标不得继续放行")
	}
	if !e.Allowed("192.168.1.50") {
		t.Fatal("白名单替换后, 新目标应放行")
	}

	// 零值 Rate 回落 DefaultRate(而非 0 = 不限速)
	e.SetConfig(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}})
	if got := e.Config().Rate; got != DefaultRate {
		t.Fatalf("Rate=0 应回落默认 %v, 实际 %v(不限速=爆破, 不可接受)", DefaultRate, got)
	}
	if got := e.Config().MaxTry; got != DefaultMaxTry {
		t.Fatalf("MaxTry=0 应回落默认 %d, 实际 %d", DefaultMaxTry, got)
	}

	// 并发读写不竞争: 一个 goroutine 反复 SetConfig, 其它并发读 Config/Allowed
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			e.SetConfig(Config{Enabled: true, Targets: []string{"192.168.1.0/24"}})
		}
	}()
	for i := 0; i < 200; i++ {
		_ = e.Config()
		_ = e.Allowed("192.168.1.1")
	}
	<-done
}

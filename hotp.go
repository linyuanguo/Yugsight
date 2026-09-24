// hotp.go HOTP 动态验证码(时间片版, 语义等同 RFC 6238 TOTP)。
//
// ===== 需求口径 =====
//
//   - 种子密钥: base32(RFC 4648, 无填充), 20 字节熵生成, 登录后由管理员在
//     设置页手动生成, 存 db 用户表(绝不写进 settings.json —— 配置文件会被
//     手工编辑/备份流转, 种子属于高敏数据, 与账号口令分离存放)。
//   - 码长 6 位, 时间片 90 秒, 计数器 = Unix 秒 / 90。
//   - 校验容错 ±1 个时间片: 服务器与浏览器时钟可能有秒级~分钟级偏差,
//     也允许用户在倒计时末尾手动输入时恰好跨片。
//   - 全程纯本地计算(crypto/hmac + sha1), 不请求任何外部接口; 前端用同一
//     算法(纯 JS SHA-1, 见 frontend/src/utils/otp.js)自行计算同一码值。
//
// 命名说明: 需求称 HOTP 但按 60 秒时间片生成, 实为时间步进(HOTP 计数器
// 换成时间片), 与 Google Authenticator 等标准的 TOTP(30 秒/SHA1/6 位)仅
// 步长不同, 算法结构完全一致。
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"strings"
	"time"
)

const (
	hotpDigits    = 6               // 码长 6 位
	hotpWindow    = 1               // 校验容错 ±1 个时间片
	hotpSeedBytes = 20              // 种子熵 160 位(与业界 TOTP 惯例一致)
	hotpMod       = 1_000_000       // 10^6: 取模得到 6 位十进制
)

// hotpPeriod 时间片长度: 90 秒(需求口径, 非标准 TOTP 的 30 秒)。
const hotpPeriod = 90 * time.Second

// hotpCounterAt 把时刻换算成时间片计数器(Unix 秒 / 90)。
// 前端 JS 用 Math.floor(ms/1000/90) 得到同一值 —— 两端口径必须严格一致。
func hotpCounterAt(t time.Time) uint64 {
	if t.Unix() < 0 {
		return 0
	}
	return uint64(t.Unix()) / 90
}

// hotpSeedGenerate 生成新的 base32 种子密钥(32 字符, 无填充)。
// crypto/rand 失败时返回空串(调用方按失败处理, 不降级出弱种子)。
func hotpSeedGenerate() string {
	b := make([]byte, hotpSeedBytes)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// hotpNormalizeSeed 种子归一: 去空白、转大写、剥 base32 填充符 '='。
// 用户从备份恢复/手工粘贴时常见小写、空格、尾部等号 —— 归一后统一可解,
// 校验失败的具体原因只记日志不外抛(避免给攻击者反馈种子格式线索)。
func hotpNormalizeSeed(s string) string {
	var b strings.Builder
	for _, c := range strings.TrimSpace(s) {
		switch {
		case c == ' ' || c == '-' || c == '=':
			continue
		case c >= 'a' && c <= 'z':
			b.WriteRune(c - 32)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// hotpCode 按种子与计数器计算 6 位动态码(RFC 4226 动态截断)。
// 种子非法返回 ""(调用方视为不匹配)。
func hotpCode(seed string, counter uint64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(hotpNormalizeSeed(seed))
	if err != nil || len(key) == 0 {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	// 动态截断: 最后一字节低 4 位为偏移, 取偏移处 4 字节并抹掉最高位
	off := sum[len(sum)-1] & 0x0f
	v := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % hotpMod
	// 定宽 6 位, 不足补零(如 000123)
	code := []byte("000000")
	for i := hotpDigits - 1; i >= 0; i-- {
		code[i] = byte('0' + v%10)
		v /= 10
	}
	return string(code)
}

// hotpVerify 在 now 所在时间片 ±hotpWindow 范围内校验码值。
// 恒定时间比较(subtle): 逐片比对, 不因首片命中提前泄漏比较结果时序。
func hotpVerify(seed, code string, now time.Time) bool {
	seed = hotpNormalizeSeed(seed)
	code = strings.TrimSpace(code)
	if seed == "" || len(code) != hotpDigits {
		return false
	}
	cur := hotpCounterAt(now)
	for i := -int64(hotpWindow); i <= int64(hotpWindow); i++ {
		slot := uint64(int64(cur) + i) // cur>=1 时不会下溢; cur=0 且 i=-1 时 slot 回绕,
		// 回绕产生的码与真码不同的概率是 (10^6-1)/10^6, 且真码会随后续片命中 —— 可接受
		want := hotpCode(seed, slot)
		if want == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// hotpRemainSecAt 距当前时间片结束的剩余秒数(1..90), 前端倒计时同口径。
func hotpRemainSecAt(now time.Time) int {
	return 90 - int(now.Unix()%90)
}

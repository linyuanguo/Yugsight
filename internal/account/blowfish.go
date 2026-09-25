// Package account Yugsight 任务 5: RBAC 账号体系(账号管理 + 会话管理 + bcrypt 密码哈希)。
//
// 零依赖说明(对齐项目硬约束"纯 Go 标准库、零第三方依赖"):
// 任务要求 bcrypt 密码哈希存储, 而 golang.org/x/crypto 不属于 Go 标准库,
// 故本包自研 bcrypt(算法与 OpenBSD / x-crypto / bcryptjs 完全一致, 输出格式
// $2b$ 与主流 bcrypt 验证器兼容)。Blowfish 初始表(P0 18 字 / S0 4x256 字)为
// pi 十六进制展开的前 1042 个 32 位字, 用 math/big 精确有理数(Machin 公式)在
// 进程启动时计算一次并缓存, 不内嵌 4KB 常量表。
// 正确性经 node bcryptjs 参考向量交叉验证, 见 bcrypt_test.go。
//
// 本包仅依赖 Go 标准库与 yugsight/db(统一 DAO 接口)。
package account

import (
	"math/big"
	"sync"
)

// Blowfish 初始表: P0(18) / S0(4x256) = pi 十六进制展开前 1042 个 32 位字。
// sync.Once 缓存; 计算耗时毫秒级(一次性, 进程生命周期内)。
var (
	tableOnce sync.Once
	p0        [18]uint32
	s0        [4][256]uint32
)

// blowfishTables 计算并缓存初始表。
func blowfishTables() {
	tableOnce.Do(func() {
		words := piHexWords(1042)
		copy(p0[:], words[:18])
		for i := 0; i < 1024; i++ {
			s0[i/256][i%256] = words[18+i]
		}
	})
}

// piHexWords 返回 pi 十六进制**小数部分**展开的前 n 个 32 位字
// (大端, 第 0 字 = pi 小数点后前 8 个 hex 位; 每字 = 8 个十六进制位)。
//
// 口径提醒: Blowfish 初始表是 pi = 3.243f6a8885a308d3... 的**小数部分**
// (P0[0] = 0x243f6a88), 不含整数位 3 —— 曾误把整数位算进表导致整个表错位。
//
// 算法: 整型定点 Machin(不用 big.Rat):
//
//	pi = 16*atan(1/5) - 4*atan(1/239),  atan(1/x) = Σ (-1)^k/(x^(2k+1)(2k+1))
//
// 直接算 floor(16^g · (pi-1)) 的大整数(g = n+1, 多算一个**守卫字**):
// 每项 floor 截断误差 < 1(16^g 尺度), 交替级数总误差 < 16·(1+1/25+…) +
// 4·(1+1/239²+…) < 26, 远小于所需末字的 2^32 间距 —— 前 n 字逐位精确,
// 误差全部落在被丢弃的守卫字里。
//
// 为什么弃用 big.Rat 精确有理数: 级数分母不约分、按 O(k²) 位增长, karatsuba
// 大数乘法不收敛, 算 1042 字实测 >45s 超时; 整型定点是约 9000 次 ≤34k 位
// big.Int 除法, 百毫秒级(一次性, sync.Once 缓存)。
func piHexWords(n int) []uint32 {
	guard := n + 1
	N := new(big.Int).Lsh(big.NewInt(1), uint(32*guard)) // 16^guard
	a := machinAtaN(N, 5)
	b := machinAtaN(N, 239)
	piN := new(big.Int).Mul(a, big.NewInt(16)) // 16*atan(1/5) 的 16^g 定点
	piN.Sub(piN, new(big.Int).Mul(b, big.NewInt(4)))
	piN.Sub(piN, new(big.Int).Mul(N, big.NewInt(3))) // 去掉整数部分 3 (pi-1 = 0.243f6a88...)
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		w := new(big.Int).Rsh(piN, uint(32*(guard-1-i)))
		out[i] = uint32(w.Uint64())
	}
	return out
}

// machinAtaN 计算 Σ_{k>=0} (-1)^k · floor(N / (x^(2k+1)(2k+1)))。
//
// 终止: 项值归零(分母超过 N)。截断误差分析见 piHexWords 注释。
// 增量维护 D = x^(2k+1)(乘 x² 步进), 避免逐项大指数。
func machinAtaN(N *big.Int, x int64) *big.Int {
	x2 := new(big.Int).Mul(big.NewInt(x), big.NewInt(x))
	D := new(big.Int).SetInt64(x)
	sum := new(big.Int)
	for k := 0; ; k++ {
		den := new(big.Int).Mul(D, big.NewInt(int64(2*k+1)))
		term := new(big.Int).Quo(N, den)
		if term.Sign() == 0 {
			break
		}
		if k%2 == 0 {
			sum.Add(sum, term)
		} else {
			sum.Sub(sum, term)
		}
		D.Mul(D, x2)
	}
	return sum
}

// bfEnc 执行一次 Blowfish 块加密(16 轮 Feistel), 与参考实现逐位一致。
//
// 展开后等价于:
//
//	for i := 0; i < 16; i++ {
//		L ^= P[i]
//		R ^= bfF(S, L)
//		L, R = R, L
//	}
//	L, R = R, L
//	R ^= P[16]
//	L ^= P[17]
func bfEnc(P *[18]uint32, S *[4][256]uint32, L, R uint32) (uint32, uint32) {
	for i := 0; i < 16; i += 2 {
		L ^= P[i]
		R ^= bfF(S, L)
		R ^= P[i+1]
		L ^= bfF(S, R)
	}
	L, R = R, L
	R ^= P[16]
	L ^= P[17]
	return L, R
}

// bfF Blowfish F 函数: ((S0+S1)^S2)+S3 (模 2^32), 与参考实现逐位一致。
func bfF(S *[4][256]uint32, x uint32) uint32 {
	return ((S[0][x>>24] + S[1][(x>>16)&0xff]) ^ S[2][(x>>8)&0xff]) + S[3][x&0xff]
}

// rederive 以零块起 521 次块加密重导出 P/S(不折叠盐)。
func rederive(P *[18]uint32, S *[4][256]uint32) {
	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l, r = bfEnc(P, S, l, r)
		P[i], P[i+1] = l, r
	}
	for i := 0; i < 4; i++ {
		for k := 0; k < 256; k += 2 {
			l, r = bfEnc(P, S, l, r)
			S[i][k], S[i][k+1] = l, r
		}
	}
}

// bfExpandKey = x-crypto blowfish.ExpandKey: 密钥字节流(循环)仅异或进 P[0..17],
// 然后 521 次零块加密重导出 P/S。bcrypt 迭代轮次即用此函数。
func bfExpandKey(P *[18]uint32, S *[4][256]uint32, key []byte) {
	if len(key) == 0 {
		return
	}
	j := 0
	for i := 0; i < 18; i++ {
		var w uint32
		for k := 0; k < 4; k++ {
			w = w<<8 | uint32(key[(j+k)%len(key)])
		}
		j = (j + 4) % len(key)
		P[i] ^= w
	}
	rederive(P, S)
}

// bfSaltedSetup = x-crypto NewSaltedCipher 主体: 密钥仅异或进 P[0..17],
// 重导出时每次块加密前将盐(循环)异或进 (l,r) 寄存器(带盐折叠的密钥调度)。
func bfSaltedSetup(P *[18]uint32, S *[4][256]uint32, key, salt []byte) {
	if len(key) == 0 || len(salt) == 0 {
		bfExpandKey(P, S, key)
		return
	}
	j := 0
	for i := 0; i < 18; i++ {
		var w uint32
		for k := 0; k < 4; k++ {
			w = w<<8 | uint32(key[(j+k)%len(key)])
		}
		j = (j + 4) % len(key)
		P[i] ^= w
	}
	js := 0
	nextSalt := func() uint32 {
		var w uint32
		for k := 0; k < 4; k++ {
			w = w<<8 | uint32(salt[(js+k)%len(salt)])
		}
		js = (js + 4) % len(salt)
		return w
	}
	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l ^= nextSalt()
		r ^= nextSalt()
		l, r = bfEnc(P, S, l, r)
		P[i], P[i+1] = l, r
	}
	for i := 0; i < 4; i++ {
		for k := 0; k < 256; k += 2 {
			l ^= nextSalt()
			r ^= nextSalt()
			l, r = bfEnc(P, S, l, r)
			S[i][k], S[i][k+1] = l, r
		}
	}
}

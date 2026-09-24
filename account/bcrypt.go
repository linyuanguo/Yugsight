package account

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
)

// bcrypt 参数(与 OpenBSD / x-crypto / bcryptjs 对齐)。
const (
	MinCost      = 4
	MaxCost      = 31
	DefaultCost  = 10
	maxPassLen   = 72 // 密码截断长度(bcrypt 标准行为)
	saltLen      = 16 // 16 字节随机盐
	cryptedLen   = 23 // 24 字节密文取前 23 字节编码(C 实现 bug 兼容)
	hashTotalLen = 61 // 完整哈希串长度: $2b$CC$ + 22 + $ + 31
)

// b64 字母表(与 x-crypto 一致), RawStd = 无填充。
const b64Alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcB64 = base64.NewEncoding(b64Alphabet).WithPadding(base64.NoPadding)

// magicCipherData = "OrpheanBeholderScryDoubt"(24 字节, 与 C 实现一致)。
var magicCipherData = []byte("OrpheanBeholderScryDoubt")

var (
	ErrInvalidCost  = errors.New("bcrypt: cost 超出范围(4-31)")
	ErrInvalidHash  = errors.New("bcrypt: 哈希格式无效")
	ErrHashMismatch = errors.New("bcrypt: 密码不匹配")
)

// HashPassword 生成 bcrypt 哈希($2b$CC$<22位盐>$<31位摘要>)。
// 密码超长截断 72 字节; cost 非法返回 ErrInvalidCost。
func HashPassword(pass string, cost int) (string, error) {
	if cost < MinCost || cost > MaxCost {
		return "", ErrInvalidCost
	}
	key := []byte(pass)
	if len(key) > maxPassLen {
		key = key[:maxPassLen]
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("bcrypt: 随机盐生成失败: %w", err)
	}
	// 密钥尾部追加 NUL(C 实现 bug 兼容, x-crypto 同)
	key = append(key, 0)
	digest := bcryptCore(key, cost, salt)
	return fmt.Sprintf("$2b$%02d$%s$%s", cost, bcB64.EncodeToString(salt), bcB64.EncodeToString(digest)), nil
}

// CompareHashAndPassword 校验密码与哈希(常数时间比较, 防时序侧信道)。
// 兼容 $2a$ / $2b$ / $2y$ 前缀。
func CompareHashAndPassword(hash, pass string) error {
	p, err := parseHash(hash)
	if err != nil {
		return err
	}
	key := []byte(pass)
	if len(key) > maxPassLen {
		key = key[:maxPassLen]
	}
	key = append(key, 0)
	d := bcryptCore(key, p.cost, p.salt)
	if subtle.ConstantTimeCompare(d, p.digest) != 1 {
		return ErrHashMismatch
	}
	return nil
}

// CostOf 解析哈希中记录的 cost(校验失败返回 0 与错误)。
func CostOf(hash string) (int, error) {
	p, err := parseHash(hash)
	if err != nil {
		return 0, err
	}
	return p.cost, nil
}

type parsedHash struct {
	cost   int
	salt   []byte // 16 字节
	digest []byte // 23 字节
}

// parseHash 解析 $2b$CC$<22>$<31> 格式哈希。
func parseHash(s string) (*parsedHash, error) {
	if len(s) != hashTotalLen {
		return nil, ErrInvalidHash
	}
	if s[0] != '$' || s[1] != '2' || s[3] != '$' || s[6] != '$' || s[29] != '$' {
		return nil, ErrInvalidHash
	}
	minor := s[2]
	if minor != 'a' && minor != 'b' && minor != 'y' {
		return nil, ErrInvalidHash
	}
	cost, err := strconv.Atoi(s[4:6])
	if err != nil || cost < MinCost || cost > MaxCost {
		return nil, ErrInvalidHash
	}
	salt, err := bcB64.DecodeString(s[7:29])
	if err != nil || len(salt) != saltLen {
		return nil, ErrInvalidHash
	}
	digest, err := bcB64.DecodeString(s[30:61])
	if err != nil || len(digest) != cryptedLen {
		return nil, ErrInvalidHash
	}
	return &parsedHash{cost: cost, salt: salt, digest: digest}, nil
}

// bcryptCore bcrypt 核心计算, 返回 23 字节编码前密文。
//
// 算法(与 x-crypto blowfish.NewSaltedCipher + bcrypt.GenerateFromPassword 一致):
//  1. P,S = pi 初始表
//  2. NewSaltedCipher(密钥, 盐): 密钥异或进 P[0..17], 重导出时盐折叠进寄存器
//  3. 循环 2^cost 次: ExpandKey(密钥); ExpandKey(盐)
//  4. 对 "OrpheanBeholderScryDoubt" 三个 8 字节块各原地加密 64 轮
//  5. 取前 23 字节
func bcryptCore(key []byte, cost int, salt []byte) []byte {
	blowfishTables()
	P := p0
	S := s0

	bfSaltedSetup(&P, &S, key, salt)
	for i := 0; i < 1<<cost; i++ {
		bfExpandKey(&P, &S, key)
		bfExpandKey(&P, &S, salt)
	}

	data := make([]byte, 24)
	copy(data, magicCipherData)
	for i := 0; i < 24; i += 8 {
		L := uint32(data[i])<<24 | uint32(data[i+1])<<16 | uint32(data[i+2])<<8 | uint32(data[i+3])
		R := uint32(data[i+4])<<24 | uint32(data[i+5])<<16 | uint32(data[i+6])<<8 | uint32(data[i+7])
		for j := 0; j < 64; j++ {
			L, R = bfEnc(&P, &S, L, R)
		}
		data[i], data[i+1], data[i+2], data[i+3] = byte(L>>24), byte(L>>16), byte(L>>8), byte(L)
		data[i+4], data[i+5], data[i+6], data[i+7] = byte(R>>24), byte(R>>16), byte(R>>8), byte(R)
	}
	return data[:cryptedLen]
}

// secrets.go SNMP 口令的加密存储(二期): 密钥来自环境变量, 不落配置文件。
//
// ===== 为什么要加密 =====
//
// v3 的鉴权/加密口令与 v2c 社区串是"能读设备全部指标"的凭据, 而 settings.json
// 是会被备份/拷给同事/贴进工单的文件。明文存口令等于把凭据跟着配置文件一起
// 散步 —— 这是监控类工具最常见的泄漏路径。
//
// ===== 为什么密钥放环境变量而不是配置 =====
//
// 密钥写进配置文件就失去了意义(同文件里既有密文也有钥匙)。环境变量由部署方
// 在进程启动时注入(YUGSIGHT_MONITOR_KEY), 配置文件里永不出现。
//
// ===== 降级口径(项目规则 3/4) =====
//
// 环境变量未设置时不加密、不报错: 明文存并写一条告警日志。理由 —— 单管理员
// 内网工具的可用性优先; 且"没设密钥"是显式可见的状态(日志 + 状态接口回显),
// 强拒会让监控在一个很常见的部署形态下直接不可用。
package monitor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strings"
)

// SecretKeyEnv 口令加密密钥的环境变量名。
const SecretKeyEnv = "YUGSIGHT_MONITOR_KEY"

// encPrefix 密文标记(非该前缀的值一律按明文处理, 兼容历史配置)。
const encPrefix = "enc:"

// SecretKey 读取环境变量里的密钥; 未设置返回 nil(调用方据此降级为明文)。
func SecretKey() []byte {
	v := strings.TrimSpace(os.Getenv(SecretKeyEnv))
	if v == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(v))
	return sum[:] // AES-256
}

// EncryptSecret 加密口令; key 为空时原样返回明文(降级, 见文件头)。
func EncryptSecret(key []byte, plain string) string {
	if len(key) == 0 || plain == "" {
		return plain
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return plain
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plain
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return plain
	}
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ct)
}

// DecryptSecret 解密口令; 非密文或无密钥时原样返回(兼容明文历史配置)。
func DecryptSecret(key []byte, stored string) string {
	s := strings.TrimSpace(stored)
	if !strings.HasPrefix(s, encPrefix) {
		return s // 明文(未设密钥时写入的)
	}
	if len(key) == 0 {
		return "" // 有密文但没密钥: 不能解 —— 返回空并让采集报"口令缺失",
		// 也好过把 "enc:xxx" 当口令发给设备(那会得到一个永远的鉴权失败)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, encPrefix))
	if err != nil {
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	if len(raw) < gcm.NonceSize() {
		return ""
	}
	pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return ""
	}
	return string(pt)
}

// IsEncrypted 判断存储值是否为密文(状态接口回显用)。
func IsEncrypted(stored string) bool {
	return strings.HasPrefix(strings.TrimSpace(stored), encPrefix)
}

// ErrNoSecretKey 有密文口令但环境变量未提供密钥(采集前置检查用)。
var ErrNoSecretKey = errors.New("SNMP 口令已加密但环境变量 " + SecretKeyEnv + " 未提供密钥")

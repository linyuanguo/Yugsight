// otp.js HOTP 动态验证码(时间片版)前端同源实现 —— 与后端 hotp.go 算法严格一致。
//
// ===== 为什么不用 WebCrypto(crypto.subtle) =====
// 本应用常经 http://<局域网IP>:8420 访问, 属非安全上下文, crypto.subtle 为
// undefined; 必须自带纯 JS SHA-1/HMAC(约 60 行, 无第三方依赖), 否则局域网
// 场景下设置页与登录页双双失效。
//
// ===== 算法口径(与后端一致) =====
//   - 种子: base32(RFC 4648), 归一 = 去空白/横线/填充 + 转大写
//   - 计数器 = floor(Unix秒 / 90); HMAC-SHA1 → RFC 4226 动态截断 → % 1e6, 补零 6 位
//   - 倒计时 = 90 - Unix秒 % 90, 基于时间片计算, 刷新页面不重置
// 参考向量(RFC 4226, 种子=base32("12345678901234567890")):
//   counter=0 → 755224, counter=1 → 287082

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

// base32Decode 宽松解码; 非法字符返回 null(与后端归一口径一致)。
function base32Decode(s) {
  const clean = String(s || '').trim().toUpperCase().replace(/[\s\-=]/g, '')
  if (!clean) return null
  let bits = 0, val = 0
  const out = []
  for (const ch of clean) {
    const idx = B32.indexOf(ch)
    if (idx < 0) return null
    val = (val << 5) | idx
    bits += 5
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8 }
  }
  return out.length ? new Uint8Array(out) : null
}

// sha1 纯 JS SHA-1(输入/输出均为字节)。
export function sha1(msg) {
  const ml = msg.length
  const total = Math.ceil((ml + 9) / 64) * 64
  const buf = new Uint8Array(total)
  buf.set(msg)
  buf[ml] = 0x80
  const dv = new DataView(buf.buffer)
  // 64 位大端比特长度: 高 32 位 = ml/2^29, 低 32 位 = (ml*8) mod 2^32
  dv.setUint32(total - 8, Math.floor(ml / 0x20000000))
  dv.setUint32(total - 4, (ml << 3) >>> 0)
  let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0
  const w = new Uint32Array(80)
  for (let i = 0; i < total / 64; i++) {
    for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i * 64 + j * 4)
    for (let j = 16; j < 80; j++) {
      const n = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]
      w[j] = (n << 1) | (n >>> 31)
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4
    for (let j = 0; j < 80; j++) {
      let f, k
      if (j < 20) { f = (b & c) | (~b & d); k = 0x5A827999 }
      else if (j < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1 }
      else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC }
      else { f = b ^ c ^ d; k = 0xCA62C1D6 }
      const t = (((a << 5) | (a >>> 27)) + f + e + k + w[j]) >>> 0
      e = d; d = c; c = (b << 30) | (b >>> 2)
      b = a; a = t
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0
  }
  const out = new Uint8Array(20)
  const odv = new DataView(out.buffer)
  odv.setUint32(0, h0); odv.setUint32(4, h1); odv.setUint32(8, h2)
  odv.setUint32(12, h3); odv.setUint32(16, h4)
  return out
}

// hmacSha1 标准 HMAC(RFC 2104), 密钥超 64 字节先哈希。
export function hmacSha1(key, msg) {
  if (key.length > 64) key = sha1(key)
  const k = new Uint8Array(64)
  k.set(key)
  const ipad = new Uint8Array(64 + msg.length)
  const opad = new Uint8Array(64 + 20)
  for (let i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c }
  ipad.set(msg, 64)
  opad.set(sha1(ipad), 64)
  return sha1(opad)
}

// totpCode 当前时间片的 6 位动态码; 种子非法返回 ''。
export function totpCode(seed, nowMs = Date.now()) {
  const key = base32Decode(seed)
  if (!key) return ''
  const counter = Math.floor(nowMs / 1000 / 90)
  const msg = new Uint8Array(8)
  const hi = Math.floor(counter / 0x100000000)
  const lo = counter >>> 0
  msg[0] = (hi >>> 24) & 0xff; msg[1] = (hi >>> 16) & 0xff
  msg[2] = (hi >>> 8) & 0xff; msg[3] = hi & 0xff
  msg[4] = (lo >>> 24) & 0xff; msg[5] = (lo >>> 16) & 0xff
  msg[6] = (lo >>> 8) & 0xff; msg[7] = lo & 0xff
  const sum = hmacSha1(key, msg)
  const off = sum[19] & 0x0f
  const v = (((sum[off] & 0x7f) << 24) | (sum[off + 1] << 16) | (sum[off + 2] << 8) | sum[off + 3]) >>> 0
  return String(v % 1000000).padStart(6, '0')
}

// totpRemainSec 当前时间片剩余秒数(1..90), 与后端 hotpRemainSecAt 同口径。
export function totpRemainSec(nowMs = Date.now()) {
  return 90 - (Math.floor(nowMs / 1000) % 90)
}

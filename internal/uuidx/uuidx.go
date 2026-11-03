// Package uuidx — UUID v4/v5 生成与校验（对齐 Python uuid 模块中本服务用到的子集）。
//
// Python 源里散落使用 uuid.uuid4()（安装身份/追踪头/事件 id）、
// uuid.uuid5(uuid.NAMESPACE_URL, seed)（会话指纹 conversation_session_id）、
// uuid.UUID(value)（指纹 device_mid 合法性校验）。此处集中复刻，避免引入第三方依赖。
package uuidx

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

// NamespaceURL 对齐 Python uuid.NAMESPACE_URL（RFC 4122 附录 C 预置命名空间）。
var NamespaceURL = [16]byte{
	0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
}

// New4 生成随机 UUIDv4 字符串（uuid.uuid4() 等价：crypto/rand，版本位 4、变位 RFC）。
func New4() string {
	var b [16]byte
	_, err := rand.Read(b[:])
	if err != nil {
		// crypto/rand 失败属系统级故障；与 Python 原语一致直接 panic
		panic(fmt.Sprintf("uuidx: 读取系统随机源失败: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return format(b)
}

// New5 以 name + namespace 计算 SHA-1 UUIDv5（uuid.uuid5(ns, name) 等价）。
func New5(ns [16]byte, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return format(b)
}

// IsValid 校验字符串是否可被 uuid.UUID(...) 解析（Python uuid.UUID(value) 的
// 合法性门：8-4-4-4-12 十六进制，忽略大小写与首尾花括号——本服务只要求
// "必须是合法 UUID"，取宽松解析）。
func IsValid(s string) bool {
	_, err := Parse(s)
	return err == nil
}

// Parse 解析 UUID 字符串为 16 字节（等价 uuid.UUID(str) 构造）。
func Parse(s string) ([16]byte, error) {
	var out [16]byte
	// 去掉可选的花括号
	if len(s) >= 2 && s[0] == '{' && s[len(s)-1] == '}' {
		s = s[1 : len(s)-1]
	}
	// 去掉连字符后应为 32 个十六进制字符
	clean := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			continue
		}
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			clean = append(clean, c)
		default:
			return out, fmt.Errorf("非法 UUID 字符 %q", c)
		}
	}
	if len(clean) != 32 {
		return out, fmt.Errorf("UUID 长度非法: %q", s)
	}
	for i := 0; i < 16; i++ {
		hi := hexVal(clean[i*2])
		lo := hexVal(clean[i*2+1])
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func format(b [16]byte) string {
	var buf [36]byte
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf[:])
}

// HexToken 对齐 Python secrets.token_hex(n)：n 字节随机数的十六进制（2n 字符）。
func HexToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("uuidx: 读取系统随机源失败: %v", err))
	}
	return hex.EncodeToString(b)
}

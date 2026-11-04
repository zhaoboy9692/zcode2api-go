package app

import (
	"encoding/binary"
	"net"
	"net/url"
	"testing"
)

// fakeSocksUpstream 带鉴权的假上游 SOCKS5：要求 user/pass，CONNECT 后回显一行数据。
func fakeSocksUpstream(t *testing.T, user, pass string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// greeting：客户端方法表
				head := make([]byte, 2)
				if _, err := readFull(c, head); err != nil {
					return
				}
				methods := make([]byte, head[1])
				if _, err := readFull(c, methods); err != nil {
					return
				}
				hasAuth := false
				for _, m := range methods {
					if m == 2 {
						hasAuth = true
					}
				}
				if !hasAuth {
					c.Write([]byte{5, 0xFF})
					return
				}
				c.Write([]byte{5, 2})
				// user/pass 子协商（RFC 1929：ver(1) + ulen(1) + uname + plen(1) + passwd）
				ver := make([]byte, 1)
				if _, err := readFull(c, ver); err != nil {
					return
				}
				ul := make([]byte, 1)
				if _, err := readFull(c, ul); err != nil {
					return
				}
				u := make([]byte, ul[0])
				if _, err := readFull(c, u); err != nil {
					return
				}
				pl := make([]byte, 1)
				if _, err := readFull(c, pl); err != nil {
					return
				}
				p := make([]byte, pl[0])
				if _, err := readFull(c, p); err != nil {
					return
				}
				if string(u) != user || string(p) != pass {
					c.Write([]byte{1, 1})
					return
				}
				c.Write([]byte{1, 0})
				// CONNECT
				req := make([]byte, 4)
				if _, err := readFull(c, req); err != nil {
					return
				}
				if req[3] == 3 {
					l := make([]byte, 1)
					if _, err := readFull(c, l); err != nil {
						return
					}
					host := make([]byte, l[0])
					if _, err := readFull(c, host); err != nil {
						return
					}
					if string(host) != "zcode.z.ai" {
						c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0}) // host unreachable
						return
					}
				}
				port := make([]byte, 2)
				if _, err := readFull(c, port); err != nil {
					return
				}
				if binary.BigEndian.Uint16(port) != 443 {
					c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0})
					return
				}
				c.Write([]byte{5, 0, 0, 1, 10, 0, 0, 1, 0, 80})
				c.Write([]byte("OK-RELAY"))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestNormalizeProxyRaw(t *testing.T) {
	cases := []struct {
		in, want string
		err      bool
	}{
		{"", "", false},
		{"  ", "", false},
		{"socks5://u:p@1.2.3.4:1080", "socks5://u:p@1.2.3.4:1080", false},
		{"socks5h://u:p@1.2.3.4:1080", "socks5://u:p@1.2.3.4:1080", false},
		{"http://zxc:pw@42.194.158.165:58080", "http://zxc:pw@42.194.158.165:58080", false},
		{"42.194.158.165:58080", "http://42.194.158.165:58080", false},
		{"ftp://x:1", "", true},
		{"http://", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeProxyRaw(c.in)
		if c.err && err == nil {
			t.Fatalf("NormalizeProxyRaw(%q) 期望报错，得到 %q", c.in, got)
		}
		if !c.err && err != nil {
			t.Fatalf("NormalizeProxyRaw(%q) 意外报错: %v", c.in, err)
		}
		if !c.err && got != c.want {
			t.Fatalf("NormalizeProxyRaw(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestSocksAuthRelayEndToEnd(t *testing.T) {
	up := fakeSocksUpstream(t, "testuser", "testpass")
	upstreamURL, _ := url.Parse("socks5://testuser:testpass@" + up)
	local, err := ensureSocksAuthRelay(upstreamURL)
	if err != nil {
		t.Fatalf("启动中继失败: %v", err)
	}

	// 走中继的 SOCKS5 客户端（免鉴权）请求 CONNECT zcode.z.ai:443
	conn, err := net.Dial("tcp", stripScheme(local))
	if err != nil {
		t.Fatalf("连中继失败: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte{5, 1, 0}) // 只要 NO-AUTH
	resp := make([]byte, 2)
	if _, err := readFull(conn, resp); err != nil || resp[1] != 0 {
		t.Fatalf("中继方法协商异常: %v %v", resp, err)
	}
	host := "zcode.z.ai"
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], 443)
	req = append(req, port[:]...)
	conn.Write(req)
	rep := make([]byte, 8) // 中继回给客户端的 CONNECT 成功回复固定 8 字节
	if _, err := readFull(conn, rep); err != nil {
		t.Fatalf("读 CONNECT 回复失败: %v", err)
	}
	if rep[1] != 0 {
		t.Fatalf("CONNECT 失败 code=%d", rep[1])
	}
	body := make([]byte, 8) // 假上游的回显数据
	if _, err := readFull(conn, body); err != nil {
		t.Fatalf("读回显数据失败: %v", err)
	}
	if string(body) != "OK-RELAY" {
		t.Fatalf("回显数据不符: %q", body)
	}
}

func stripScheme(socksURL string) string {
	for i := 0; i < len(socksURL); i++ {
		if socksURL[i:i+3] == "://" {
			return socksURL[i+3:]
		}
	}
	return socksURL
}

// SOCKS5 免鉴权本地中继：给验证码浏览器（Chromium）用。
//
// Chromium 的 --proxy-server 不支持 SOCKS 用户名/密码认证，而显式上游代理
// （ZCODE_UPSTREAM_PROXY）完全可能是带鉴权的 socks5://user:pass@host:port。
// 为保住「验证码出口 == 请求出口」的一致性，这里在 127.0.0.1 起一个免鉴权
// SOCKS5 服务：浏览器连它，它带凭据连真代理，之后双向搬运字节。
//
// 协议最小实现（RFC 1928）：服务端侧只收 NO-AUTH 且只认 CONNECT；客户端侧
// 只发 user/pass 子协商（0x02）。每连接一个 goroutine，握手 10s 超时，建流后
// 不设整体超时（长隧道）。
package app

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"
)

var (
	relayMu       sync.Mutex
	relayAddr     string // 已启动中继的 "socks5://127.0.0.1:port"；空 = 未启动
	relayUpstream *url.URL
)

// ensureSocksAuthRelay 启动（幂等）本地免鉴权 SOCKS5 中继，返回其代理 URL。
func ensureSocksAuthRelay(upstream *url.URL) (string, error) {
	relayMu.Lock()
	defer relayMu.Unlock()
	if relayAddr != "" && relayUpstream != nil && relayUpstream.String() == upstream.String() {
		return relayAddr, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // 监听关闭（进程退出），尽力而为的辅助设施
			}
			go handleRelayConn(conn, upstream)
		}
	}()
	relayAddr = "socks5://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	relayUpstream = upstream
	return relayAddr, nil
}

func handleRelayConn(client net.Conn, upstream *url.URL) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	// ── 服务端握手：收方法表，一律回 NO-AUTH ──
	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil {
		return
	}
	if head[0] != 5 {
		return
	}
	n := int(head[1])
	methods := make([]byte, n)
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}

	// ── 收 CONNECT 请求（atyp/addr/port 原样透传给上游）──
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	if req[1] != 1 { // 只支持 CONNECT
		_, _ = client.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 1: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3: // 域名
		l := make([]byte, 1)
		if _, err := io.ReadFull(client, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = string(b)
	case 4: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		_, _ = client.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0})
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	// ── 上游握手：要 user/pass 子协商，带凭据 CONNECT ──
	up, err := dialSocksUpstream(upstream, host, port)
	if err != nil {
		_, _ = client.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0}) // general failure
		return
	}
	defer up.Close()
	_ = client.SetDeadline(time.Time{}) // 建流后解除握手超时

	if _, err := client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0}); err != nil {
		return
	}
	pipeRelay(client, up)
}

// dialSocksUpstream 带凭据连上游 SOCKS5 并请求 CONNECT host:port。
func dialSocksUpstream(upstream *url.URL, host string, port uint16) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", upstream.Host, 15*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	pass, _ := upstream.User.Password()
	hasAuth := upstream.User != nil && upstream.User.Username() != ""

	// 方法表：有凭据要 user/pass(0x02)，无凭据只要 NO-AUTH(0x00)
	greet := []byte{5, 1, 0}
	if hasAuth {
		greet = []byte{5, 2, 0, 2}
	}
	if _, err := conn.Write(greet); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[0] != 5 || resp[1] == 0xFF {
		conn.Close()
		return nil, fmt.Errorf("上游代理不接受可用认证方法")
	}
	if resp[1] == 2 { // user/pass 子协商（RFC 1929）
		if !hasAuth {
			conn.Close()
			return nil, fmt.Errorf("上游代理要求认证但未提供凭据")
		}
		user := upstream.User.Username()
		auth := append([]byte{1, byte(len(user))}, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if _, err := conn.Write(auth); err != nil {
			conn.Close()
			return nil, err
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil {
			conn.Close()
			return nil, err
		}
		if ar[1] != 0 {
			conn.Close()
			return nil, fmt.Errorf("上游代理认证失败")
		}
	}

	// CONNECT
	target := []byte{5, 1, 0, 3, byte(len(host))}
	target = append(target, host...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	target = append(target, portBuf[:]...)
	if _, err := conn.Write(target); err != nil {
		conn.Close()
		return nil, err
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, err
	}
	if reply[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("上游 CONNECT 失败，code=%d", reply[1])
	}
	// 丢弃 BND.ADDR/PORT
	switch reply[3] {
	case 1:
		_, _ = io.ReadFull(conn, make([]byte, 6))
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			conn.Close()
			return nil, err
		}
		_, _ = io.ReadFull(conn, make([]byte, int(l[0])+2))
	case 4:
		_, _ = io.ReadFull(conn, make([]byte, 18))
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func pipeRelay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
}

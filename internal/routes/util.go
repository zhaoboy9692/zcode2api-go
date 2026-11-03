// routes 层内部工具：IO/随机/拨号助手。
package routes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"
)

// ioReadCloser 别名（网关内存响应体用）。
type ioReadCloser = io.ReadCloser

var ioEOF = io.EOF

// readAll 对齐 httpx resp.aread()。
func readAll(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	return io.ReadAll(r)
}

// randHexImpl 对齐 secrets.token_hex(n)。
func randHexImpl(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// dialerWithTimeout 对齐 httpx connect 超时。
func dialerWithTimeout(d time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d, KeepAlive: 30 * time.Second}).DialContext
}

var _ = fmt.Sprintf

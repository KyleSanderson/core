package proxy

import (
	"io"
	"sync"
)

// proxyBufSize is the size of every buffer handed out by the shared pool.
// 64KB keeps bulk relay reads large (fewer syscalls per byte on the
// netstack) while bounding per-connection memory to one buffer per copy
// direction.
const proxyBufSize = 64 * 1024

// bufPool is the single shared buffer pool for all proxy data paths. HTTP
// CONNECT tunnels, 101 protocol upgrades, plain-HTTP relays, SOCKS4
// relays and go-socks5 (via its bufferpool.BufPool interface) all draw
// from it, so buffers are reused aggressively across thousands of
// connections instead of being reallocated per connection.
type bufPool struct {
	pool sync.Pool
}

var buffers = bufPool{pool: sync.Pool{New: newProxyBuf}}

func newProxyBuf() any {
	b := make([]byte, proxyBufSize)
	return &b
}

// Get returns a proxyBufSize buffer. The method set (Get/Put) satisfies
// go-socks5's bufferpool.BufPool, which is how the SOCKS5 server ends up
// sharing this same pool.
func (p *bufPool) Get() []byte {
	b := p.pool.Get().(*[]byte)
	return *b
}

// Put returns a buffer to the pool. Foreign or resized slices are dropped
// rather than pooled so a bad caller cannot poison every other user of
// the pool.
func (p *bufPool) Put(b []byte) {
	if cap(b) != proxyBufSize {
		return
	}
	s := b[:proxyBufSize]
	p.pool.Put(&s)
}

// copyBuffer copies src to dst through a pooled 64KB buffer so no
// per-connection io.Copy scratch buffers are allocated.
func copyBuffer(dst io.Writer, src io.Reader) error {
	if _, ok := dst.(io.ReaderFrom); ok {
		_, err := io.Copy(dst, src)
		return err
	} else if _, ok := src.(io.WriterTo); ok {
		_, err := io.Copy(dst, src)
		return err
	}

	buf := buffers.Get()
	_, err := io.CopyBuffer(dst, src, buf)
	buffers.Put(buf)
	return err
}

// copyThenClose copies src to dst through a pooled buffer and then closes
// closeAfter, which unblocks the opposite-direction copy that is still
// reading from the same connection.
func copyThenClose(dst io.Writer, src io.Reader, closeAfter io.Closer) {
	_ = copyBuffer(dst, src)
	if closeAfter != nil {
		_ = closeAfter.Close()
	}
}

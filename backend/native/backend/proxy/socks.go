package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	wireproxyawg "github.com/artem-russkikh/wireproxy-awg"
	"github.com/things-go/go-socks5"
)

// socksProxySpawner replaces the fork's SOCKS5-only routine with a listener
// that multiplexes SOCKS5 and SOCKS4/4a on the same port.
//
// Windows Internet Options (WinINET) only ever implemented SOCKS4/4a, so a
// SOCKS5-only listener immediately closes Windows connections (go-socks5
// expects version byte 0x05 and rejects 0x04), which is why the SOCKS proxy
// "didn't work at all" from the hotspot Windows client.
type socksProxySpawner struct {
	conf *wireproxyawg.Socks5Config
}

func (s *socksProxySpawner) SpawnRoutine(ctx context.Context, vt *wireproxyawg.VirtualTun) error {
	server := &socksProxyServer{
		conf:   s.conf,
		vt:     vt,
		logger: vt.Logger,
		socks5: newSocks5Server(s.conf, vt),
	}
	server.logger.Verbosef("SOCKS proxy routine started for bind address %s", s.conf.BindAddress)
	return server.listenAndServe(ctx)
}

const (
	socksVersion4             = 0x04
	socksVersion5             = 0x05
	socks4RequestGranted      = 0x5a
	socks4RequestRejected     = 0x5b
	socks4ConnectCommand      = 0x01
	socks4GreetingReadTimeout = 30 * time.Second
	socks4MaxFieldLength      = 512
)

type socksProxyServer struct {
	conf   *wireproxyawg.Socks5Config
	vt     *wireproxyawg.VirtualTun
	logger *device.Logger
	socks5 *socks5.Server
}

func newSocks5Server(conf *wireproxyawg.Socks5Config, vt *wireproxyawg.VirtualTun) *socks5.Server {
	var authMethods []socks5.Authenticator
	if conf.Username != "" {
		authMethods = append(authMethods, socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{conf.Username: conf.Password},
		})
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	options := []socks5.Option{
		// Hostnames are resolved by the netstack, whose queries are
		// hijacked by the WrapperTUN DNS engine (DoT/DoH/plain/split
		// DNS, caching). Tnet.DialContext's signature matches exactly.
		socks5.WithDial(vt.Tnet.DialContext),
		socks5.WithAuthMethods(authMethods),
		// go-socks5's BufPool interface is satisfied by the same shared
		// 64KB pool the HTTP relays use (see pool.go) — one pool total.
		socks5.WithBufferPool(&buffers),
	}
	return socks5.NewServer(options...)
}

func (s *socksProxyServer) listenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.conf.BindAddress)
	if err != nil {
		s.logger.Errorf("SOCKS proxy listen on %s failed: %v", s.conf.BindAddress, err)
		return err
	}
	s.logger.Verbosef("SOCKS proxy listener bound on %s", s.conf.BindAddress)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Errorf("SOCKS proxy accept error: %v", err)
			return err
		}
		go s.serveConn(conn)
	}
}

// bufioConn lets go-socks5 read from the shared bufio.Reader so bytes already
// buffered during version detection are not lost.
type bufioConn struct {
	net.Conn
	br *bufio.Reader
}

func (c bufioConn) Read(p []byte) (int, error) { return c.br.Read(p) }

func (s *socksProxyServer) serveConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(socks4GreetingReadTimeout))
	version, err := br.Peek(1)
	if err != nil || len(version) == 0 {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	switch version[0] {
	case socksVersion5:
		if err = s.socks5.ServeConn(bufioConn{conn, br}); err != nil && !isBenignConnError(err) {
			s.logger.Errorf("SOCKS5 serve error for %s: %v", conn.RemoteAddr(), err)
		}
	case socksVersion4:
		s.serveSocks4(conn, br)
	default:
		s.logger.Errorf("SOCKS unsupported protocol version %d from %s", version[0], conn.RemoteAddr())
	}
}

// serveSocks4 handles SOCKS4 and SOCKS4a CONNECT requests (WinINET-compatible).
func (s *socksProxyServer) serveSocks4(conn net.Conn, br *bufio.Reader) {
	var header [8]byte
	if _, err := io.ReadFull(br, header[:]); err != nil {
		return
	}

	command := header[1]
	port := binary.BigEndian.Uint16(header[2:4])
	rawIP := net.IP(header[4:8])

	// The userid field carries no credential the shared proxy configuration
	// could check (SOCKS4 has no password support at all), but it must still
	// be consumed for framing before the optional 4a hostname.
	if _, err := readSocks4Field(br); err != nil {
		return
	}

	reply := func(code byte) {
		_, _ = conn.Write([]byte{0x00, code, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}

	if command != socks4ConnectCommand {
		reply(socks4RequestRejected)
		return
	}

	// SOCKS4a: 0.0.0.x (nonzero final octet) means the hostname follows.
	var host string
	if len(rawIP) == 4 && rawIP[0] == 0 && rawIP[1] == 0 && rawIP[2] == 0 && rawIP[3] != 0 {
		domain, err := readSocks4Field(br)
		if err != nil {
			return
		}
		host = string(domain)
	} else {
		host = rawIP.String()
	}

	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	peer, err := s.vt.Tnet.Dial("tcp", addr)
	if err != nil {
		s.logger.Verbosef("SOCKS4 dial to %s failed: %v", addr, err)
		reply(socks4RequestRejected)
		return
	}
	defer func() { _ = peer.Close() }()

	reply(socks4RequestGranted)

	// Both directions copy through the shared 64KB buffer pool (pool.go).
	go copyThenClose(peer, io.MultiReader(br, conn), peer)
	_ = copyBuffer(conn, peer)
}

func readSocks4Field(r io.Reader) ([]byte, error) {
	var (
		out  []byte
		next [1]byte
	)
	for {
		if _, err := io.ReadFull(r, next[:]); err != nil {
			return nil, err
		}
		if next[0] == 0x00 {
			return out, nil
		}
		out = append(out, next[0])
		if len(out) > socks4MaxFieldLength {
			return nil, errors.New("socks4 field too long")
		}
	}
}

func isBenignConnError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection aborted") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "operation aborted")
}

package bind

import (
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// NetstackBind sends and receives WireGuard UDP on a gVisor netstack, so an
// inner Device's packets traverse an outer Device's tunnel instead of the NIC.
type NetstackBind struct {
	tnet   *netstack.Net
	locals []netip.Addr

	mu     sync.Mutex
	ipv4   *gonet.UDPConn
	ipv6   *gonet.UDPConn
	closed bool
}

func NewNetstackBind(tnet *netstack.Net, locals []netip.Addr) conn.Bind {
	return &NetstackBind{tnet: tnet, locals: locals}
}

func (b *NetstackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: e}, nil
}

func (b *NetstackBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ipv4 != nil || b.ipv6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.closed = false

	port := uport
	var fns []conn.ReceiveFunc
	var err, err6 error

	v4Local, v6Local, has4, has6 := b.listenLocals()
	if has4 {
		var v4 *gonet.UDPConn
		v4, err = b.tnet.ListenUDPAddrPort(netip.AddrPortFrom(v4Local, port))
		if err == nil {
			b.ipv4 = v4
			if ap, ok := udpAddrPort(v4.LocalAddr()); ok && port == 0 {
				port = ap.Port()
			}
			fns = append(fns, b.makeReceive(v4))
		}
	}

	if has6 {
		var v6 *gonet.UDPConn
		v6, err6 = b.tnet.ListenUDPAddrPort(netip.AddrPortFrom(v6Local, port))
		if err6 == nil {
			b.ipv6 = v6
			if ap, ok := udpAddrPort(v6.LocalAddr()); ok && port == 0 {
				port = ap.Port()
			}
			fns = append(fns, b.makeReceive(v6))
		}
	}

	if len(fns) == 0 {
		if err != nil {
			return nil, 0, err
		}
		if err6 != nil {
			return nil, 0, err6
		}
		return nil, 0, syscall.EAFNOSUPPORT
	}
	return fns, port, nil
}

func (b *NetstackBind) makeReceive(c *gonet.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, addr, err := c.ReadFrom(packets[0])
		if err != nil {
			b.mu.Lock()
			closed := b.closed
			b.mu.Unlock()
			if closed {
				return 0, net.ErrClosed
			}
			return 0, err
		}
		sizes[0] = n
		uaddr, ok := addr.(*net.UDPAddr)
		if !ok {
			return 0, syscall.EINVAL
		}
		ip, _ := netip.AddrFromSlice(uaddr.IP)
		if ip.Is4In6() {
			ip = ip.Unmap()
		}
		eps[0] = &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(ip, uint16(uaddr.Port))}
		return 1, nil
	}
}

func (b *NetstackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	var err1, err2 error
	if b.ipv4 != nil {
		err1 = b.ipv4.Close()
		b.ipv4 = nil
	}
	if b.ipv6 != nil {
		err2 = b.ipv6.Close()
		b.ipv6 = nil
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (b *NetstackBind) SetMark(uint32) error { return nil }

func (b *NetstackBind) BatchSize() int { return 1 }

func (b *NetstackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	std, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	dst := std.AddrPort
	addr := dst.Addr()
	if addr.Is4In6() {
		addr = addr.Unmap()
		dst = netip.AddrPortFrom(addr, dst.Port())
	}

	b.mu.Lock()
	c := b.ipv4
	if addr.Is6() {
		c = b.ipv6
	}
	b.mu.Unlock()
	if c == nil {
		return syscall.EAFNOSUPPORT
	}

	ua := net.UDPAddrFromAddrPort(dst)
	for _, buf := range bufs {
		if _, err := c.WriteTo(buf, ua); err != nil {
			return err
		}
	}
	return nil
}

func (b *NetstackBind) listenLocals() (v4, v6 netip.Addr, has4, has6 bool) {
	v4 = netip.IPv4Unspecified()
	v6 = netip.IPv6Unspecified()
	if len(b.locals) == 0 {
		return v4, v6, true, true
	}
	for _, a := range b.locals {
		if a.Is4() && !has4 {
			v4 = a
			has4 = true
		}
		if a.Is6() && !has6 {
			v6 = a
			has6 = true
		}
	}
	return v4, v6, has4, has6
}

func udpAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	if addr == nil {
		return netip.AddrPort{}, false
	}
	uaddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	return uaddr.AddrPort(), true
}

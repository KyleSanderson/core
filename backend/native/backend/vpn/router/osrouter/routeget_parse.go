package osrouter

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// darwinNetRoute is one exact entry from `route get` on Darwin.
type darwinNetRoute struct {
	dst     netip.Prefix
	iface   string
	gateway string // empty or link#N means an interface route
}

func (rt darwinNetRoute) viaGateway() bool {
	if rt.gateway == "" {
		return false
	}
	if strings.HasPrefix(rt.gateway, "link#") {
		return false
	}
	if rt.iface != "" && rt.gateway == rt.iface {
		return false
	}
	return true
}

func parseDarwinRouteGet(out string, isv6 bool) (darwinNetRoute, bool) {
	var dest, mask, gw, ifName, prefixlen string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "destination":
			dest = val
		case "mask":
			mask = val
		case "gateway":
			gw = val
		case "interface":
			ifName = val
		case "prefixlen":
			prefixlen = val
		}
	}
	if dest == "" && ifName == "" {
		return darwinNetRoute{}, false
	}
	p, ok := prefixFromRouteGet(dest, mask, prefixlen, isv6)
	if !ok {
		return darwinNetRoute{}, false
	}
	return darwinNetRoute{dst: p, iface: ifName, gateway: gw}, true
}

func prefixFromRouteGet(dest, mask, prefixlen string, isv6 bool) (netip.Prefix, bool) {
	if dest == "" || dest == "default" {
		if isv6 {
			return netip.MustParsePrefix("::/0"), true
		}
		return netip.MustParsePrefix("0.0.0.0/0"), true
	}
	if p, err := netip.ParsePrefix(dest); err == nil {
		return p.Masked(), true
	}
	addr, err := netip.ParseAddr(dest)
	if err != nil {
		return netip.Prefix{}, false
	}
	if prefixlen != "" {
		bits, err := strconv.Atoi(prefixlen)
		if err == nil {
			p := netip.PrefixFrom(addr, bits)
			if p.IsValid() {
				return p.Masked(), true
			}
		}
	}
	if mask == "" || mask == "default" {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	ip := net.ParseIP(mask)
	if ip == nil {
		return netip.Prefix{}, false
	}
	var m net.IPMask
	if addr.Is6() {
		m = net.IPMask(ip.To16())
	} else {
		m = net.IPMask(ip.To4())
		if m == nil {
			return netip.Prefix{}, false
		}
	}
	ones, bits := m.Size()
	if bits == 0 {
		return netip.Prefix{}, false
	}
	p := netip.PrefixFrom(addr, ones)
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

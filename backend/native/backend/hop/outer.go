package hop

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	wireproxyawg "github.com/artem-russkikh/wireproxy-awg"
	"github.com/wgtunnel/backend/bind"
	"github.com/wgtunnel/backend/log"
	"github.com/wgtunnel/backend/roaming"
)

const (
	tag         = "OuterHop"
	defaultMTU  = 1280
	wgOverhead  = 80
	minInnerMTU = 576
)

// Outer is a netstack-only WireGuard device that carries an inner Device's UDP.
type Outer struct {
	Dev   *device.Device
	Tnet  *netstack.Net
	MTU   int
	Addrs []netip.Addr
}

var (
	attachMu sync.Mutex
	byHandle = map[int32]*Outer{}
)

// Start brings up a physical-bind Device on a gVisor TUN. bypass is passed to
// bind.NewBind so the outer sockets use the protected path.
func Start(config string, bypass bool) (*Outer, error) {
	config = strings.Clone(config)
	conf, err := wireproxyawg.ParseConfigString(config)
	if err != nil {
		return nil, err
	}
	setting, err := wireproxyawg.CreateIPCRequest(conf.Device, false)
	if err != nil {
		return nil, err
	}
	mtu := setting.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}
	tun, tnet, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, mtu)
	if err != nil {
		return nil, err
	}

	statusCB := func(code device.StatusCode) {
		if code != device.StatusHealthy {
			log.Error(tag, "status %d", code)
		}
	}
	dev := device.NewDevice(
		tun,
		bind.NewBind(bypass),
		log.WithTag(tag).DeviceLogger(),
		statusCB,
	)
	roaming.ApplyRoaming(dev)
	if err := dev.IpcSet(setting.IpcRequest); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	log.Debug(tag, "outer device up mtu=%d bypass=%v", mtu, bypass)
	return &Outer{Dev: dev, Tnet: tnet, MTU: mtu, Addrs: setting.DeviceAddr}, nil
}

func (o *Outer) Close() {
	if o == nil || o.Dev == nil {
		return
	}
	o.Dev.Close()
	o.Dev = nil
}

// StartOuterIfSet starts an outer hop when outerConfig is not empty and returns
// the bind the inner Device should use. The caller must Attach on success or
// Close the Outer on failure.
func StartOuterIfSet(outerConfig string, bypass bool) (*Outer, conn.Bind, error) {
	if strings.TrimSpace(outerConfig) == "" {
		return nil, bind.NewBind(bypass), nil
	}
	o, err := Start(outerConfig, bypass)
	if err != nil {
		return nil, nil, err
	}
	return o, bind.NewNetstackBind(o.Tnet, o.Addrs), nil
}

// AdjustInnerMTU drops the inner MTU so a full inner packet fits in the outer
// tunnel. No-op when there is no outer hop.
func AdjustInnerMTU(inner *wireproxyawg.DeviceConfig, outer *Outer) {
	if inner == nil || outer == nil {
		return
	}
	maxInner := outer.MTU - wgOverhead
	if maxInner < minInnerMTU {
		maxInner = minInnerMTU
	}
	if inner.MTU <= 0 || inner.MTU > maxInner {
		log.Debug(tag, "inner MTU %d -> %d (outer %d)", inner.MTU, maxInner, outer.MTU)
		inner.MTU = maxInner
	}
}

func Attach(handle int32, o *Outer) {
	if o == nil {
		return
	}
	attachMu.Lock()
	defer attachMu.Unlock()
	if old, ok := byHandle[handle]; ok {
		old.Close()
	}
	byHandle[handle] = o
}

func CloseAttached(handle int32) {
	attachMu.Lock()
	o := byHandle[handle]
	delete(byHandle, handle)
	attachMu.Unlock()
	if o != nil {
		o.Close()
	}
}

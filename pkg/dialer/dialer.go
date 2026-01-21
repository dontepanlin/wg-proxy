package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const MTU = 1280

type Dialer struct {
	net *netstack.Net
	dev *device.Device
}

func NewDialer(debug bool, in Interface, peers ...Peer) (*Dialer, error) {
	addr, err := netip.ParseAddr(in.Address)
	if err != nil {
		return nil, err
	}
	dns_addresses := []netip.Addr{}
	for _, raw := range in.Dns {
		dns, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, err
		}
		dns_addresses = append(dns_addresses, dns)
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, dns_addresses, MTU)
	if err != nil {
		return nil, err
	}

	logger := device.NewLogger(device.LogLevelSilent, "wireguard")
	if debug {
		logger = device.NewLogger(device.LogLevelVerbose, "wireguard")
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)

	key, err := base64KeyToHex(in.PrivateKey)
	if err != nil {
		return nil, err
	}
	ipcString := fmt.Sprintf("private_key=%s\n", key)

	for _, peer := range peers {
		str, err := peer.toIpcString()
		if err != nil {
			return nil, err
		}
		ipcString = fmt.Sprintf("%s%s", ipcString, str)
	}

	logrus.Debugf("ipc_string: %s", ipcString)

	err = dev.IpcSet(ipcString)
	if err != nil {
		return nil, err
	}

	return &Dialer{
		net: tnet,
		dev: dev,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.net.DialContext(ctx, network, address)
}

func (d *Dialer) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := d.net.LookupHost(name)
	if err != nil {
		return ctx, nil, err
	}
	if len(addr) == 0 {
		return ctx, nil, fmt.Errorf("no addresses found for %s", name)
	}
	// Convert the first resolved IP address to net.IP
	ip := net.ParseIP(addr[0])
	return ctx, ip, nil
}

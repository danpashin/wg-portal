package adapters

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/danpashin/wgctrl"
	"github.com/danpashin/wgctrl/wgtypes"
	"github.com/vishvananda/netlink"

	"github.com/h44z/wg-portal/internal/domain"
	"github.com/h44z/wg-portal/internal/lowlevel"
)

// WgRepo implements all low-level WireGuard interactions.
type WgRepo struct {
	Clients map[string]lowlevel.WireGuardClient
	nl      lowlevel.NetlinkClient
}

// NewWireGuardRepository creates a new WgRepo instance.
// This repository is used to interact with the WireGuard/AmneziaWG kernel or userspace module.
func NewWireGuardRepository() *WgRepo {
	clientTypes := []wgtypes.ClientType{
		wgtypes.NativeClient,
		wgtypes.AmneziaClient,
	}

	clients := make(map[string]lowlevel.WireGuardClient)
	for _, clientType := range clientTypes {
		client, err := wgctrl.New(clientType)
		if err != nil {
			slog.Warn("failed to init wgctrl: %s\n", err.Error())
			continue
		}

		devices, err := client.Devices()
		if err != nil {
			slog.Warn("failed to get client devices %s\n", err.Error())
			continue
		}

		for _, device := range devices {
			clients[device.Name] = client
		}
	}

	if len(clients) == 0 {
		panic("no wg-compatible clients available")
	}

	nl := &lowlevel.NetlinkManager{}

	repo := &WgRepo{
		Clients: clients,
		nl:      nl,
	}

	return repo
}

// GetInterfaces returns all existing WireGuard interfaces.
func (r *WgRepo) GetInterfaces(_ context.Context) ([]domain.PhysicalInterface, error) {
	type DeviceClient struct {
		Device     *wgtypes.Device
		ClientType wgtypes.ClientType
	}

	var devicesErrors []error
	var devices []DeviceClient
	for _, client := range r.Clients {
		clientDevices, err := client.Devices()
		if err != nil {
			devicesErrors = append(devicesErrors, err)
		} else {
			for _, device := range clientDevices {
				devices = append(devices, DeviceClient{
					Device:     device,
					ClientType: client.Type(),
				})
			}
		}
	}

	if len(devicesErrors) > 0 {
		formatted := "device list error:\n"
		for _, err := range devicesErrors {
			formatted += fmt.Sprintf("- %s\n", err.Error())
		}
		return nil, fmt.Errorf(formatted)
	}

	interfaces := make([]domain.PhysicalInterface, 0, len(devices))
	for _, deviceClient := range devices {
		device := deviceClient.Device
		interfaceModel, err := r.convertWireGuardInterface(deviceClient.ClientType, device)
		if err != nil {
			return nil, fmt.Errorf("interface convert failed for %s: %w", device.Name, err)
		}
		interfaces = append(interfaces, interfaceModel)
	}

	return interfaces, nil
}

// GetInterface returns the interface with the given id.
// If no interface is found, an error os.ErrNotExist is returned.
func (r *WgRepo) GetInterface(_ context.Context, id domain.InterfaceIdentifier) (*domain.PhysicalInterface, error) {
	return r.getInterface(id)
}

// GetPeers returns all peers associated with the given interface id.
// If the requested interface is found, an error os.ErrNotExist is returned.
func (r *WgRepo) GetPeers(_ context.Context, deviceId domain.InterfaceIdentifier) ([]domain.PhysicalPeer, error) {
	client := r.Clients[string(deviceId)]
	if client == nil {
		return nil, fmt.Errorf("nullable client for %s", deviceId)
	}

	device, err := client.Device(string(deviceId))
	if err != nil {
		return nil, fmt.Errorf("device error: %w", err)
	}

	peers := make([]domain.PhysicalPeer, 0, len(device.Peers))
	for _, peer := range device.Peers {
		peerModel, err := r.convertWireGuardPeer(&peer)
		if err != nil {
			return nil, fmt.Errorf("peer convert failed for %v: %w", peer.PublicKey, err)
		}
		peers = append(peers, peerModel)
	}

	return peers, nil
}

// GetPeer returns the peer with the given id.
// If the requested interface or peer is found, an error os.ErrNotExist is returned.
func (r *WgRepo) GetPeer(
	_ context.Context,
	deviceId domain.InterfaceIdentifier,
	id domain.PeerIdentifier,
) (*domain.PhysicalPeer, error) {
	return r.getPeer(deviceId, id)
}

func (r *WgRepo) convertWireGuardInterface(clientType wgtypes.ClientType, device *wgtypes.Device) (domain.PhysicalInterface, error) {
	// read data from wgctrl interface

	iface := domain.PhysicalInterface{
		Identifier: domain.InterfaceIdentifier(device.Name),
		KeyPair: domain.KeyPair{
			PrivateKey: device.PrivateKey.String(),
			PublicKey:  device.PublicKey.String(),
		},
		ListenPort:    device.ListenPort,
		Addresses:     nil,
		Mtu:           0,
		FirewallMark:  uint32(device.FirewallMark),
		DeviceUp:      false,
		ImportSource:  "wgctrl",
		DeviceType:    device.Type.String(),
		BytesUpload:   0,
		BytesDownload: 0,
		ClientType:    clientType,
	}

	if device.HasAdvancedSecurity() {
		iface.AdvancedSecurity = &domain.AdvancedSecurity{
			JunkPacketCount:   device.AdvancedSecurity.JunkPacketCount,
			JunkPacketMinSize: device.AdvancedSecurity.JunkPacketMinSize,
			JunkPacketMaxSize: device.AdvancedSecurity.JunkPacketMaxSize,

			InitPacketJunkSize:        device.AdvancedSecurity.InitPacketJunkSize,
			ResponsePacketJunkSize:    device.AdvancedSecurity.ResponsePacketJunkSize,
			CookieReplyPacketJunkSize: device.AdvancedSecurity.CookieReplyPacketJunkSize,
			TransportPacketJunkSize:   device.AdvancedSecurity.TransportPacketJunkSize,

			InitPacketMagicHeader:      device.AdvancedSecurity.InitPacketMagicHeader,
			ResponsePacketMagicHeader:  device.AdvancedSecurity.ResponsePacketMagicHeader,
			UnderloadPacketMagicHeader: device.AdvancedSecurity.UnderloadPacketMagicHeader,
			TransportPacketMagicHeader: device.AdvancedSecurity.TransportPacketMagicHeader,

			FirstSpecialJunkPacket:  device.AdvancedSecurity.FirstSpecialJunkPacket,
			SecondSpecialJunkPacket: device.AdvancedSecurity.SecondSpecialJunkPacket,
			ThirdSpecialJunkPacket:  device.AdvancedSecurity.ThirdSpecialJunkPacket,
			FourthSpecialJunkPacket: device.AdvancedSecurity.FourthSpecialJunkPacket,
			FifthSpecialJunkPacket:  device.AdvancedSecurity.FifthSpecialJunkPacket,
		}
	}

	// read data from netlink interface

	lowLevelInterface, err := r.nl.LinkByName(device.Name)
	if err != nil {
		return domain.PhysicalInterface{}, fmt.Errorf("netlink error for %s: %w", device.Name, err)
	}
	ipAddresses, err := r.nl.AddrList(lowLevelInterface)
	if err != nil {
		return domain.PhysicalInterface{}, fmt.Errorf("ip read error for %s: %w", device.Name, err)
	}

	for _, addr := range ipAddresses {
		iface.Addresses = append(iface.Addresses, domain.CidrFromNetlinkAddr(addr))
	}
	iface.Mtu = lowLevelInterface.Attrs().MTU
	iface.DeviceUp = lowLevelInterface.Attrs().OperState == netlink.OperUnknown // wg only supports unknown
	if stats := lowLevelInterface.Attrs().Statistics; stats != nil {
		iface.BytesUpload = stats.TxBytes
		iface.BytesDownload = stats.RxBytes
	}

	return iface, nil
}

func (r *WgRepo) convertWireGuardPeer(peer *wgtypes.Peer) (domain.PhysicalPeer, error) {
	peerModel := domain.PhysicalPeer{
		Identifier: domain.PeerIdentifier(peer.PublicKey.String()),
		Endpoint:   "",
		AllowedIPs: nil,
		KeyPair: domain.KeyPair{
			PublicKey: peer.PublicKey.String(),
		},
		PresharedKey:        "",
		PersistentKeepalive: int(peer.PersistentKeepaliveInterval.Seconds()),
		LastHandshake:       peer.LastHandshakeTime,
		ProtocolVersion:     peer.ProtocolVersion,
		BytesUpload:         uint64(peer.ReceiveBytes),
		BytesDownload:       uint64(peer.TransmitBytes),
	}

	for _, addr := range peer.AllowedIPs {
		peerModel.AllowedIPs = append(peerModel.AllowedIPs, domain.CidrFromIpNet(addr))
	}
	if peer.Endpoint != nil {
		peerModel.Endpoint = peer.Endpoint.String()
	}
	if peer.PresharedKey != (wgtypes.Key{}) {
		peerModel.PresharedKey = domain.PreSharedKey(peer.PresharedKey.String())
	}

	return peerModel, nil
}

// SaveInterface updates the interface with the given id.
// If no existing interface is found, a new interface is created.
// Updating the interface does not interrupt any existing connections.
func (r *WgRepo) SaveInterface(
	_ context.Context,
	clientType wgtypes.ClientType,
	id domain.InterfaceIdentifier,
	updateFunc func(pi *domain.PhysicalInterface) (*domain.PhysicalInterface, error),
) error {
	physicalInterface, err := r.getOrCreateInterface(clientType, id)
	if err != nil {
		return err
	}

	if updateFunc != nil {
		physicalInterface, err = updateFunc(physicalInterface)
		if err != nil {
			return err
		}
	}

	if err := r.updateLowLevelInterface(physicalInterface); err != nil {
		return err
	}
	if err := r.updateWireGuardInterface(physicalInterface); err != nil {
		return err
	}

	return nil
}

func (r *WgRepo) getOrCreateInterface(clientType wgtypes.ClientType, id domain.InterfaceIdentifier) (*domain.PhysicalInterface, error) {
	device, err := r.getInterface(id)
	if err == nil {
		return device, nil // interface exists
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("device error: %w", err) // unknown error
	}

	// create new device
	if err := r.createLowLevelInterface(clientType, id); err != nil {
		return nil, err
	}

	device, err = r.getInterface(id)
	return device, err
}

func (r *WgRepo) getInterface(id domain.InterfaceIdentifier) (*domain.PhysicalInterface, error) {
	client := r.Clients[string(id)]
	if client == nil {
		return nil, fmt.Errorf("nullable client for %s", id)
	}

	device, err := client.Device(string(id))
	if err != nil {
		return nil, err
	}

	pi, err := r.convertWireGuardInterface(client.Type(), device)
	return &pi, err
}

func (r *WgRepo) createLowLevelInterface(clientType wgtypes.ClientType, id domain.InterfaceIdentifier) error {
	var linkType = "wireguard"
	if clientType == wgtypes.AmneziaClient {
		linkType = "amneziawg"
	}

	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: string(id),
		},
		LinkType: linkType,
	}
	err := r.nl.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("link add failed: %w", err)
	}

	return nil
}

func (r *WgRepo) updateLowLevelInterface(pi *domain.PhysicalInterface) error {
	link, err := r.nl.LinkByName(string(pi.Identifier))
	if err != nil {
		return err
	}
	if pi.Mtu != 0 {
		if err := r.nl.LinkSetMTU(link, pi.Mtu); err != nil {
			return fmt.Errorf("mtu error: %w", err)
		}
	}

	for _, addr := range pi.Addresses {
		err := r.nl.AddrReplace(link, addr.NetlinkAddr())
		if err != nil {
			return fmt.Errorf("failed to set ip %s: %w", addr.String(), err)
		}
	}

	// Remove unwanted IP addresses
	rawAddresses, err := r.nl.AddrList(link)
	if err != nil {
		return fmt.Errorf("failed to fetch interface ips: %w", err)
	}
	for _, rawAddr := range rawAddresses {
		netlinkAddr := domain.CidrFromNetlinkAddr(rawAddr)
		remove := true
		for _, addr := range pi.Addresses {
			if addr == netlinkAddr {
				remove = false
				break
			}
		}

		if !remove {
			continue
		}

		err := r.nl.AddrDel(link, &rawAddr)
		if err != nil {
			return fmt.Errorf("failed to remove deprecated ip %s: %w", netlinkAddr.String(), err)
		}
	}

	// Update link state
	if pi.DeviceUp {
		if err := r.nl.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to bring up device: %w", err)
		}
	} else {
		if err := r.nl.LinkSetDown(link); err != nil {
			return fmt.Errorf("failed to bring down device: %w", err)
		}
	}

	return nil
}

func (r *WgRepo) updateWireGuardInterface(pi *domain.PhysicalInterface) error {
	pKey, err := wgtypes.NewKey(pi.KeyPair.GetPrivateKeyBytes())
	if err != nil {
		return err
	}

	var fwMark *int
	if pi.FirewallMark != 0 {
		intFwMark := int(pi.FirewallMark)
		fwMark = &intFwMark
	}

	config := wgtypes.Config{
		PrivateKey:   &pKey,
		ListenPort:   &pi.ListenPort,
		FirewallMark: fwMark,
		ReplacePeers: false,
	}

	if pi.HasAdvancedSecurity() {
		advSec := pi.AdvancedSecurity
		config.AdvancedSecurityConfig.JunkPacketCount = &advSec.JunkPacketCount
		config.AdvancedSecurityConfig.JunkPacketMinSize = &advSec.JunkPacketMinSize
		config.AdvancedSecurityConfig.JunkPacketMaxSize = &advSec.JunkPacketMaxSize

		config.AdvancedSecurityConfig.InitPacketJunkSize = &advSec.InitPacketJunkSize
		config.AdvancedSecurityConfig.ResponsePacketJunkSize = &advSec.ResponsePacketJunkSize
		config.AdvancedSecurityConfig.CookieReplyPacketJunkSize = &advSec.CookieReplyPacketJunkSize
		config.AdvancedSecurityConfig.TransportPacketJunkSize = &advSec.TransportPacketJunkSize

		config.AdvancedSecurityConfig.InitPacketMagicHeader = &advSec.InitPacketMagicHeader
		config.AdvancedSecurityConfig.ResponsePacketMagicHeader = &advSec.ResponsePacketMagicHeader
		config.AdvancedSecurityConfig.UnderloadPacketMagicHeader = &advSec.UnderloadPacketMagicHeader
		config.AdvancedSecurityConfig.TransportPacketMagicHeader = &advSec.TransportPacketMagicHeader

		config.AdvancedSecurityConfig.FirstSpecialJunkPacket = advSec.FirstSpecialJunkPacket
		config.AdvancedSecurityConfig.SecondSpecialJunkPacket = advSec.SecondSpecialJunkPacket
		config.AdvancedSecurityConfig.ThirdSpecialJunkPacket = advSec.ThirdSpecialJunkPacket
		config.AdvancedSecurityConfig.FourthSpecialJunkPacket = advSec.FourthSpecialJunkPacket
		config.AdvancedSecurityConfig.FifthSpecialJunkPacket = advSec.FifthSpecialJunkPacket
	}

	client := r.Clients[string(pi.Identifier)]
	if client == nil {
		return fmt.Errorf("nullable client for %s", pi.Identifier)
	}

	err = client.ConfigureDevice(string(pi.Identifier), config)
	if err != nil {
		return err
	}

	return nil
}

// DeleteInterface deletes the interface with the given id.
// If the requested interface is found, no error is returned.
func (r *WgRepo) DeleteInterface(_ context.Context, id domain.InterfaceIdentifier) error {
	if err := r.deleteLowLevelInterface(id); err != nil {
		return err
	}

	return nil
}

func (r *WgRepo) deleteLowLevelInterface(id domain.InterfaceIdentifier) error {
	link, err := r.nl.LinkByName(string(id))
	if err != nil {
		var linkNotFoundError netlink.LinkNotFoundError
		if errors.As(err, &linkNotFoundError) {
			return nil // ignore not found error
		}
		return fmt.Errorf("unable to find low level interface: %w", err)
	}

	err = r.nl.LinkDel(link)
	if err != nil {
		return fmt.Errorf("failed to delete low level interface: %w", err)
	}

	return nil
}

// SavePeer updates the peer with the given id.
// If no existing peer is found, a new peer is created.
func (r *WgRepo) SavePeer(
	_ context.Context,
	deviceId domain.InterfaceIdentifier,
	id domain.PeerIdentifier,
	updateFunc func(pp *domain.PhysicalPeer) (*domain.PhysicalPeer, error),
) error {
	physicalPeer, err := r.getOrCreatePeer(deviceId, id)
	if err != nil {
		return err
	}

	physicalPeer, err = updateFunc(physicalPeer)
	if err != nil {
		return err
	}

	if err := r.updatePeer(deviceId, physicalPeer); err != nil {
		return err
	}

	return nil
}

func (r *WgRepo) getOrCreatePeer(deviceId domain.InterfaceIdentifier, id domain.PeerIdentifier) (
	*domain.PhysicalPeer,
	error,
) {
	peer, err := r.getPeer(deviceId, id)
	if err == nil {
		return peer, nil // peer exists
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("peer error: %w", err) // unknown error
	}

	// create new peer
	client := r.Clients[string(deviceId)]
	if client == nil {
		return nil, fmt.Errorf("nullable client for %s", deviceId)
	}

	err = client.ConfigureDevice(string(deviceId), wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: id.ToPublicKey(),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("peer create error for %s: %w", id.ToPublicKey(), err)
	}

	peer, err = r.getPeer(deviceId, id)
	if err != nil {
		return nil, fmt.Errorf("peer error after create: %w", err)
	}
	return peer, nil
}

func (r *WgRepo) getPeer(deviceId domain.InterfaceIdentifier, id domain.PeerIdentifier) (*domain.PhysicalPeer, error) {
	if !id.IsPublicKey() {
		return nil, errors.New("invalid public key")
	}

	client := r.Clients[string(deviceId)]
	if client == nil {
		return nil, fmt.Errorf("nullable client for %s", deviceId)
	}

	device, err := client.Device(string(deviceId))
	if err != nil {
		return nil, err
	}

	publicKey := id.ToPublicKey()
	for _, peer := range device.Peers {
		if peer.PublicKey != publicKey {
			continue
		}

		peerModel, err := r.convertWireGuardPeer(&peer)
		return &peerModel, err
	}

	return nil, os.ErrNotExist
}

func (r *WgRepo) updatePeer(deviceId domain.InterfaceIdentifier, pp *domain.PhysicalPeer) error {
	cfg := wgtypes.PeerConfig{
		PublicKey:                   pp.GetPublicKey(),
		Remove:                      false,
		UpdateOnly:                  true,
		PresharedKey:                pp.GetPresharedKey(),
		Endpoint:                    pp.GetEndpointAddress(),
		PersistentKeepaliveInterval: pp.GetPersistentKeepaliveTime(),
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  pp.GetAllowedIPs(),
	}

	client := r.Clients[string(deviceId)]
	if client == nil {
		return fmt.Errorf("nullable client for %s", deviceId)
	}

	err := client.ConfigureDevice(string(deviceId), wgtypes.Config{ReplacePeers: false, Peers: []wgtypes.PeerConfig{cfg}})
	if err != nil {
		return err
	}

	return nil
}

// DeletePeer deletes the peer with the given id.
// If the requested interface or peer is found, no error is returned.
func (r *WgRepo) DeletePeer(_ context.Context, deviceId domain.InterfaceIdentifier, id domain.PeerIdentifier) error {
	if !id.IsPublicKey() {
		return errors.New("invalid public key")
	}

	err := r.deletePeer(deviceId, id)
	if err != nil {
		return err
	}

	return nil
}

func (r *WgRepo) deletePeer(deviceId domain.InterfaceIdentifier, id domain.PeerIdentifier) error {
	cfg := wgtypes.PeerConfig{
		PublicKey: id.ToPublicKey(),
		Remove:    true,
	}

	client := r.Clients[string(deviceId)]
	if client == nil {
		return fmt.Errorf("nullable client for %s", deviceId)
	}

	err := client.ConfigureDevice(string(deviceId), wgtypes.Config{ReplacePeers: false, Peers: []wgtypes.PeerConfig{cfg}})
	if err != nil {
		return err
	}

	return nil
}

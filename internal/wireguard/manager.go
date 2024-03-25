package wireguard

import (
	"sync"

	"github.com/danpashin/wgctrl"
	"github.com/danpashin/wgctrl/wgtypes"
	"github.com/pkg/errors"
)

// Manager offers a synchronized management interface to the real WireGuard interface.
type Manager struct {
	Cfg       *Config
	wgDevices map[string]*wgctrl.Client
	mux       sync.RWMutex
}

func (m *Manager) Init() error {
	m.wgDevices = make(map[string]*wgctrl.Client)

	clientTypes := []wgtypes.ClientType{
		wgtypes.NativeClient,
		wgtypes.AmneziaClient,
	}

	for _, clientType := range clientTypes {
		// Error is ignored here 'cause interface may not exist
		client, _ := wgctrl.New(clientType)

		// Try to cache all interfaces names with this client
		if client != nil {
			devices, err := client.Devices()
			if err != nil {
				return errors.Wrap(err, "could not get WireGuard device")
			}

			for _, device := range devices {
				m.wgDevices[device.Name] = client
			}
		}
	}

	if len(m.wgDevices) == 0 {
		return errors.Errorf("Couldn't find any suitable WG interfaces. Tried all with no success.")
	}

	return nil
}

func (m *Manager) IsDeviceSupportsAmnezia(device string) bool {
	client := m.wgDevices[device]
	return client.Type() == wgtypes.AmneziaClient
}

func (m *Manager) GetDeviceInfo(device string) (*wgtypes.Device, error) {
	client := m.wgDevices[device]
	if client == nil {
		return nil, errors.Errorf("could not get WireGuard device %s", device)
	}

	dev, err := client.Device(device)
	if err != nil {
		return nil, errors.Wrap(err, "could not get WireGuard device")
	}

	return dev, nil
}

func (m *Manager) GetPeerList(device string) ([]wgtypes.Peer, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()

	client := m.wgDevices[device]
	if client == nil {
		return nil, errors.Errorf("could not get WireGuard device %s", device)
	}

	dev, err := client.Device(device)
	if err != nil {
		return nil, errors.Wrap(err, "could not get WireGuard device")
	}

	return dev.Peers, nil
}

func (m *Manager) GetPeer(device string, pubKey string) (*wgtypes.Peer, error) {
	m.mux.RLock()
	defer m.mux.RUnlock()

	publicKey, err := wgtypes.ParseKey(pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "invalid public key")
	}

	peers, err := m.GetPeerList(device)
	if err != nil {
		return nil, errors.Wrap(err, "could not get WireGuard peers")
	}

	for _, peer := range peers {
		if peer.PublicKey == publicKey {
			return &peer, nil
		}
	}

	return nil, errors.Errorf("could not find WireGuard peer: %s", pubKey)
}

func (m *Manager) AddPeer(device string, cfg wgtypes.PeerConfig) error {
	m.mux.Lock()
	defer m.mux.Unlock()

	client := m.wgDevices[device]
	if client == nil {
		return errors.Errorf("could not get WireGuard device %s", device)
	}

	err := client.ConfigureDevice(device, wgtypes.Config{Peers: []wgtypes.PeerConfig{cfg}})
	if err != nil {
		return errors.Wrap(err, "could not configure WireGuard device")
	}

	return nil
}

func (m *Manager) UpdatePeer(device string, cfg wgtypes.PeerConfig) error {
	m.mux.Lock()
	defer m.mux.Unlock()

	client := m.wgDevices[device]
	if client == nil {
		return errors.Errorf("could not get WireGuard device %s", device)
	}

	cfg.UpdateOnly = true
	err := client.ConfigureDevice(device, wgtypes.Config{Peers: []wgtypes.PeerConfig{cfg}})
	if err != nil {
		return errors.Wrap(err, "could not configure WireGuard device")
	}

	return nil
}

func (m *Manager) RemovePeer(device string, pubKey string) error {
	m.mux.Lock()
	defer m.mux.Unlock()

	publicKey, err := wgtypes.ParseKey(pubKey)
	if err != nil {
		return errors.Wrap(err, "invalid public key")
	}

	peer := wgtypes.PeerConfig{
		PublicKey: publicKey,
		Remove:    true,
	}

	client := m.wgDevices[device]
	if client == nil {
		return errors.Errorf("could not get WireGuard device %s", device)
	}

	err = client.ConfigureDevice(device, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}})
	if err != nil {
		return errors.Wrap(err, "could not configure WireGuard device")
	}

	return nil
}

func (m *Manager) UpdateDevice(device string, cfg wgtypes.Config) error {
	client := m.wgDevices[device]
	if client == nil {
		return errors.Errorf("could not get WireGuard device %s", device)
	}

	return client.ConfigureDevice(device, cfg)
}

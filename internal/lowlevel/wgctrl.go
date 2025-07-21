package lowlevel

import (
	"io"

	"github.com/danpashin/wgctrl/wgtypes"
)

// A WireGuardClient is a type which can control a WireGuard device.
type WireGuardClient interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	Type() wgtypes.ClientType
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}

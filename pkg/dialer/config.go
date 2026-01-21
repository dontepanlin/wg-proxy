package dialer

import (
	"encoding/base64"
	"errors"
	"fmt"

	_ "gopkg.in/yaml.v3"
)

type Interface struct {
	Address    string   `yaml:"address"`
	PrivateKey string   `yaml:"private_key"`
	Dns        []string `yaml:"dns"`
}

type Peer struct {
	PublicKey    string `yaml:"public_key"`
	PresharedKey string `yaml:"preshared_key"` // ← NEW
	Endpoint     string `yaml:"endpoint"`
	AllowedIP    string `yaml:"allowedip"`
	KeepAlive    int    `yaml:"keep_alive"`
}

func base64KeyToHex(in string) (string, error) {
	out, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return "", errors.Join(fmt.Errorf("Invalid base64: %s", in), err)
	}

	return fmt.Sprintf("%x", out), nil
}

func (p *Peer) toIpcString() (string, error) {
	pubKey, err := base64KeyToHex(p.PublicKey)
	if err != nil {
		return "", err
	}

	out := fmt.Sprintf(
		"public_key=%s\nallowed_ip=%s\nendpoint=%s\n",
		pubKey,
		p.AllowedIP,
		p.Endpoint,
	)

	// 🔐 Add preshared key if present
	if p.PresharedKey != "" {
		psk, err := base64KeyToHex(p.PresharedKey)
		if err != nil {
			return "", err
		}
		out += fmt.Sprintf("preshared_key=%s\n", psk)
	}

	if p.KeepAlive > 0 {
		out += fmt.Sprintf(
			"persistent_keepalive_interval=%d\n",
			p.KeepAlive,
		)
	}

	return out, nil
}

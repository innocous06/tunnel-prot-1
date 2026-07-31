package config

import (
	"encoding/json"
	"os"
)

// ServerProfile represents a single target server for the client to connect to.
// All fields are dynamic — nothing is hardcoded in the binary.
type ServerProfile struct {
	Name          string `json:"name"`
	Hostname      string `json:"hostname"`
	Port          int    `json:"port"`
	RegionLabel   string `json:"region_label"`
	TunClientAddr string `json:"tun_client_addr"` // e.g. "10.66.0.2/24"
}

// ClientConfig is the fully dynamic client configuration.
// Load it from a JSON file; change any field by editing the file.
type ClientConfig struct {
	Profiles   []ServerProfile `json:"profiles"`
	ClientCert string          `json:"client_cert"` // path to device cert PEM
	ClientKey  string          `json:"client_key"`  // path to device key PEM
	CACert     string          `json:"ca_cert"`     // path to private CA cert PEM
}

// ServerConfig is the fully dynamic server daemon configuration.
type ServerConfig struct {
	ListenUDP      string `json:"listen_udp"`       // e.g. ":443"
	ListenTCP      string `json:"listen_tcp"`       // e.g. ":443"
	TunAddress     string `json:"tun_address"`      // e.g. "10.66.0.1/24"
	TunSubnet      string `json:"tun_subnet"`       // e.g. "10.66.0.0/24" for NAT rule
	ServerCertFile string `json:"server_cert_file"` // path to cert PEM
	ServerKeyFile  string `json:"server_key_file"`  // path to key PEM
	CACert         string `json:"ca_cert"`          // path to CA cert PEM (to verify clients)
}

// LoadClientConfig reads and parses a client config JSON file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ClientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadServerConfig reads and parses a server config JSON file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

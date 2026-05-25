// Package config loads static bootstrap settings for wafportal. Runtime data
// (protected sites, custom rules) lives in the database and is managed via the
// admin API, not here.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Proxy    ProxyConfig    `yaml:"proxy"`
	Admin    AdminConfig    `yaml:"admin"`
	TLS      TLSConfig      `yaml:"tls"`
	Database DatabaseConfig `yaml:"database"`
}

type ProxyConfig struct {
	// HTTPAddr serves ACME HTTP-01 challenges and redirects to HTTPS for TLS
	// sites; it also serves plaintext traffic for sites with TLS disabled.
	HTTPAddr string `yaml:"http_addr"`
	// HTTPSAddr serves TLS traffic. Leave empty to disable HTTPS (dev only).
	HTTPSAddr string `yaml:"https_addr"`
}

type AdminConfig struct {
	// Addr is the listen address for the control-plane API and SPA. Bind this
	// to localhost (or behind a VPN) in production; it is unauthenticated in v1.
	Addr string `yaml:"addr"`
}

type TLSConfig struct {
	// Email is registered with Let's Encrypt for autocert sites.
	Email string `yaml:"email"`
	// CacheDir stores ACME-issued certificates so they survive restarts.
	CacheDir string `yaml:"cache_dir"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

func Default() Config {
	return Config{
		Proxy:    ProxyConfig{HTTPAddr: ":80", HTTPSAddr: ":443"},
		Admin:    AdminConfig{Addr: "127.0.0.1:9090"},
		TLS:      TLSConfig{CacheDir: "./certs"},
		Database: DatabaseConfig{Path: "./wafportal.db"},
	}
}

// Load reads a YAML config file, falling back to defaults for any unset field.
// A missing file is not an error: defaults are returned so the binary runs
// out of the box.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %q: %w", path, err)
	}
	return cfg, nil
}

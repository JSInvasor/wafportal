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
	Proxy     ProxyConfig     `yaml:"proxy"`
	Admin     AdminConfig     `yaml:"admin"`
	TLS       TLSConfig       `yaml:"tls"`
	Database  DatabaseConfig  `yaml:"database"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

// RateLimitConfig configures per-client L7 flood protection. It does not defend
// against volumetric (L3/L4) DDoS, which must be absorbed upstream.
type RateLimitConfig struct {
	Enabled           bool    `yaml:"enabled"`
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
	// TrustForwardedHeader makes the limiter read the client IP from a proxy
	// header (e.g. behind Cloudflare or another reverse proxy). Only enable it
	// when a trusted proxy sits in front, or clients can spoof the header.
	TrustForwardedHeader bool   `yaml:"trust_forwarded_header"`
	ForwardedHeader      string `yaml:"forwarded_header"`
}

type ProxyConfig struct {
	// HTTPAddr serves ACME HTTP-01 challenges and redirects to HTTPS for TLS
	// sites; it also serves plaintext traffic for sites with TLS disabled.
	HTTPAddr string `yaml:"http_addr"`
	// HTTPSAddr serves TLS traffic. Leave empty to disable HTTPS (dev only).
	HTTPSAddr string `yaml:"https_addr"`
}

type AdminConfig struct {
	// Addr is the listen address for the control-plane API and SPA.
	Addr string `yaml:"addr"`
	// Username for the portal admin account (defaults to "admin").
	Username string `yaml:"username"`
	// Password bootstraps the admin account. Prefer the WAFPORTAL_ADMIN_PASSWORD
	// environment variable over storing it here. If neither is set, a random
	// password is generated and printed to the log on first run.
	Password string `yaml:"password"`
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
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 20,
			Burst:             40,
			ForwardedHeader:   "X-Forwarded-For",
		},
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

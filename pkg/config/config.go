// Package config loads the low-level runtime settings (listen address,
// database connection, file paths) from a JSON file. Application data such as
// rules, groups and users lives in the database, not here.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	ListenAddr    string `json:"listen_addr"`
	BlockPagePath string `json:"block_page_path"`
	LogLevel      string `json:"log_level"`
	// Timezone is the IANA zone rule schedules are evaluated in, e.g.
	// "Europe/Amsterdam", or "Local" for the server's own zone.
	Timezone string `json:"timezone"`
	// RuleRefreshInterval is how often rules are re-read from the database
	// (a Go duration such as "30s"); edits take effect within this time.
	RuleRefreshInterval string   `json:"rule_refresh_interval"`
	Database            Database `json:"database"`
	TLS                 TLS      `json:"tls"`
}

type Database struct {
	URL string `json:"url"`
}

type TLS struct {
	CACertPath string `json:"ca_cert_path"`
	CAKeyPath  string `json:"ca_key_path"`
}

// Default returns the settings used for any field omitted from the file.
func Default() Config {
	return Config{
		ListenAddr:          ":8080",
		BlockPagePath:       "blockpage/blockpage.html",
		LogLevel:            "info",
		Timezone:            "Local",
		RuleRefreshInterval: "30s",
		Database: Database{
			URL: "postgres://localhost:5432/canopy_filter?sslmode=disable",
		},
		TLS: TLS{
			CACertPath: "certs/ca.crt",
			CAKeyPath:  "certs/ca.key",
		},
	}
}

// Load reads and validates the JSON config at path. Omitted fields keep their
// defaults; unknown fields are rejected so typos don't silently go unnoticed.
func Load(path string) (Config, error) {
	cfg := Default()

	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return cfg, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// Location returns the timezone rule schedules are evaluated in.
func (c Config) Location() (*time.Location, error) {
	if c.Timezone == "" {
		return nil, fmt.Errorf("timezone must not be empty (use \"Local\" for the server's zone)")
	}
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return nil, fmt.Errorf("timezone %q is not a valid IANA zone: %w", c.Timezone, err)
	}
	return loc, nil
}

// RefreshInterval returns how often rules are re-read from the database.
func (c Config) RefreshInterval() (time.Duration, error) {
	d, err := time.ParseDuration(c.RuleRefreshInterval)
	if err != nil {
		return 0, fmt.Errorf("rule_refresh_interval %q is not a valid duration: %w", c.RuleRefreshInterval, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("rule_refresh_interval must be positive (got %s)", c.RuleRefreshInterval)
	}
	return d, nil
}

func (c Config) validate() error {
	if _, err := c.Location(); err != nil {
		return err
	}
	if _, err := c.RefreshInterval(); err != nil {
		return err
	}
	switch {
	case c.ListenAddr == "":
		return fmt.Errorf("listen_addr must not be empty")
	case c.Database.URL == "":
		return fmt.Errorf("database.url must not be empty")
	case c.TLS.CACertPath == "" || c.TLS.CAKeyPath == "":
		return fmt.Errorf("tls.ca_cert_path and tls.ca_key_path must not be empty")
	case c.BlockPagePath == "":
		return fmt.Errorf("block_page_path must not be empty")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be one of debug, info, warn, error (got %q)", c.LogLevel)
	}
	return nil
}

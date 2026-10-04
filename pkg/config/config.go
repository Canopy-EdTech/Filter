// Package config loads the low-level runtime settings (listen address,
// database connection, file paths) from a JSON file. Application data such as
// rules, groups and users lives in the database, not here.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	ListenAddr    string   `json:"listen_addr"`
	BlockPagePath string   `json:"block_page_path"`
	LogLevel      string   `json:"log_level"`
	Database      Database `json:"database"`
	TLS           TLS      `json:"tls"`
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
		ListenAddr:    ":8080",
		BlockPagePath: "blockpage/blockpage.html",
		LogLevel:      "info",
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

func (c Config) validate() error {
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

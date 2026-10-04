package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "time/tzdata"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFullConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, `{
		"listen_addr": ":9090",
		"block_page_path": "page.html",
		"log_level": "debug",
		"timezone": "Europe/Amsterdam",
		"rule_refresh_interval": "2m",
		"database": {"url": "postgres://u:p@db:5432/x"},
		"tls": {"ca_cert_path": "a.crt", "ca_key_path": "a.key"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		ListenAddr:          ":9090",
		BlockPagePath:       "page.html",
		LogLevel:            "debug",
		Timezone:            "Europe/Amsterdam",
		RuleRefreshInterval: "2m",
		Database:            Database{URL: "postgres://u:p@db:5432/x"},
		TLS:                 TLS{CACertPath: "a.crt", CAKeyPath: "a.key"},
	}
	if cfg != want {
		t.Fatalf("got %+v, want %+v", cfg, want)
	}
}

func TestLoadAppliesDefaultsForOmittedFields(t *testing.T) {
	cfg, err := Load(writeConfig(t, `{"listen_addr": ":1234"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	want.ListenAddr = ":1234"
	if cfg != want {
		t.Fatalf("got %+v, want %+v", cfg, want)
	}
}

func TestLoadPartialNestedObjectKeepsOtherDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, `{"tls": {"ca_cert_path": "only.crt"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.CACertPath != "only.crt" || cfg.TLS.CAKeyPath != Default().TLS.CAKeyPath {
		t.Fatalf("got %+v", cfg.TLS)
	}
}

func TestLoadEmptyObjectIsDefault(t *testing.T) {
	cfg, err := Load(writeConfig(t, `{}`))
	if err != nil || cfg != Default() {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{"unknown field", `{"listen_adr": ":1"}`, "unknown field"},
		{"unknown nested field", `{"database": {"uri": "x"}}`, "unknown field"},
		{"malformed json", `{`, "parse config"},
		{"wrong type", `{"listen_addr": 8080}`, "parse config"},
		{"empty listen_addr", `{"listen_addr": ""}`, "listen_addr"},
		{"empty database url", `{"database": {"url": ""}}`, "database.url"},
		{"empty ca cert", `{"tls": {"ca_cert_path": ""}}`, "tls."},
		{"empty ca key", `{"tls": {"ca_key_path": ""}}`, "tls."},
		{"empty block page", `{"block_page_path": ""}`, "block_page_path"},
		{"bad log level", `{"log_level": "verbose"}`, "log_level"},
		{"bad timezone", `{"timezone": "Mars/Olympus"}`, "timezone"},
		{"empty timezone", `{"timezone": ""}`, "timezone"},
		{"bad refresh interval", `{"rule_refresh_interval": "soon"}`, "rule_refresh_interval"},
		{"zero refresh interval", `{"rule_refresh_interval": "0s"}`, "must be positive"},
		{"negative refresh interval", `{"rule_refresh_interval": "-5s"}`, "must be positive"},
		{"refresh interval needs a unit", `{"rule_refresh_interval": "30"}`, "rule_refresh_interval"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.content))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil || !strings.Contains(err.Error(), "open config") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadAcceptsEveryLogLevel(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		if _, err := Load(writeConfig(t, `{"log_level": "`+level+`"}`)); err != nil {
			t.Errorf("level %q rejected: %v", level, err)
		}
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	if _, err := Load("../../config.example.json"); err != nil {
		t.Fatalf("config.example.json: %v", err)
	}
}

func TestLocationAndRefreshInterval(t *testing.T) {
	cfg, err := Load(writeConfig(t, `{"timezone": "Europe/Amsterdam", "rule_refresh_interval": "1m30s"}`))
	if err != nil {
		t.Fatal(err)
	}
	loc, err := cfg.Location()
	if err != nil || loc.String() != "Europe/Amsterdam" {
		t.Fatalf("location = %v, %v", loc, err)
	}
	d, err := cfg.RefreshInterval()
	if err != nil || d != 90*time.Second {
		t.Fatalf("interval = %v, %v", d, err)
	}

	def := Default()
	if loc, err := def.Location(); err != nil || loc != time.Local {
		t.Fatalf("default location = %v, %v; want the local zone", loc, err)
	}
	if d, _ := def.RefreshInterval(); d != 30*time.Second {
		t.Fatalf("default interval = %v", d)
	}
}

package main

import (
	"crypto/tls"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
	_ "time/tzdata" // embed the zone database so timezone names work in minimal containers

	"github.com/Canopy-EdTech/Filter/pkg/config"
	"github.com/Canopy-EdTech/Filter/pkg/filter"
	"github.com/Canopy-EdTech/Filter/pkg/proxy"
	"github.com/elazarl/goproxy"
	_ "github.com/lib/pq"
)

func main() {
	configPath := flag.String("config", "config.json", "path to the JSON config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config (copy config.example.json to config.json): %v\n", err)
		os.Exit(1)
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid log level: %v\n", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	db, err := sql.Open("postgres", cfg.Database.URL)
	if err != nil {
		logger.Error("Failed to open database connection", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		logger.Error("Failed to reach database", "error", err)
		os.Exit(1)
	}

	loc, err := cfg.Location()
	if err != nil {
		logger.Error("Invalid timezone", "error", err)
		os.Exit(1)
	}
	refresh, err := cfg.RefreshInterval()
	if err != nil {
		logger.Error("Invalid rule refresh interval", "error", err)
		os.Exit(1)
	}
	logger.Info("Rule schedules use timezone", "timezone", loc.String(), "rule_refresh_interval", refresh.String(), "local_time", time.Now().In(loc).Format(time.RFC3339))

	blockingEngine := filter.NewEngine(db, filter.WithLocation(loc), filter.WithRefreshInterval(refresh), filter.WithLogger(logger))

	ca, err := tls.LoadX509KeyPair(cfg.TLS.CACertPath, cfg.TLS.CAKeyPath)
	if err != nil {
		logger.Error("Failed to load MITM CA; run utils/generatecerts.sh first", "error", err)
		os.Exit(1)
	}
	mitmConnect := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&ca),
	}

	logger.Info("Starting proxy...")

	server, err := proxy.NewServer(cfg.ListenAddr, blockingEngine, logger, mitmConnect, cfg.BlockPagePath)
	if err != nil {
		logger.Error("Failed to load block page", "error", err)
		os.Exit(1)
	}

	logger.Info("Proxy online and listening", "addr", cfg.ListenAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("Proxy server failed to run", "error", err)
	}
}

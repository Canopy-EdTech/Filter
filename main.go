package main

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"

	"github.com/Canopy-EdTech/Filter/pkg/filter"
	"github.com/Canopy-EdTech/Filter/pkg/proxy"
	"github.com/elazarl/goproxy"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	blockingEngine := filter.NewEngine()

	ca, err := tls.LoadX509KeyPair("certs/ca.crt", "certs/ca.key")
	if err != nil {
		logger.Error("Failed to load MITM CA; run utils/generatecerts.sh first", "error", err)
		os.Exit(1)
	}
	mitmConnect := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&ca),
	}

	logger.Info("Starting proxy...")

	server := proxy.NewServer(":8080", blockingEngine, logger, mitmConnect)

	logger.Info("Proxy online and listening", "addr", ":8080")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("Proxy server failed to run", "error", err)
	}
}

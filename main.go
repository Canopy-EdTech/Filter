package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/Canopy-EdTech/Filter/pkg/filter"
	"github.com/Canopy-EdTech/Filter/pkg/proxy"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	blockingEngine := filter.NewEngine()

	logger.Info("Starting proxy...")

	server := proxy.NewServer(":8080", blockingEngine, logger)

	logger.Info("Proxy online and listening", "addr", ":8080")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("Proxy server failed to run", "error", err)
	}
}

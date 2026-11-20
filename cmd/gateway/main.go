// Command gateway runs the API gateway from a configuration file.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/runsecure/go-api-gateway-firewall/gateway"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", envOr("GATEWAY_CONFIG", "gateway.yaml"), "path to JSON or YAML config")
	logLevel := flag.String("log-level", envOr("GATEWAY_LOG_LEVEL", "info"), "debug, info, warn or error")
	logFormat := flag.String("log-format", envOr("GATEWAY_LOG_FORMAT", "json"), "json or text")
	check := flag.Bool("check", false, "validate the config, compile schemas and exit")
	flag.Parse()

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		return err
	}
	hopts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler = slog.NewJSONHandler(os.Stdout, hopts)
	if *logFormat == "text" {
		h = slog.NewTextHandler(os.Stdout, hopts)
	}
	logger := slog.New(h)
	slog.SetDefault(logger)

	cfg, err := gateway.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	if err != nil {
		return err
	}
	if *check {
		fmt.Printf("config OK: %d routes\n", len(cfg.Routes))
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return gw.ListenAndServe(ctx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

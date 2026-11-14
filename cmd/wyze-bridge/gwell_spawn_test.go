package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/IDisposable/docker-wyze-bridge/internal/config"
)

func TestConfigureGwellProxyDisablesMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	cfg := &config.Config{GwellEnabled: true}
	configureGwellProxy(cfg, zerolog.Nop())

	if cfg.GwellEnabled {
		t.Fatal("GwellEnabled should be false when gwell-proxy is unavailable")
	}
	if cfg.GwellBinary != "" {
		t.Errorf("GwellBinary = %q, want empty", cfg.GwellBinary)
	}
}

func TestConfigureGwellProxyResolvesConfiguredBinary(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "gwell-proxy")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	cfg := &config.Config{
		GwellEnabled: true,
		GwellBinary:  "gwell-proxy",
	}
	configureGwellProxy(cfg, zerolog.Nop())

	if !cfg.GwellEnabled {
		t.Fatal("GwellEnabled should remain true when the binary is available")
	}
	if cfg.GwellBinary != binary {
		t.Errorf("GwellBinary = %q, want %q", cfg.GwellBinary, binary)
	}
}

func TestStartGwellProxyBeforeDiscovery(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	binary := filepath.Join(dir, "gwell-proxy")
	script := fmt.Sprintf("#!/bin/sh\n: > %q\n", marker)
	if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cfg := &config.Config{GwellEnabled: true, GwellBinary: binary}
	handle := startGwellProxyIfEnabled(ctx, cfg)
	if handle == nil {
		cancel()
		t.Fatal("proxy should start while camera discovery is pending")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("proxy binary was not started")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := handle.Stop(stopCtx); err != nil {
		t.Fatalf("stop gwell-proxy: %v", err)
	}
}

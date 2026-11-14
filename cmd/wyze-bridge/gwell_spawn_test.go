package main

import (
	"os"
	"path/filepath"
	"testing"

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

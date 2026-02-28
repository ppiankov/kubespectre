package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	content := `stale_days: 120
severity_min: high
format: json
timeout: 10m
trusted_registries:
  - gcr.io/my-project
  - us-docker.pkg.dev/my-project
exclude:
  namespaces:
    - kube-system
  labels:
    - app=legacy
`
	if err := os.WriteFile(filepath.Join(dir, ".kubespectre.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.StaleDays != 120 {
		t.Errorf("StaleDays = %d, want 120", cfg.StaleDays)
	}
	if cfg.SeverityMin != "high" {
		t.Errorf("SeverityMin = %q, want %q", cfg.SeverityMin, "high")
	}
	if cfg.Format != "json" {
		t.Errorf("Format = %q, want %q", cfg.Format, "json")
	}
	if cfg.Timeout != "10m" {
		t.Errorf("Timeout = %q, want %q", cfg.Timeout, "10m")
	}
	if len(cfg.TrustedRegistries) != 2 {
		t.Errorf("TrustedRegistries len = %d, want 2", len(cfg.TrustedRegistries))
	}
	if len(cfg.Exclude.Namespaces) != 1 {
		t.Errorf("Exclude.Namespaces len = %d, want 1", len(cfg.Exclude.Namespaces))
	}
	if len(cfg.Exclude.Labels) != 1 {
		t.Errorf("Exclude.Labels len = %d, want 1", len(cfg.Exclude.Labels))
	}
}

func TestLoadYMLExtension(t *testing.T) {
	dir := t.TempDir()
	content := `stale_days: 30
`
	if err := os.WriteFile(filepath.Join(dir, ".kubespectre.yml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.StaleDays != 30 {
		t.Errorf("StaleDays = %d, want 30", cfg.StaleDays)
	}
}

func TestLoadMissing(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.StaleDays != 0 {
		t.Errorf("StaleDays = %d, want 0 (zero value)", cfg.StaleDays)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".kubespectre.yaml"), []byte("{{invalid"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestTimeoutDuration(t *testing.T) {
	tests := []struct {
		timeout string
		want    time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"30s", 30 * time.Second},
		{"", 0},
		{"invalid", 0},
	}

	for _, tt := range tests {
		cfg := Config{Timeout: tt.timeout}
		got := cfg.TimeoutDuration()
		if got != tt.want {
			t.Errorf("TimeoutDuration(%q) = %v, want %v", tt.timeout, got, tt.want)
		}
	}
}

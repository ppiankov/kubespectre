package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds kubespectre configuration loaded from .kubespectre.yaml.
type Config struct {
	Namespace                       string   `yaml:"namespace"`
	StaleDays                       int      `yaml:"stale_days"`
	SeverityMin                     string   `yaml:"severity_min"`
	Format                          string   `yaml:"format"`
	Timeout                         string   `yaml:"timeout"`
	TrustedRegistries               []string `yaml:"trusted_registries"`
	DangerousCapabilities           []string `yaml:"dangerous_capabilities"`             // WO-35: overrides the built-in dangerous-capability list.
	ManagedSecretMarkers            []string `yaml:"managed_secret_markers"`             // WO-34: overrides the built-in controller-managed-secret annotation markers.
	DisableManagedSecretDownranking bool     `yaml:"disable_managed_secret_downranking"` // WO-34: opt back into uniform STALE_SECRET severity.
	Exclude                         Exclude  `yaml:"exclude"`
}

// Exclude defines resources to skip during auditing.
type Exclude struct {
	Namespaces []string `yaml:"namespaces"`
	Labels     []string `yaml:"labels"`
}

// TimeoutDuration parses the timeout string as a duration.
// WO-18: Invalid configured deadlines must fail instead of silently disabling protection.
func (c Config) TimeoutDuration() (time.Duration, error) {
	if c.Timeout == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 0, fmt.Errorf("parse timeout %q: %w", c.Timeout, err)
	}
	return d, nil
}

// Load searches for .kubespectre.yaml or .kubespectre.yml in the given directory
// and returns the parsed config. Returns an empty Config if no file is found.
func Load(dir string) (Config, error) {
	candidates := []string{
		filepath.Join(dir, ".kubespectre.yaml"),
		filepath.Join(dir, ".kubespectre.yml"),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return Config{}, fmt.Errorf("read config %s: %w", path, err)
		}

		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %s: %w", path, err)
		}
		return cfg, nil
	}

	return Config{}, nil
}

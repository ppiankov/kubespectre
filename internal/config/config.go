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
	Namespace         string   `yaml:"namespace"`
	StaleDays         int      `yaml:"stale_days"`
	SeverityMin       string   `yaml:"severity_min"`
	Format            string   `yaml:"format"`
	Timeout           string   `yaml:"timeout"`
	TrustedRegistries []string `yaml:"trusted_registries"`
	Exclude           Exclude  `yaml:"exclude"`
}

// Exclude defines resources to skip during auditing.
type Exclude struct {
	Namespaces []string `yaml:"namespaces"`
	Labels     []string `yaml:"labels"`
}

// TimeoutDuration parses the timeout string as a duration.
func (c Config) TimeoutDuration() time.Duration {
	if c.Timeout == "" {
		return 0
	}
	d, _ := time.ParseDuration(c.Timeout)
	return d
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

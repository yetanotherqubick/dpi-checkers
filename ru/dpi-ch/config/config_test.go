package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

func preserveConfigState(t *testing.T) {
	t.Helper()
	oldCfg := *_cfg
	oldPath := _path
	t.Cleanup(func() {
		*_cfg = oldCfg
		_path = oldPath
	})
}

func TestLoadDefaultConfig(t *testing.T) {
	preserveConfigState(t)

	if err := Load(CfgDefPath); err != nil {
		t.Fatalf("Load(%q): %v", CfgDefPath, err)
	}
	if _cfg.All.Format != "json" {
		t.Fatalf("got format %q, want json", _cfg.All.Format)
	}
	if _cfg.Checkers.Webhost.Workers != 8 {
		t.Fatalf("got webhost workers %d, want 8", _cfg.Checkers.Webhost.Workers)
	}
	if len(_cfg.Checkers.Webhost.Sections) == 0 {
		t.Fatal("default webhost sections are empty")
	}
}

func TestLoadUserConfigExcludesDefaultSections(t *testing.T) {
	preserveConfigState(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `
all:
  format: yaml
checkers:
  webhost:
    exclude-default-sections: true
    sections:
      - name: Test section
        desc: Local test section
        targets:
          - name: Test target
            filter: subnet("192.0.2.0/24")
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := Load(path); err != nil {
		t.Fatalf("Load(%q): %v", path, err)
	}

	if _cfg.All.Format != "yaml" {
		t.Fatalf("got format %q, want yaml", _cfg.All.Format)
	}
	if !_cfg.Checkers.Webhost.ExcludeDefaultSections {
		t.Fatal("exclude-default-sections is false")
	}
	if len(_cfg.Checkers.Webhost.Sections) != 1 {
		t.Fatalf("got %d webhost sections, want 1", len(_cfg.Checkers.Webhost.Sections))
	}
	if got := _cfg.Checkers.Webhost.Sections[0].Name; got != "Test section" {
		t.Fatalf("got section name %q, want %q", got, "Test section")
	}
}

func TestLoadUserConfigMergesDefaultSections(t *testing.T) {
	preserveConfigState(t)

	if err := Load(CfgDefPath); err != nil {
		t.Fatalf("Load defaults: %v", err)
	}
	defaultSections := slices.Clone(_cfg.Checkers.Webhost.Sections)

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `
checkers:
  webhost:
    sections:
      - name: Custom section
        targets: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := Load(path); err != nil {
		t.Fatalf("Load(%q): %v", path, err)
	}

	if len(_cfg.Checkers.Webhost.Sections) != len(defaultSections)+1 {
		t.Fatalf("got %d sections, want %d", len(_cfg.Checkers.Webhost.Sections), len(defaultSections)+1)
	}
	if !reflect.DeepEqual(_cfg.Checkers.Webhost.Sections[:len(defaultSections)], defaultSections) {
		t.Fatal("default sections were not preserved")
	}
	if got := _cfg.Checkers.Webhost.Sections[len(defaultSections)].Name; got != "Custom section" {
		t.Fatalf("got custom section %q, want %q", got, "Custom section")
	}
}

func TestLoadUserConfigOverridesValues(t *testing.T) {
	preserveConfigState(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `
all:
  format: yaml
  auto-exit: true
checkers:
  cidrwhitelist:
    timeout: 11s
  webhost:
    workers: 3
  dns:
    resolve:
      plain-opt:
        timeout: 7s
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := Load(path); err != nil {
		t.Fatalf("Load(%q): %v", path, err)
	}

	if _cfg.All.Format != "yaml" || !_cfg.All.AutoExit {
		t.Fatalf("unexpected all config: %+v", _cfg.All)
	}
	if _cfg.Checkers.CidrWhitelist.Timeout != 11*time.Second {
		t.Fatalf("got CIDR timeout %v, want 11s", _cfg.Checkers.CidrWhitelist.Timeout)
	}
	if _cfg.Checkers.Webhost.Workers != 3 {
		t.Fatalf("got webhost workers %d, want 3", _cfg.Checkers.Webhost.Workers)
	}
	if _cfg.Checkers.Dns.Resolve.PlainOpt.Timeout != 7*time.Second {
		t.Fatalf("got DNS timeout %v, want 7s", _cfg.Checkers.Dns.Resolve.PlainOpt.Timeout)
	}
}

func TestLoadMissingExplicitConfigFails(t *testing.T) {
	preserveConfigState(t)

	path := filepath.Join(t.TempDir(), "missing.yaml")
	if err := Load(path); err == nil {
		t.Fatal("expected missing explicit config to fail")
	}
}

func TestLoadInvalidConfigFails(t *testing.T) {
	preserveConfigState(t)

	path := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(path, []byte("checkers: ["), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := Load(path); err == nil {
		t.Fatal("expected invalid YAML to fail")
	}
}

func TestConfigPathForAbsoluteConfig(t *testing.T) {
	preserveConfigState(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("all:\n  format: yaml\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := Load(path); err != nil {
		t.Fatalf("Load(%q): %v", path, err)
	}

	got, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}
	want, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	if got != filepath.Clean(want) {
		t.Fatalf("got %q, want %q", got, filepath.Clean(want))
	}
}

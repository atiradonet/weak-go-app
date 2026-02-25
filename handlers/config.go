package handlers

import (
	"fmt"
	"io"
	"net/http"

	"gopkg.in/yaml.v2"
)

// AppConfig holds application settings loaded from a YAML body.
type AppConfig struct {
	Host   string `yaml:"host"`
	Port   int    `yaml:"port"`
	Debug  bool   `yaml:"debug"`
	DBUrl  string `yaml:"db_url"`
	APIKey string `yaml:"api_key"`
}

// ParseConfig reads a YAML body from the request and unmarshals it into
// AppConfig, then echoes the non-sensitive fields back to the caller.
//
// CVE-2022-28948 / CVE-2021-4235: gopkg.in/yaml.v2 < v2.4.0 panics on
// certain malformed YAML inputs (e.g. deeply nested aliases, merge keys),
// enabling remote denial-of-service with a single malicious request.
//
// CWE-20: Improper Input Validation — untrusted YAML is decoded directly
// with no size cap, content restrictions, or schema validation, making
// the application fully exposed to the library bugs listed above.
func ParseConfig(w http.ResponseWriter, r *http.Request) {
	// No maximum body size — an attacker can stream arbitrarily large payloads.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read error", http.StatusBadRequest)
		return
	}

	var cfg AppConfig
	// Untrusted body decoded directly; triggers CVE-2022-28948 on bad input.
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		// CWE-209: raw library error surfaced to the caller.
		http.Error(w, "YAML parse error: "+err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "Config loaded: host=%s port=%d debug=%v\n", cfg.Host, cfg.Port, cfg.Debug)
}

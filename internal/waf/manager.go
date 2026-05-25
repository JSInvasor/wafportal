// Package waf wraps the Coraza engine: it compiles the OWASP Core Rule Set
// plus operator-defined custom rules into ready-to-use engines, and provides
// the HTTP middleware that inspects traffic and records events.
package waf

import (
	"fmt"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"

	"github.com/jsinvasor/wafportal/internal/store"
)

// baseDirectives loads Coraza's recommended configuration and the full OWASP
// CRS from the embedded coreruleset filesystem. The SecRuleEngine mode is
// appended per build so the same ruleset can run in blocking or detection mode.
const baseDirectives = `
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
`

// Manager owns the compiled engines and rebuilds them when custom rules change.
// It is safe for concurrent use: Engine reads under an RLock while Reload swaps
// the engine map under a write lock.
type Manager struct {
	mu      sync.RWMutex
	engines map[store.WAFMode]coraza.WAF
}

func NewManager() *Manager {
	return &Manager{engines: map[store.WAFMode]coraza.WAF{}}
}

// Reload compiles fresh engines for blocking and detection modes from the CRS
// plus the supplied custom directives. On any compile error the existing
// engines are left untouched so a bad custom rule never takes the proxy down.
func (m *Manager) Reload(customDirectives []string) error {
	custom := strings.Join(customDirectives, "\n")

	on, err := build(custom, "On")
	if err != nil {
		return fmt.Errorf("build blocking engine: %w", err)
	}
	detect, err := build(custom, "DetectionOnly")
	if err != nil {
		return fmt.Errorf("build detection engine: %w", err)
	}

	m.mu.Lock()
	m.engines = map[store.WAFMode]coraza.WAF{
		store.WAFModeOn:        on,
		store.WAFModeDetection: detect,
	}
	m.mu.Unlock()
	return nil
}

func build(custom, engineMode string) (coraza.WAF, error) {
	directives := baseDirectives
	if strings.TrimSpace(custom) != "" {
		directives += "\n" + custom
	}
	// SecRuleEngine goes last so it overrides whatever the recommended config
	// or CRS setup selected.
	directives += "\nSecRuleEngine " + engineMode + "\n"

	return coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives(directives),
	)
}

// Engine returns the compiled engine for a site's mode, or nil when the mode is
// "off" or the manager has not been loaded yet.
func (m *Manager) Engine(mode store.WAFMode) coraza.WAF {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.engines[mode]
}

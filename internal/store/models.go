package store

import "time"

// WAFMode controls how the engine treats a site's traffic.
type WAFMode string

const (
	WAFModeOn        WAFMode = "on"        // inspect and block
	WAFModeDetection WAFMode = "detection" // inspect and log, never block
	WAFModeOff       WAFMode = "off"       // bypass the WAF entirely
)

// TLSMode controls how the proxy terminates TLS for a site.
type TLSMode string

const (
	TLSModeAuto   TLSMode = "auto"   // Let's Encrypt (ACME)
	TLSModeManual TLSMode = "manual" // operator-supplied cert/key files
	TLSModeOff    TLSMode = "off"    // plaintext HTTP only
)

// Site is a domain protected by the WAF and the upstream it proxies to.
type Site struct {
	ID          int64     `json:"id"`
	Domain      string    `json:"domain"`
	UpstreamURL string    `json:"upstream_url"`
	WAFMode     WAFMode   `json:"waf_mode"`
	TLSMode     TLSMode   `json:"tls_mode"`
	CertFile    string    `json:"cert_file,omitempty"`
	KeyFile     string    `json:"key_file,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CustomRule is an operator-defined SecLang directive applied globally, on top
// of the OWASP Core Rule Set.
type CustomRule struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Directive   string    `json:"directive"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Event records one request that triggered the WAF. A request that matches
// several rules produces a single event holding the aggregate decision.
type Event struct {
	ID           int64     `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	TxID         string    `json:"tx_id"`
	Domain       string    `json:"domain"`
	ClientIP     string    `json:"client_ip"`
	Method       string    `json:"method"`
	URI          string    `json:"uri"`
	Blocked      bool      `json:"blocked"`
	StatusCode   int       `json:"status_code"`
	RuleID       int       `json:"rule_id"`  // rule that caused the interruption, if any
	Message      string    `json:"message"`  // message of the top matched rule
	Severity     int       `json:"severity"` // lowest numeric severity = most severe
	AnomalyScore int       `json:"anomaly_score"`
	MatchedRules []int     `json:"matched_rules"`
}

// Stats is an aggregate view of recent WAF activity for the dashboard.
type Stats struct {
	TotalEvents   int64          `json:"total_events"`
	BlockedEvents int64          `json:"blocked_events"`
	TopRules      []RuleCount    `json:"top_rules"`
	TopClients    []ClientCount  `json:"top_clients"`
	Timeline      []TimelinePoint `json:"timeline"`
}

type RuleCount struct {
	RuleID  int    `json:"rule_id"`
	Message string `json:"message"`
	Count   int64  `json:"count"`
}

type ClientCount struct {
	ClientIP string `json:"client_ip"`
	Count    int64  `json:"count"`
}

type TimelinePoint struct {
	Bucket  time.Time `json:"bucket"`
	Total   int64     `json:"total"`
	Blocked int64     `json:"blocked"`
}

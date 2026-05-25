package waf

import (
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/jsinvasor/wafportal/internal/store"
)

// EventSink receives one event per request that matched at least one rule.
// Implementations must be non-blocking or buffered; the proxy calls this on the
// request path.
type EventSink func(*store.Event)

// Middleware inspects a request with the given engine, blocks it on
// interruption (blocking mode only), otherwise hands it to upstream. Every
// request that matches a rule is reported to sink. The engine must be non-nil;
// sites in "off" mode should bypass this middleware entirely.
func Middleware(engine coraza.WAF, upstream http.Handler, sink EventSink, domain string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := engine.NewTransaction()

		status := http.StatusOK
		blocked := false

		defer func() {
			tx.ProcessLogging()
			if e := buildEvent(tx, r, domain, blocked, status); e != nil {
				sink(e)
			}
			_ = tx.Close()
		}()

		if it, err := processRequestPhase(tx, r); err != nil {
			status = http.StatusBadGateway
			http.Error(w, "request processing error", status)
			return
		} else if it != nil {
			blocked = true
			status = statusFromInterruption(it)
			w.WriteHeader(status)
			return
		}

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		upstream.ServeHTTP(rec, r)
		status = rec.status

		// Response headers are inspected for audit/logging completeness. The
		// body has already started streaming to the client, so a phase-3
		// interruption cannot retroactively block it in v1.
		tx.ProcessResponseHeaders(rec.status, r.Proto)
	})
}

// processRequestPhase drives Coraza through connection, URI, header, and body
// inspection. It mirrors coraza/http.WrapHandler's request handling but lets
// the caller own the transaction so it can read MatchedRules afterwards.
func processRequestPhase(tx types.Transaction, r *http.Request) (*types.Interruption, error) {
	client, port := splitHostPort(r.RemoteAddr)
	tx.ProcessConnection(client, port, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)

	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}

	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			return nil, err
		}
		if it != nil {
			return it, nil
		}
		rbr, err := tx.RequestBodyReader()
		if err != nil {
			return nil, err
		}
		// Hand the buffered body (plus any bytes beyond Coraza's limit) back to
		// the upstream handler so the proxied request body is intact.
		r.Body = io.NopCloser(io.MultiReader(rbr, r.Body))
	}

	return tx.ProcessRequestBody()
}

var anomalyScoreRE = regexp.MustCompile(`Total Score:\s*(\d+)`)

// buildEvent summarizes a finished transaction into a storable event, or
// returns nil when nothing security-relevant happened. The CRS fires dozens of
// infrastructure rules (initialization, scoring, logging) on every request;
// those carry no severity and are filtered out. Only genuine detection rules
// (severity set, i.e. >= 0) — or an actual block — produce an event.
func buildEvent(tx types.Transaction, r *http.Request, domain string, blocked bool, status int) *store.Event {
	const unset = 99 // worse than any real severity (lower value = more severe)

	var matched []int
	bestSev := unset
	bestMsg := ""
	bestID := 0
	anomaly := 0

	for _, mr := range tx.MatchedRules() {
		// The CRS blocking rule reports the cumulative anomaly score in its
		// message even though it carries no severity of its own.
		if anomaly == 0 {
			if m := anomalyScoreRE.FindStringSubmatch(mr.Message()); m != nil {
				anomaly, _ = strconv.Atoi(m[1])
			}
		}

		sev := int(mr.Rule().Severity())
		if sev < 0 {
			continue // infrastructure / control rule, not a detection
		}
		if id := mr.Rule().ID(); id != 0 {
			matched = append(matched, id)
		}
		if sev < bestSev {
			bestSev = sev
			bestMsg = mr.Message()
			bestID = mr.Rule().ID()
		}
	}

	if !blocked && len(matched) == 0 {
		return nil
	}

	e := &store.Event{
		Timestamp:    time.Now().UTC(),
		TxID:         tx.ID(),
		Domain:       domain,
		ClientIP:     splitHost(r.RemoteAddr),
		Method:       r.Method,
		URI:          r.URL.RequestURI(),
		Blocked:      blocked,
		StatusCode:   status,
		RuleID:       bestID,
		Message:      bestMsg,
		AnomalyScore: anomaly,
		MatchedRules: matched,
	}
	if bestSev != unset {
		e.Severity = bestSev
	}
	// Fall back to the interruption when a block had no severity-bearing
	// detection rule (e.g. a custom deny rule without a severity).
	if e.RuleID == 0 {
		if it := tx.Interruption(); it != nil {
			e.RuleID = it.RuleID
		}
	}
	return e
}

func statusFromInterruption(it *types.Interruption) int {
	if it.Status > 0 {
		return it.Status
	}
	return http.StatusForbidden
}

// statusRecorder captures the upstream response status for event logging while
// passing all writes straight through to the real ResponseWriter.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func splitHostPort(addr string) (string, int) {
	idx := strings.LastIndexByte(addr, ':')
	if idx == -1 {
		return addr, 0
	}
	port, _ := strconv.Atoi(addr[idx+1:])
	return addr[:idx], port
}

func splitHost(addr string) string {
	h, _ := splitHostPort(addr)
	return h
}

// Package api is the control plane: a JSON REST API for managing protected
// sites and custom rules and for querying WAF events, plus serving the SPA.
package api

import (
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/jsinvasor/wafportal/internal/store"
)

// Server holds the dependencies shared by the API handlers. reload re-syncs the
// WAF engines and proxy routing table from the store; it is invoked after any
// mutation so changes take effect immediately.
type Server struct {
	store  *store.Store
	reload func() error
	spa    http.Handler
}

func NewServer(st *store.Store, reload func() error, spa http.Handler) *Server {
	return &Server{store: st, reload: reload, spa: spa}
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	r.Route("/api", func(r chi.Router) {
		r.Get("/health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, map[string]string{"status": "ok"}) })

		r.Get("/sites", s.listSites)
		r.Post("/sites", s.createSite)
		r.Get("/sites/{id}", s.getSite)
		r.Put("/sites/{id}", s.updateSite)
		r.Delete("/sites/{id}", s.deleteSite)

		r.Get("/rules", s.listRules)
		r.Post("/rules", s.createRule)
		r.Get("/rules/{id}", s.getRule)
		r.Put("/rules/{id}", s.updateRule)
		r.Delete("/rules/{id}", s.deleteRule)

		r.Get("/events", s.listEvents)
		r.Get("/stats", s.stats)
	})

	if s.spa != nil {
		r.Handle("/*", s.spa)
	}
	return r
}

// ---- Sites ----

func (s *Server) listSites(w http.ResponseWriter, _ *http.Request) {
	sites, err := s.store.ListSites()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, orEmpty(sites))
}

func (s *Server) getSite(w http.ResponseWriter, r *http.Request) {
	id := idParam(r)
	site, err := s.store.GetSite(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, site)
}

func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	var site store.Site
	if !readJSON(w, r, &site) {
		return
	}
	if msg := validateSite(&site); msg != "" {
		writeJSONErr(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.store.CreateSite(&site); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.applyReload()
	writeJSON(w, http.StatusCreated, site)
}

func (s *Server) updateSite(w http.ResponseWriter, r *http.Request) {
	var site store.Site
	if !readJSON(w, r, &site) {
		return
	}
	site.ID = idParam(r)
	if msg := validateSite(&site); msg != "" {
		writeJSONErr(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.store.UpdateSite(&site); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.applyReload()
	writeJSON(w, http.StatusOK, site)
}

func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSite(idParam(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.applyReload()
	w.WriteHeader(http.StatusNoContent)
}

// ---- Rules ----

func (s *Server) listRules(w http.ResponseWriter, _ *http.Request) {
	rules, err := s.store.ListRules()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, orEmpty(rules))
}

func (s *Server) getRule(w http.ResponseWriter, r *http.Request) {
	rule, err := s.store.GetRule(idParam(r))
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var rule store.CustomRule
	if !readJSON(w, r, &rule) {
		return
	}
	if rule.Name == "" || rule.Directive == "" {
		writeJSONErr(w, http.StatusBadRequest, "name and directive are required")
		return
	}
	if err := s.store.CreateRule(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.applyReloadErr(); err != nil {
		// Roll back the rule so a directive that fails to compile does not
		// stay in the store and break every future reload.
		_ = s.store.DeleteRule(rule.ID)
		writeJSONErr(w, http.StatusBadRequest, "rule rejected: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	var rule store.CustomRule
	if !readJSON(w, r, &rule) {
		return
	}
	rule.ID = idParam(r)
	if rule.Name == "" || rule.Directive == "" {
		writeJSONErr(w, http.StatusBadRequest, "name and directive are required")
		return
	}
	if err := s.store.UpdateRule(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.applyReloadErr(); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "rule rejected: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRule(idParam(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.applyReload()
	w.WriteHeader(http.StatusNoContent)
}

// ---- Events & stats ----

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{
		Domain:      q.Get("domain"),
		BlockedOnly: q.Get("blocked") == "true",
		Limit:       atoiDefault(q.Get("limit"), 100),
		Offset:      atoiDefault(q.Get("offset"), 0),
	}
	events, err := s.store.ListEvents(f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, orEmpty(events))
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	window := 24 * time.Hour
	if v := r.URL.Query().Get("window"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			window = d
		}
	}
	st, err := s.store.Stats(window)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// ---- helpers ----

func (s *Server) applyReload() {
	if err := s.applyReloadErr(); err != nil {
		log.Printf("api: reload failed: %v", err)
	}
}

func (s *Server) applyReloadErr() error {
	if s.reload == nil {
		return nil
	}
	return s.reload()
}

func validateSite(site *store.Site) string {
	if site.Domain == "" {
		return "domain is required"
	}
	if site.UpstreamURL == "" {
		return "upstream_url is required"
	}
	switch site.WAFMode {
	case store.WAFModeOn, store.WAFModeDetection, store.WAFModeOff:
	case "":
		site.WAFMode = store.WAFModeOn
	default:
		return "invalid waf_mode"
	}
	switch site.TLSMode {
	case store.TLSModeAuto, store.TLSModeManual, store.TLSModeOff:
	case "":
		site.TLSMode = store.TLSModeAuto
	default:
		return "invalid tls_mode"
	}
	if site.TLSMode == store.TLSModeManual && (site.CertFile == "" || site.KeyFile == "") {
		return "cert_file and key_file are required for manual TLS"
	}
	return ""
}

func idParam(r *http.Request) int64 {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	return id
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSONErr(w, status, err.Error())
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// orEmpty avoids serializing a nil slice as JSON null.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// SPAHandler serves the embedded single-page app, falling back to index.html
// for client-side routes so deep links work on refresh.
func SPAHandler(dist fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			fileServer.ServeHTTP(w, r)
			return
		}
		if _, err := fs.Stat(dist, path[1:]); err != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

// Package proxy is the data plane: it routes inbound requests to the right
// upstream by Host header, runs each through the WAF, and terminates TLS
// (Let's Encrypt or operator-supplied certificates).
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/crypto/acme/autocert"

	"github.com/jsinvasor/wafportal/internal/ratelimit"
	"github.com/jsinvasor/wafportal/internal/store"
	"github.com/jsinvasor/wafportal/internal/waf"
)

type Proxy struct {
	wafmgr   *waf.Manager
	sink     waf.EventSink
	limiter  *ratelimit.Limiter
	clientIP func(*http.Request) string

	certMgr *autocert.Manager

	mu          sync.RWMutex
	handlers    map[string]http.Handler // domain -> WAF-wrapped reverse proxy
	autoDomains map[string]bool         // domains using Let's Encrypt
	manualCerts map[string]*tls.Certificate
}

func New(wafmgr *waf.Manager, sink waf.EventSink, limiter *ratelimit.Limiter, clientIP func(*http.Request) string, certCacheDir, acmeEmail string) *Proxy {
	p := &Proxy{
		wafmgr:      wafmgr,
		sink:        sink,
		limiter:     limiter,
		clientIP:    clientIP,
		handlers:    map[string]http.Handler{},
		autoDomains: map[string]bool{},
		manualCerts: map[string]*tls.Certificate{},
	}
	p.certMgr = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(certCacheDir),
		Email:      acmeEmail,
		HostPolicy: p.hostPolicy,
	}
	return p
}

// Reload rebuilds the routing table from the current set of sites. Called at
// startup and whenever sites or custom rules change. A site whose upstream URL
// is invalid is skipped with a log line rather than failing the whole reload.
func (p *Proxy) Reload(sites []store.Site) {
	handlers := map[string]http.Handler{}
	autoDomains := map[string]bool{}
	manualCerts := map[string]*tls.Certificate{}

	for _, site := range sites {
		if !site.Enabled {
			continue
		}
		target, err := url.Parse(site.UpstreamURL)
		if err != nil || target.Host == "" {
			log.Printf("proxy: skipping site %q: invalid upstream %q", site.Domain, site.UpstreamURL)
			continue
		}

		var h http.Handler = newReverseProxy(target)
		if engine := p.wafmgr.Engine(site.WAFMode); engine != nil {
			h = waf.Middleware(engine, h, p.sink, site.Domain)
		}
		handlers[strings.ToLower(site.Domain)] = h

		switch site.TLSMode {
		case store.TLSModeAuto:
			autoDomains[strings.ToLower(site.Domain)] = true
		case store.TLSModeManual:
			if cert, err := tls.LoadX509KeyPair(site.CertFile, site.KeyFile); err != nil {
				log.Printf("proxy: site %q manual cert load failed: %v", site.Domain, err)
			} else {
				manualCerts[strings.ToLower(site.Domain)] = &cert
			}
		}
	}

	p.mu.Lock()
	p.handlers = handlers
	p.autoDomains = autoDomains
	p.manualCerts = manualCerts
	p.mu.Unlock()
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.limiter != nil && !p.limiter.Allow(p.clientIP(r)) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	h := p.handlerFor(r.Host)
	if h == nil {
		http.Error(w, "no site configured for this host", http.StatusNotFound)
		return
	}
	h.ServeHTTP(w, r)
}

func (p *Proxy) handlerFor(host string) http.Handler {
	domain := strings.ToLower(host)
	if i := strings.IndexByte(domain, ':'); i != -1 {
		domain = domain[:i]
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.handlers[domain]
}

// HTTPHandler is mounted on the plaintext listener. It serves ACME HTTP-01
// challenges, redirects TLS-enabled sites to HTTPS, and serves sites that run
// plaintext directly.
func (p *Proxy) HTTPHandler() http.Handler {
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.usesTLS(r.Host) {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		p.ServeHTTP(w, r)
	})
	// autocert intercepts /.well-known/acme-challenge/ and passes everything
	// else to our redirect handler.
	return p.certMgr.HTTPHandler(redirect)
}

// TLSConfig wires certificate selection: operator-supplied certs first, then
// Let's Encrypt for autocert domains.
func (p *Proxy) TLSConfig() *tls.Config {
	cfg := p.certMgr.TLSConfig()
	cfg.GetCertificate = p.getCertificate
	return cfg
}

func (p *Proxy) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := strings.ToLower(hello.ServerName)
	p.mu.RLock()
	cert, ok := p.manualCerts[domain]
	p.mu.RUnlock()
	if ok {
		return cert, nil
	}
	return p.certMgr.GetCertificate(hello)
}

func (p *Proxy) hostPolicy(_ context.Context, host string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.autoDomains[strings.ToLower(host)] {
		return nil
	}
	return fmt.Errorf("acme: host %q not configured for automatic TLS", host)
}

func (p *Proxy) usesTLS(host string) bool {
	domain := strings.ToLower(host)
	if i := strings.IndexByte(domain, ':'); i != -1 {
		domain = domain[:i]
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.autoDomains[domain] {
		return true
	}
	_, ok := p.manualCerts[domain]
	return ok
}

func newReverseProxy(target *url.URL) http.Handler {
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy: upstream %s error: %v", target, err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
	return rp
}

// Command wafportal is an L7 web application firewall built on OWASP Coraza
// (ModSecurity-compatible, Core Rule Set) with a management portal. A single
// binary runs the proxy data plane and the control-plane API + SPA.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jsinvasor/wafportal/internal/api"
	"github.com/jsinvasor/wafportal/internal/auth"
	"github.com/jsinvasor/wafportal/internal/config"
	"github.com/jsinvasor/wafportal/internal/proxy"
	"github.com/jsinvasor/wafportal/internal/store"
	"github.com/jsinvasor/wafportal/internal/waf"
	"github.com/jsinvasor/wafportal/web"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	st, err := store.Open(cfg.Database.Path)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	wafmgr := waf.NewManager()
	sink := newEventSink(st, 4096)
	p := proxy.New(wafmgr, sink.Submit, cfg.TLS.CacheDir, cfg.TLS.Email)

	// reload re-syncs engines and routing from the store. The proxy reads
	// engines from wafmgr, so rules must be (re)compiled before routing.
	reload := func() error {
		directives, err := st.EnabledRuleDirectives()
		if err != nil {
			return err
		}
		if err := wafmgr.Reload(directives); err != nil {
			return err
		}
		sites, err := st.ListSites()
		if err != nil {
			return err
		}
		p.Reload(sites)
		return nil
	}
	if err := reload(); err != nil {
		log.Fatalf("initial WAF load: %v", err)
	}
	log.Printf("WAF engine loaded (OWASP CRS + custom rules)")

	password := cfg.Admin.Password
	if env := os.Getenv("WAFPORTAL_ADMIN_PASSWORD"); env != "" {
		password = env
	}
	authn, err := auth.New(st, cfg.Admin.Username, password)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	if authn.GeneratedPassword != "" {
		log.Printf("\n"+
			"==================================================\n"+
			"  Portal admin account created\n"+
			"    username: %s\n"+
			"    password: %s\n"+
			"  Set WAFPORTAL_ADMIN_PASSWORD to choose your own.\n"+
			"==================================================",
			authn.Username(), authn.GeneratedPassword)
	}

	spa, err := web.Dist()
	if err != nil {
		log.Fatalf("embedded SPA: %v", err)
	}
	apiSrv := api.NewServer(st, authn, reload, api.SPAHandler(spa))

	servers := startServers(cfg, p, apiSrv)
	waitForShutdown(servers)
}

func startServers(cfg config.Config, p *proxy.Proxy, apiSrv *api.Server) []*http.Server {
	var servers []*http.Server

	admin := &http.Server{Addr: cfg.Admin.Addr, Handler: apiSrv.Handler()}
	servers = append(servers, admin)
	go func() {
		log.Printf("admin API + portal listening on %s", cfg.Admin.Addr)
		if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("admin server: %v", err)
		}
	}()

	httpSrv := &http.Server{Addr: cfg.Proxy.HTTPAddr, Handler: p.HTTPHandler()}
	servers = append(servers, httpSrv)
	go func() {
		log.Printf("proxy HTTP listening on %s", cfg.Proxy.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server: %v", err)
		}
	}()

	if cfg.Proxy.HTTPSAddr != "" {
		httpsSrv := &http.Server{
			Addr:      cfg.Proxy.HTTPSAddr,
			Handler:   p,
			TLSConfig: p.TLSConfig(),
		}
		servers = append(servers, httpsSrv)
		go func() {
			log.Printf("proxy HTTPS listening on %s", cfg.Proxy.HTTPSAddr)
			// Certificates are resolved via TLSConfig.GetCertificate.
			if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server: %v", err)
			}
		}()
	}

	return servers
}

func waitForShutdown(servers []*http.Server) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(ctx)
	}
}

// eventSink decouples event persistence from the request path: the proxy
// submits events to a buffered channel and a single worker writes them to the
// store. When the buffer is full events are dropped rather than blocking
// traffic.
type eventSink struct {
	ch chan *store.Event
	st *store.Store
}

func newEventSink(st *store.Store, buffer int) *eventSink {
	s := &eventSink{ch: make(chan *store.Event, buffer), st: st}
	go s.run()
	return s
}

func (s *eventSink) Submit(e *store.Event) {
	select {
	case s.ch <- e:
	default:
		log.Printf("event sink full; dropping event for %s", e.Domain)
	}
}

func (s *eventSink) run() {
	for e := range s.ch {
		if err := s.st.InsertEvent(e); err != nil {
			log.Printf("insert event: %v", err)
		}
	}
}

// Package ratelimit provides per-client request rate limiting to blunt
// application-layer (L7) flood attacks. It is not a defense against volumetric
// (L3/L4) DDoS, which must be handled upstream (e.g. Cloudflare or the
// hosting provider).
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter keeps a token bucket per client key. Idle buckets are evicted
// periodically so memory stays bounded under attack from many source IPs.
type Limiter struct {
	rps   rate.Limit
	burst int
	ttl   time.Duration

	mu      sync.Mutex
	clients map[string]*client
}

type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// New returns a limiter allowing rps requests per second per client with the
// given burst allowance. A background goroutine evicts buckets unused for ~3x
// the cleanup interval.
func New(rps float64, burst int) *Limiter {
	l := &Limiter{
		rps:     rate.Limit(rps),
		burst:   burst,
		ttl:     10 * time.Minute,
		clients: make(map[string]*client),
	}
	go l.cleanupLoop()
	return l
}

// Allow reports whether a request from key may proceed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	c, ok := l.clients[key]
	if !ok {
		c = &client{limiter: rate.NewLimiter(l.rps, l.burst)}
		l.clients[key] = c
	}
	c.lastSeen = time.Now()
	lim := c.limiter
	l.mu.Unlock()
	return lim.Allow()
}

func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(l.ttl)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-l.ttl)
		l.mu.Lock()
		for key, c := range l.clients {
			if c.lastSeen.Before(cutoff) {
				delete(l.clients, key)
			}
		}
		l.mu.Unlock()
	}
}

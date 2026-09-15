package auth

import (
	"sync"
	"time"
)

// RateLimiter: after 5 failed logins from an IP, lock it for 15 minutes.
// In-memory, process-local (per spec).
type RateLimiter struct {
	mu sync.Mutex
	m  map[string]*recEntry
}

type recEntry struct {
	fails       int
	firstFail   time.Time
	lockedUntil time.Time
}

const (
	maxFails   = 5
	lockWindow = 15 * time.Minute
)

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{m: map[string]*recEntry{}}
}

func (r *RateLimiter) IsLocked(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.m[ip]
	if !ok {
		return false
	}
	r.gc(rec, ip)
	if time.Now().Before(rec.lockedUntil) {
		return true
	}
	return false
}

func (r *RateLimiter) NoteFail(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.m[ip]
	if !ok || time.Since(rec.firstFail) > lockWindow {
		rec = &recEntry{firstFail: time.Now()}
		r.m[ip] = rec
	}
	rec.fails++
	if rec.fails >= maxFails {
		rec.lockedUntil = time.Now().Add(lockWindow)
	}
}

func (r *RateLimiter) Reset(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, ip)
}

func (r *RateLimiter) gc(e *recEntry, ip string) {
	if time.Since(e.firstFail) > lockWindow {
		delete(r.m, ip)
	}
}

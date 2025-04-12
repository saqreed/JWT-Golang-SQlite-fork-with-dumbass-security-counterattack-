package security

import (
	"crypto/rand"
	"sync"
	"time"
)

type BruteForceProtection struct {
	attempts    map[string]int
	lastAttempt map[string]time.Time
	lock        sync.RWMutex
	maxAttempts int
	blockTime   time.Duration
	garbageSize int64 // Size in bytes
}

func NewBruteForceProtection(maxAttempts int, blockTime time.Duration, garbageSize int64) *BruteForceProtection {
	return &BruteForceProtection{
		attempts:    make(map[string]int),
		lastAttempt: make(map[string]time.Time),
		maxAttempts: maxAttempts,
		blockTime:   blockTime,
		garbageSize: garbageSize,
	}
}

func (b *BruteForceProtection) RecordFailedAttempt(ip string) bool {
	b.lock.Lock()
	defer b.lock.Unlock()

	now := time.Now()

	// Reset attempts if enough time has passed
	if last, exists := b.lastAttempt[ip]; exists {
		if now.Sub(last) > b.blockTime {
			b.attempts[ip] = 0
		}
	}

	b.attempts[ip]++
	b.lastAttempt[ip] = now

	return b.attempts[ip] >= b.maxAttempts
}

func (b *BruteForceProtection) GenerateGarbage() []byte {
	garbage := make([]byte, b.garbageSize)
	rand.Read(garbage)
	return garbage
}

func (b *BruteForceProtection) ResetAttempts(ip string) {
	b.lock.Lock()
	defer b.lock.Unlock()
	delete(b.attempts, ip)
	delete(b.lastAttempt, ip)
}

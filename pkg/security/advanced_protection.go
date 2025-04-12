package security

import (
	"crypto/rand"
	"sync"
	"time"
)

type SuspiciousPattern struct {
	Pattern string
	Weight  int
}

type AdvancedProtection struct {
	attempts           map[string]int
	lastAttempt        map[string]time.Time
	blockedIPs         map[string]time.Time
	lock               sync.RWMutex
	maxAttempts        int
	blockTime          time.Duration
	permanentBlockTime time.Duration
	baseGarbageSize    int64
	suspiciousPatterns []SuspiciousPattern
	notificationChan   chan string
}

func NewAdvancedProtection(
	maxAttempts int,
	blockTime time.Duration,
	permanentBlockTime time.Duration,
	baseGarbageSize int64,
) *AdvancedProtection {
	return &AdvancedProtection{
		attempts:           make(map[string]int),
		lastAttempt:        make(map[string]time.Time),
		blockedIPs:         make(map[string]time.Time),
		maxAttempts:        maxAttempts,
		blockTime:          blockTime,
		permanentBlockTime: permanentBlockTime,
		baseGarbageSize:    baseGarbageSize,
		suspiciousPatterns: []SuspiciousPattern{
			{Pattern: "admin", Weight: 2},
			{Pattern: "password", Weight: 2},
			{Pattern: "123456", Weight: 3},
			{Pattern: "qwerty", Weight: 3},
		},
		notificationChan: make(chan string, 100),
	}
}

func (a *AdvancedProtection) RecordFailedAttempt(ip string, username string) bool {
	a.lock.Lock()
	defer a.lock.Unlock()

	now := time.Now()

	// Check if IP is permanently blocked
	if blockTime, exists := a.blockedIPs[ip]; exists {
		if now.Sub(blockTime) < a.permanentBlockTime {
			return true
		}
		delete(a.blockedIPs, ip)
	}

	// Reset attempts if enough time has passed
	if last, exists := a.lastAttempt[ip]; exists {
		if now.Sub(last) > a.blockTime {
			a.attempts[ip] = 0
		}
	}

	a.attempts[ip]++
	a.lastAttempt[ip] = now

	// Check for suspicious patterns
	suspiciousScore := a.checkSuspiciousPatterns(username)
	if suspiciousScore > 0 {
		a.attempts[ip] += suspiciousScore
		a.notificationChan <- "Suspicious activity detected from IP: " + ip + " with username: " + username
	}

	// If attempts exceed threshold, block IP permanently
	if a.attempts[ip] >= a.maxAttempts*2 {
		a.blockedIPs[ip] = now
		a.notificationChan <- "IP " + ip + " permanently blocked due to excessive attempts"
		return true
	}

	return a.attempts[ip] >= a.maxAttempts
}

func (a *AdvancedProtection) checkSuspiciousPatterns(username string) int {
	score := 0
	for _, pattern := range a.suspiciousPatterns {
		if len(username) >= len(pattern.Pattern) {
			score += pattern.Weight
		}
	}
	return score
}

func (a *AdvancedProtection) GenerateGarbage(ip string) []byte {
	a.lock.RLock()
	attempts := a.attempts[ip]
	a.lock.RUnlock()

	// Progressive garbage size based on attempts
	garbageSize := a.baseGarbageSize * int64(attempts)
	if garbageSize > 10*1024*1024*1024 { // Cap at 10GB
		garbageSize = 10 * 1024 * 1024 * 1024
	}

	garbage := make([]byte, garbageSize)
	rand.Read(garbage)
	return garbage
}

func (a *AdvancedProtection) ResetAttempts(ip string) {
	a.lock.Lock()
	defer a.lock.Unlock()
	delete(a.attempts, ip)
	delete(a.lastAttempt, ip)
}

func (a *AdvancedProtection) GetNotifications() <-chan string {
	return a.notificationChan
}

func (a *AdvancedProtection) IsIPBlocked(ip string) bool {
	a.lock.RLock()
	defer a.lock.RUnlock()

	if blockTime, exists := a.blockedIPs[ip]; exists {
		return time.Now().Sub(blockTime) < a.permanentBlockTime
	}
	return false
}

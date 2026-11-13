package server

import (
	"sync"
	"time"
)

// tokenBucket はプロセス内の簡易レートリミッタ。認証前のチャレンジ発行は
// 暗号学的な意味では安いが、DB 書き込みを伴うので回数を絞る。
type tokenBucket struct {
	mu       sync.Mutex
	rate     float64 // 1 秒あたりの回復量
	burst    float64
	tokens   float64
	lastSeen time.Time
}

func newTokenBucket(perMinute, burst float64) *tokenBucket {
	if perMinute <= 0 || burst <= 0 {
		return nil
	}
	return &tokenBucket{
		rate:     perMinute / 60,
		burst:    burst,
		tokens:   burst,
		lastSeen: time.Now(),
	}
}

func (b *tokenBucket) allow(now time.Time) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if elapsed := now.Sub(b.lastSeen).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.lastSeen = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

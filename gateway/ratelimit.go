package gateway

import (
	"hash/maphash"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	rlShards        = 64
	rlSweepInterval = time.Minute
)

// rateLimiter is a sharded per-key token bucket. Idle buckets are swept
// inline on access, so it needs no background goroutine.
type rateLimiter struct {
	rate   float64 // tokens per second
	burst  float64
	seed   maphash.Seed
	shards [rlShards]rlShard
	now    func() time.Time
	byUser bool
}

type rlShard struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(c *RateLimitConfig) *rateLimiter {
	rl := &rateLimiter{
		rate: c.RequestsPerSecond, burst: float64(c.Burst),
		seed: maphash.MakeSeed(), now: time.Now, byUser: c.Key == "principal",
	}
	for i := range rl.shards {
		rl.shards[i].buckets = map[string]*bucket{}
	}
	return rl
}

// allow consumes a token for key, returning the wait until the next token
// when the bucket is empty.
func (rl *rateLimiter) allow(key string) (bool, time.Duration) {
	s := &rl.shards[maphash.String(rl.seed, key)%rlShards]
	now := rl.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.lastSweep) > rlSweepInterval {
		rl.sweep(s, now)
	}
	b, ok := s.buckets[key]
	if !ok {
		b = &bucket{tokens: rl.burst, last: now}
		s.buckets[key] = b
	} else {
		b.tokens = math.Min(rl.burst, b.tokens+now.Sub(b.last).Seconds()*rl.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / rl.rate * float64(time.Second))
}

// sweep drops buckets that would have fully refilled; they are
// indistinguishable from new ones.
func (rl *rateLimiter) sweep(s *rlShard, now time.Time) {
	full := time.Duration(rl.burst / rl.rate * float64(time.Second))
	for k, b := range s.buckets {
		if now.Sub(b.last) > full {
			delete(s.buckets, k)
		}
	}
	s.lastSweep = now
}

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := ""
		if rl.byUser {
			if p := PrincipalFrom(r.Context()); p != nil && p.Subject != "" {
				key = "p:" + p.Authenticator + ":" + p.Subject
			}
		}
		if key == "" {
			key = "ip:" + ClientIPFrom(r.Context())
		}
		if ok, wait := rl.allow(key); !ok {
			secs := int(math.Ceil(wait.Seconds()))
			w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
			WriteProblem(w, r, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

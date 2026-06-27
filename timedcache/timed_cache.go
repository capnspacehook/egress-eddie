package timedcache

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// TimedCache is a concurrency-safe timed cache.
type TimedCache[K comparable, V any] struct {
	mtx    sync.RWMutex
	logger *zap.Logger

	cache map[K]*countedTimedValue[V]
	count bool
}

// countedTimedValue stores the optional count and deadline for eviction
// of a value of a key stored in a TimedCache.
type countedTimedValue[V any] struct {
	count      int
	generation uint64
	timer      *time.Timer

	value V
}

// New creates a new timed cache. If count is true, keys will take
// n [RemoveEntry] calls to be manually removed from the cache where n
// is the number of times [AddEntry] is called with the same key.
// Keys will be removed from the cache when the deadline is reached
// regardless of whether the cache is a counting cache or not.
func New[K comparable, V any](logger *zap.Logger, count bool) *TimedCache[K, V] {
	var t TimedCache[K, V]

	t.logger = logger
	t.cache = make(map[K]*countedTimedValue[V])
	t.count = count

	return &t
}

// Add adds a key to the cache with a ttl. The value associated with
// the key will be the zero value of the V's type.
func (t *TimedCache[K, V]) Add(key K, ttl time.Duration) {
	var zero V
	t.add(key, zero, ttl)
}

// AddValue adds a key and value to the cache with a ttl. If the key
// already exists the existing value will be left untouched. If this is
// a counting cache the count of the key will be incremented.
func (t *TimedCache[K, V]) AddValue(key K, value V, ttl time.Duration) {
	t.add(key, value, ttl)
}

func (t *TimedCache[K, V]) add(key K, value V, ttl time.Duration) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	t.logger.Debug("adding key", zap.Any("key", key))

	ct, ok := t.cache[key]
	if ok {
		if t.count {
			t.logger.Debug("incrementing count", zap.Any("key", key))
			ct.count++
		}

		ct.timer.Stop()
		ct.generation++
		gen := ct.generation
		ct.timer = time.AfterFunc(ttl, func() {
			t.expire(key, gen)
		})
		return
	}

	var gen uint64
	t.cache[key] = &countedTimedValue[V]{
		generation: gen,
		timer: time.AfterFunc(ttl, func() {
			t.expire(key, gen)
		}),
		value: value,
	}
}

func (t *TimedCache[K, V]) expire(key K, gen uint64) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	ct, ok := t.cache[key]
	if !ok {
		return
	}
	// if the generation of the key doesn't match the current one,
	// it means the timer has been restarted and the key shouldn't
	// be deleted yet
	if ct.generation != gen {
		return
	}

	t.logger.Debug("deleting expired key", zap.Any("key", key))
	delete(t.cache, key)
}

func (t *TimedCache[K, V]) Exists(key K) bool {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	_, ok := t.cache[key]

	return ok
}

func (t *TimedCache[K, V]) Lookup(key K) (V, bool) {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	var zero V
	ct, ok := t.cache[key]
	if !ok {
		return zero, false
	}

	return ct.value, ok
}

func (t *TimedCache[K, V]) keyCount(key K) int {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	ct, ok := t.cache[key]
	if !ok {
		return -1
	}

	return ct.count
}

// Remove deletes a key from the cache. If the cache is a counting cache
// the key will only be removed if its count is zero, otherwise the key's
// count will be decremented instead.
func (t *TimedCache[K, V]) Remove(key K) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	ct, ok := t.cache[key]
	if !ok {
		return
	}

	if ct.count != 0 {
		t.logger.Debug("decrementing count", zap.Any("key", key))
		ct.count--
		return
	}

	t.logger.Debug("deleting key", zap.Any("key", key))

	ct.timer.Stop()
	delete(t.cache, key)
}

// Stop kills all goroutines waiting on key deadlines. Keys are not
// removed from the cache.
func (t *TimedCache[K, V]) Stop() {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	for _, ct := range t.cache {
		ct.timer.Stop()
	}
}

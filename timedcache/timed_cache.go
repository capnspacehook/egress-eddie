package timedcache

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// TimedCache is a concurrency-safe timed cache. It stores entries, not
// key-value pairs.
type TimedCache[T comparable] struct {
	mtx    sync.RWMutex
	logger *zap.Logger

	cache map[T]*countedTimer
	count bool
}

// countedTimer stores the optional count and deadline for eviction
// of an entry stored in a TimedCache.
type countedTimer struct {
	count      int
	generation uint64
	timer      *time.Timer
}

// New creates a new timed cache. If count is true, entries will take
// n RemoveEntry calls to be manually removed from the cache where n
// is the number of times AddEntry is called with the same entry.
// Entries will be removed from the cache when the deadline is reached
// regardless of whether the cache is a counting cache or not.
func New[T comparable](logger *zap.Logger, count bool) *TimedCache[T] {
	var t TimedCache[T]

	t.logger = logger
	t.cache = make(map[T]*countedTimer)
	t.count = count

	return &t
}

func (t *TimedCache[T]) AddEntry(entry T, ttl time.Duration) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	t.logger.Debug("adding entry", zap.Any("entry", entry))

	ct, ok := t.cache[entry]
	if ok {
		if t.count {
			t.logger.Debug("incrementing count", zap.Any("entry", entry))
			ct.count++
		}

		ct.timer.Stop()
		ct.generation++
		gen := ct.generation
		ct.timer = time.AfterFunc(ttl, func() {
			t.expireEntry(entry, gen)
		})
		return
	}

	var gen uint64
	t.cache[entry] = &countedTimer{
		generation: gen,
		timer: time.AfterFunc(ttl, func() {
			t.expireEntry(entry, gen)
		}),
	}
}

func (t *TimedCache[T]) expireEntry(entry T, gen uint64) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	ct, ok := t.cache[entry]
	if !ok {
		return
	}
	if ct.generation != gen {
		return
	}

	t.logger.Debug("deleting entry", zap.Any("entry", entry))
	delete(t.cache, entry)
}

func (t *TimedCache[T]) EntryExists(entry T) bool {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	_, ok := t.cache[entry]

	return ok
}

func (t *TimedCache[T]) RemoveEntry(entry T) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	ct, ok := t.cache[entry]
	if !ok {
		return
	}

	if ct.count != 0 {
		t.logger.Debug("decrementing count", zap.Any("entry", entry))
		ct.count--
		return
	}

	t.logger.Debug("deleting entry", zap.Any("entry", entry))

	ct.timer.Stop()
	delete(t.cache, entry)
}

// Stop kills all goroutines waiting on entry deadlines. Entries are not
// removed from the cache.
func (t *TimedCache[T]) Stop() {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	for _, ct := range t.cache {
		ct.timer.Stop()
	}
}

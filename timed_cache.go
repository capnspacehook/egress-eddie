package main

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// TimedCache is a concurrency-safe timed cache. It stores entries, not
// key-value pairs.
type TimedCache[T comparable] struct {
	mtx    sync.RWMutex
	wg     sync.WaitGroup
	logger *zap.Logger

	cache map[T]*countedTimer
	count bool
}

// countedTimer stores the optional count and deadline for eviction
// of an entry stored in a TimedCache.
type countedTimer struct {
	count  int
	status chan timerStatus
	timer  *time.Timer
}

// timerStatus is used to communicate with a child goroutine that is
// waiting to delete a cache entry.
type timerStatus uint8

const (
	reset timerStatus = iota // signals that the timer is getting reset
	start                    // signals that the timer has started
	stop                     // signals that the goroutine should finish
)

// NewTimedCache creates a new timed cache. If count is true, entries will
// take n RemoveEntry calls to be manually removed from the cache where n
// is the number of times AddEntry is called with the same entry.
// Entries will be removed from the cache when the deadline is reached
// regardless of whether the cache is a counting cache or not.
func NewTimedCache[T comparable](logger *zap.Logger, count bool) *TimedCache[T] {
	var t TimedCache[T]

	t.logger = logger
	t.cache = make(map[T]*countedTimer)
	t.count = count

	return &t
}

func (t *TimedCache[T]) AddEntry(entry T, ttl time.Duration) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	ct, ok := t.cache[entry]
	if ok {
		if t.count {
			t.logger.Debug("incrementing count", zap.Any("entry", entry))
			ct.count++
		}

		ct.status <- reset
		if !ct.timer.Stop() {
			<-ct.timer.C
		}
		ct.timer.Reset(ttl)
		ct.status <- start
		return
	}

	timer := time.NewTimer(ttl)
	status := make(chan timerStatus)

	t.cache[entry] = &countedTimer{
		count:  0,
		status: status,
		timer:  timer,
	}

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()

		running := true
		for running {
			select {
			case <-timer.C:
				running = false
			case s := <-status:
				if s == reset {
					// wait until timer is finished resetting
					<-status
				} else if s == stop {
					return
				}
			}
		}

		t.logger.Debug("deleting entry", zap.Any("entry", entry))

		t.mtx.Lock()
		delete(t.cache, entry)
		t.mtx.Unlock()
	}()
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

	// we have already acquired a mutex lock here, so tell the child
	// goroutine to stop so it won't attempt to also remove this entry
	// as well
	ct.status <- stop
	if !ct.timer.Stop() {
		<-ct.timer.C
	}

	t.logger.Debug("deleting entry", zap.Any("entry", entry))
	delete(t.cache, entry)
}

// Stop kills all goroutines waiting on entry deadlines. Entries are not
// removed from the cache.
func (t *TimedCache[T]) Stop() {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	for _, ct := range t.cache {
		ct.status <- stop
		if !ct.timer.Stop() {
			<-ct.timer.C
		}
	}

	t.wg.Wait()
}

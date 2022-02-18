package main

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

type TimedCache[T comparable] struct {
	mtx    sync.RWMutex
	wg     sync.WaitGroup
	logger *zap.Logger

	cache map[T]*countedTimer
	count bool
}

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

	ct.status <- stop
	if !ct.timer.Stop() {
		<-ct.timer.C
	}

	t.logger.Debug("deleting entry", zap.Any("entry", entry))
	delete(t.cache, entry)
}

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

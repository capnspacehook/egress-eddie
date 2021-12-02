package main

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

type TimedCache[T comparable] struct {
	mtx    sync.RWMutex
	logger *zap.Logger

	cache map[T]*pair
	count bool
}

type pair struct {
	count int
	timer *time.Timer
}

func NewTimedCache[T comparable](logger *zap.Logger, count bool) *TimedCache[T] {
	var t TimedCache[T]

	t.logger = logger
	t.cache = make(map[T]*pair)
	t.count = count

	return &t
}

func (t *TimedCache[T]) AddEntry(key T, ttl time.Duration) {
	if t == nil {
		return
	}

	t.mtx.Lock()
	defer t.mtx.Unlock()

	p, ok := t.cache[key]
	if ok {
		if t.count {
			t.logger.Debug("incrementing count", zap.Any("key", key))
			p.count++
		}

		if !p.timer.Stop() {
			<-p.timer.C
		}
		p.timer.Reset(ttl)
		return
	}

	timer := time.NewTimer(ttl)
	t.cache[key] = &pair{
		count: 0,
		timer: timer,
	}

	go func() {
		<-timer.C
		t.logger.Debug("deleting entry", zap.Any("key", key))

		t.mtx.Lock()
		delete(t.cache, key)
		t.mtx.Unlock()
	}()
}

func (t *TimedCache[T]) EntryExists(key T) bool {
	if t == nil {
		return false
	}

	t.mtx.RLock()
	defer t.mtx.RUnlock()

	_, ok := t.cache[key]

	return ok
}

func (t *TimedCache[T]) RemoveEntry(key T) {
	if t == nil {
		return
	}

	t.mtx.Lock()
	defer t.mtx.Unlock()

	p, ok := t.cache[key]
	if !ok {
		return
	}

	if p.count != 0 {
		t.logger.Debug("decrementing count", zap.Any("key", key))
		p.count--
		return
	}
	t.logger.Debug("deleting entry", zap.Any("key", key))

	if !p.timer.Stop() {
		<-p.timer.C
	}

	delete(t.cache, key)
}

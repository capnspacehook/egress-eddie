package main

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

type TimedCache struct {
	mtx    sync.RWMutex
	logger *zap.Logger

	// TODO: make generic once 1.18 lands
	cache map[string]*pair
	count bool
}

type pair struct {
	count int
	timer *time.Timer
}

func NewTimedCache(logger *zap.Logger, count bool) *TimedCache {
	var t TimedCache

	t.logger = logger
	t.cache = make(map[string]*pair)
	t.count = count

	return &t
}

func (t *TimedCache) AddEntry(key string, ttl time.Duration) {
	if t == nil {
		return
	}

	t.mtx.Lock()
	defer t.mtx.Unlock()

	p, ok := t.cache[key]
	if ok {
		if t.count {
			t.logger.Debug("incrementing count", zap.String("key", key))
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
		t.logger.Debug("deleting entry", zap.String("key", key))

		t.mtx.Lock()
		delete(t.cache, key)
		t.mtx.Unlock()
	}()
}

func (t *TimedCache) EntryExists(key string) bool {
	if t == nil {
		return false
	}

	t.mtx.RLock()
	defer t.mtx.RUnlock()

	_, ok := t.cache[key]

	return ok
}

func (t *TimedCache) RemoveEntry(key string) {
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
		t.logger.Debug("decrementing count", zap.String("key", key))
		p.count--
		return
	}
	t.logger.Debug("deleting entry", zap.String("key", key))

	if !p.timer.Stop() {
		<-p.timer.C
	}

	delete(t.cache, key)
}

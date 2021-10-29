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
	records map[string]*time.Timer
}

func NewTimedCache(logger *zap.Logger) *TimedCache {
	var t TimedCache

	t.logger = logger
	t.records = make(map[string]*time.Timer)

	return &t
}

func (t *TimedCache) AddRecord(record string, ttl uint32) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	dur := time.Duration(ttl) * time.Second
	timer, ok := t.records[record]
	if ok {
		if !timer.Stop() {
			<-timer.C
		}

		timer.Reset(dur)
	} else {
		timer := time.NewTimer(dur)
		t.records[record] = timer

		go func() {
			<-timer.C
			t.logger.Debug("deleting record", zap.String("record", record))

			t.mtx.Lock()
			delete(t.records, record)
			t.mtx.Unlock()
		}()
	}
}

func (t *TimedCache) RecordExists(record string) bool {
	t.mtx.RLock()
	defer t.mtx.RUnlock()

	_, ok := t.records[record]

	return ok
}

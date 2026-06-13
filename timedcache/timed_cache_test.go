package timedcache

import (
	"maps"
	"math"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/matryer/is"
	"go.uber.org/zap"
	"pgregory.net/rapid"
)

// TestTimedCacheDeadlock tests that a deadlock does not occur when
// an entry is added and removed at the same time.
func TestTimedCacheDeadlock(t *testing.T) {
	is := is.New(t)

	logger, err := zap.NewDevelopment()
	is.NoErr(err)

	tc := New[int](logger, true)
	tc.AddEntry(42, time.Second)
	time.Sleep(time.Second)

	tc.AddEntry(42, time.Second)
}

func TestTimedCache(t *testing.T) {
	is := is.New(t)

	logger, err := zap.NewDevelopment()
	is.NoErr(err)

	tc := New[int](logger, false)

	t.Run("timed deletion", func(t *testing.T) {
		is := is.New(t)

		tc.AddEntry(42, 100*time.Millisecond)
		is.True(tc.EntryExists(42))
		time.Sleep(150 * time.Millisecond)
		is.True(!tc.EntryExists(42))
	})

	t.Run("changing ttl", func(t *testing.T) {
		is := is.New(t)

		tc.AddEntry(42, 100*time.Second)
		is.True(tc.EntryExists(42))
		tc.AddEntry(42, 100*time.Millisecond)
		time.Sleep(150 * time.Millisecond)
		is.True(!tc.EntryExists(42))
	})

	t.Run("removal", func(t *testing.T) {
		is := is.New(t)

		tc.AddEntry(42, 100*time.Millisecond)
		is.True(tc.EntryExists(42))
		tc.RemoveEntry(42)
		is.True(!tc.EntryExists(42))
	})
}

func TestTimedCacheWithCount(t *testing.T) {
	is := is.New(t)

	logger, err := zap.NewDevelopment()
	is.NoErr(err)

	tc := New[int](logger, true)

	t.Run("timed deletion", func(t *testing.T) {
		is := is.New(t)

		tc.AddEntry(42, 100*time.Millisecond)
		is.True(tc.EntryExists(42))
		time.Sleep(150 * time.Millisecond)
		is.True(!tc.EntryExists(42))
	})

	t.Run("changing ttl", func(t *testing.T) {
		is := is.New(t)

		tc.AddEntry(42, 100*time.Second)
		is.True(tc.EntryExists(42))
		tc.AddEntry(42, 100*time.Millisecond)
		time.Sleep(150 * time.Millisecond)
		is.True(!tc.EntryExists(42))
	})

	t.Run("timed deletion with count", func(t *testing.T) {
		is := is.New(t)

		tc.AddEntry(42, 100*time.Millisecond)
		is.True(tc.EntryExists(42))
		tc.AddEntry(42, 100*time.Millisecond)
		tc.RemoveEntry(42)
		is.True(tc.EntryExists(42))
		time.Sleep(150 * time.Millisecond)
		is.True(!tc.EntryExists(42))
	})

	t.Run("removal", func(t *testing.T) {
		is := is.New(t)

		tc.AddEntry(42, 100*time.Millisecond)
		is.True(tc.EntryExists(42))
		tc.AddEntry(42, 100*time.Millisecond)
		tc.RemoveEntry(42)
		tc.RemoveEntry(42)
		is.True(!tc.EntryExists(42))
	})
}

func TestTimedCacheState(t *testing.T) {
	rapid.Check(t, testTimedCacheState)
}

func FuzzTimedCacheState(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(testTimedCacheState))
}

type stateEntry struct {
	ttl     time.Duration
	created time.Time
	count   int
}

func testTimedCacheState(t *rapid.T) {
	rapid.SyncTest(t, func(t *rapid.T) {
		logger, err := zap.NewDevelopment()
		if err != nil {
			t.Fatal(err)
		}

		tc := New[int](logger, true)
		t.Cleanup(tc.Stop)

		state := make(map[int]stateEntry)
		t.Repeat(map[string]func(*rapid.T){
			"add entry": func(t *rapid.T) {
				// advance time and wait for expired entries to be removed
				time.Sleep(time.Second)
				synctest.Wait()

				i := rapid.IntRange(0, math.MaxInt).Draw(t, "entry")
				secs := rapid.IntRange(1, 100).Draw(t, "ttl")
				ttl := time.Duration(secs) * time.Second

				existsPrior := tc.EntryExists(i)
				var curCount int
				if existsPrior {
					curCount = tc.entryCount(i) + 1
				}

				tc.AddEntry(i, ttl)
				now := time.Now()
				if !tc.EntryExists(i) {
					t.Fatal("entry should exist")
				}

				state[i] = stateEntry{
					ttl:     ttl,
					created: now,
					count:   curCount,
				}

				count := tc.entryCount(i)
				if count != curCount {
					t.Logf("stateCount=%d entryCount=%d", curCount, count)
					t.Fatal("count should match")
				}

				t.Logf("count=%d", curCount)
			},
			"remove existing entry": func(t *rapid.T) {
				// advance time and wait for expired entries to be removed
				time.Sleep(time.Second)
				synctest.Wait()

				if len(state) == 0 {
					return
				}

				entries := slices.Collect(maps.Keys(state))
				i := rapid.SampledFrom(entries).Draw(t, "entry")

				tc.RemoveEntry(i)
				exists := tc.EntryExists(i)
				now := time.Now()

				s := state[i]
				deadline := s.created.Add(s.ttl)
				ttlLeft := deadline.Sub(now)

				if exists {
					if now.After(deadline) {
						t.Logf("state=%#v ttlLeft=%s", s, ttlLeft)
						t.Fatal("entry should have been removed due to ttl")
					} else if s.count == 0 {
						t.Logf("state=%#v ttlLeft=%s", s, ttlLeft)
						t.Fatal("entry should have been removed due to count")
					}
				} else if now.Before(deadline) && s.count > 0 {
					t.Logf("state=%#v ttlLeft=%s", s, ttlLeft)
					t.Fatal("entry should not have been removed")
				}

				if s.count > 0 {
					s.count--
					state[i] = s
					t.Logf("count=%d", s.count)
				} else {
					delete(state, i)
					t.Log("removed")
				}
			},
			"check entries": func(t *rapid.T) {
				// advance time and wait for expired entries to be removed
				time.Sleep(time.Second)
				synctest.Wait()

				now := time.Now()
				for i, s := range state {
					exists := tc.EntryExists(i)
					deadline := s.created.Add(s.ttl)

					if !exists && now.Before(deadline) {
						ttlLeft := deadline.Sub(now)
						t.Logf("key=%d state=%#v ttlLeft=%s", i, s, ttlLeft)
						t.Fatal("entry should exist")
					}

					if exists {
						count := tc.entryCount(i)
						if count != s.count {
							t.Logf("key=%d state=%#v entry=%#v", i, s, tc.cache[i])
							t.Fatal("count should match")
						}
					}
				}
			},
			"sleep": func(t *rapid.T) {
				secs := rapid.IntRange(1, 100).Draw(t, "secs")
				time.Sleep(time.Second * time.Duration(secs))
			},
		})
	})
}

package timedcache

import (
	"testing"
	"time"

	"github.com/matryer/is"
	"go.uber.org/zap"
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

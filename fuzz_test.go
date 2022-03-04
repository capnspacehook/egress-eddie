package main

import (
	"testing"
)

func FuzzConfig(f *testing.F) {
	// logger := zap.NewNop()

	for _, tt := range configTests {
		f.Add([]byte(tt.configStr))
	}

	f.Fuzz(func(t *testing.T, cb []byte) {
		_, err := parseConfigBytes(cb)
		if err != nil {
			return
		}

		// ctx, cancel := context.WithCancel(context.Background())
		// f, err := StartFilters(ctx, logger, config)
		// cancel()
		// f.Stop()
		// if err != nil {
		// 	t.Fatal(err)
		// }
	})
}

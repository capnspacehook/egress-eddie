package main

import (
	"testing"
)

func FuzzConfig(f *testing.F) {
	// for _, tt := range configTests {
	// 	f.Add([]byte(tt.configStr))
	// }

	f.Fuzz(func(t *testing.T, cb []byte) {
		_, err := parseConfigBytes(cb)
		if err != nil {
			return
		}
	})
}

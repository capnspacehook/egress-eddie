module github.com/capnspacehook/egress-eddie

go 1.18

require (
	github.com/BurntSushi/toml v1.3.0
	github.com/florianl/go-nfqueue v1.3.1
	github.com/google/gopacket v1.1.19
	github.com/landlock-lsm/go-landlock v0.0.0-20211207181312-ab929acf048a
	github.com/mdlayher/netlink v1.7.1
	go.uber.org/zap v1.24.0
	golang.org/x/exp v0.0.0-20220722155223-a9213eeb770e
	golang.org/x/sys v0.7.0
	gvisor.dev/gvisor v0.0.0-20221108212141-79965837f088
)

// Test dependencies
require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be
	github.com/matryer/is v1.4.1
	go.uber.org/goleak v1.2.1
)

require (
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/net v0.2.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.63 // indirect
)

module github.com/capnspacehook/egress-eddie

go 1.25.5

require (
	github.com/BurntSushi/toml v1.5.0
	github.com/florianl/go-nfqueue v1.3.2
	github.com/google/gopacket v1.1.19
	github.com/landlock-lsm/go-landlock v0.0.0-20250303204525-1544bccde3a3
	github.com/mdlayher/netlink v1.8.0
	go.uber.org/zap v1.27.1
	golang.org/x/sys v0.36.0
	gvisor.dev/gvisor v0.0.0-20250911055229-61a46406f068
)

// Test dependencies
require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be
	github.com/matryer/is v1.4.1
	go.uber.org/goleak v1.3.0
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.70 // indirect
)

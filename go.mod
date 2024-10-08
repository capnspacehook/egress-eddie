module github.com/capnspacehook/egress-eddie

go 1.23

require (
	github.com/BurntSushi/toml v1.4.0
	github.com/florianl/go-nfqueue v1.3.2
	github.com/google/gopacket v1.1.19
	github.com/landlock-lsm/go-landlock v0.0.0-20211207181312-ab929acf048a
	github.com/mdlayher/netlink v1.7.2
	go.uber.org/zap v1.27.0
	golang.org/x/exp v0.0.0-20230725093048-515e97ebf090
	golang.org/x/sys v0.25.0
	gvisor.dev/gvisor v0.0.0-20230811195211-463ea554e02f
)

// Test dependencies
require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be
	github.com/matryer/is v1.4.1
	go.uber.org/goleak v1.3.0
)

require (
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.63 // indirect
)

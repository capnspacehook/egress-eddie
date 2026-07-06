module github.com/capnspacehook/egress-eddie

go 1.26.4

require (
	codeberg.org/miekg/dns v0.6.83
	github.com/BurntSushi/toml v1.6.0
	github.com/capnspacehook/glob v0.0.0-20260626023508-ee0ef131248e
	github.com/florianl/go-nfqueue/v2 v2.1.0
	github.com/gopacket/gopacket v1.6.1
	github.com/landlock-lsm/go-landlock v0.9.0
	github.com/mdlayher/netlink v1.11.2
	go.uber.org/zap v1.27.1
	golang.org/x/sys v0.46.0
	gvisor.dev/gvisor v0.0.0-20260624000029-d10071d63566
)

// Test dependencies
require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be
	github.com/matryer/is v1.4.1
	go.uber.org/goleak v1.3.0
	pgregory.net/rapid v1.3.0
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/exp v0.0.0-20260218203240-3dfff04db8fa // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.77 // indirect
)

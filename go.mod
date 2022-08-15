module github.com/capnspacehook/egress-eddie

go 1.18

require (
	github.com/BurntSushi/toml v1.2.0
	github.com/florianl/go-nfqueue v1.3.1-0.20220325083416-d7801b74b0ff
	github.com/google/gopacket v1.1.19
	github.com/landlock-lsm/go-landlock v0.0.0-20211207181312-ab929acf048a
	github.com/mdlayher/netlink v1.6.0
	go.uber.org/zap v1.22.0
	golang.org/x/exp v0.0.0-20220722155223-a9213eeb770e
	golang.org/x/sys v0.0.0-20220224120231-95c6836cb0e7
	gvisor.dev/gvisor v0.0.0-20220706205639-118a2001295b
)

// Test dependencies
require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be
	github.com/matryer/is v1.4.0
	go.uber.org/goleak v1.1.12
)

require (
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/mdlayher/socket v0.2.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.7.1-0.20210427113832-6241f9ab9942 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.63 // indirect
)

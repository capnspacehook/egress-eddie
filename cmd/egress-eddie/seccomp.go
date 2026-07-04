package main

import (
	"os"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
)

var allowedSyscalls = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	unix.SYS_CLOCK_GETTIME: seccomp.PerArg{
		seccomp.EqualTo(unix.CLOCK_MONOTONIC),
		seccomp.AnyValue{},
	},
	// used to create OS threads for the Go scheduler
	unix.SYS_CLONE: seccomp.PerArg{
		// parent_tidptr and child_tidptr are always 0 because neither
		// CLONE_PARENT_SETTID nor CLONE_CHILD_SETTID are used.
		seccomp.EqualTo(
			unix.CLONE_VM |
				unix.CLONE_FS |
				unix.CLONE_FILES |
				unix.CLONE_SETTLS |
				unix.CLONE_SIGHAND |
				unix.CLONE_SYSVSEM |
				unix.CLONE_THREAD),
		seccomp.AnyValue{},
		seccomp.EqualTo(0),
		seccomp.EqualTo(0),
		seccomp.AnyValue{},
	},
	unix.SYS_CLOSE: seccomp.MatchAll{},
	unix.SYS_EPOLL_CTL: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.EPOLL_CTL_ADD),
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.EPOLL_CTL_DEL),
			seccomp.AnyValue{},
			seccomp.AnyValue{},
		},
	},
	unix.SYS_EPOLL_PWAIT: seccomp.MatchAll{},
	unix.SYS_EXIT_GROUP:  seccomp.MatchAll{},
	unix.SYS_FCNTL: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.F_GETFL),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.F_SETFL),
		},
	},
	unix.SYS_FSTAT: seccomp.MatchAll{},
	unix.SYS_FUTEX: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_GETPID:  seccomp.MatchAll{},
	unix.SYS_GETTID:  seccomp.MatchAll{},
	unix.SYS_MADVISE: seccomp.MatchAll{},
	unix.SYS_MMAP: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.PROT_READ | unix.PROT_WRITE),
			seccomp.EqualTo(unix.MAP_SHARED),
			seccomp.GreaterThan(0),
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.PROT_READ | unix.PROT_WRITE),
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
			seccomp.GreaterThan(0),
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.PROT_READ | unix.PROT_WRITE),
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS | unix.MAP_FIXED),
			seccomp.GreaterThan(0),
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_MUNMAP:     seccomp.MatchAll{},
	unix.SYS_NANOSLEEP:  seccomp.MatchAll{},
	unix.SYS_NEWFSTATAT: seccomp.MatchAll{},
	// used to name anonymous memory mappings
	unix.SYS_PRCTL: seccomp.PerArg{
		seccomp.EqualTo(unix.PR_SET_VMA),
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
	},
	unix.SYS_PREAD64: seccomp.MatchAll{},
	unix.SYS_READ:    seccomp.MatchAll{},
	// used to receive queued packets from nfqueue over netlink
	unix.SYS_RECVMSG: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MSG_PEEK),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MSG_PEEK | unix.MSG_TRUNC),
		},
	},
	unix.SYS_RESTART_SYSCALL:   seccomp.MatchAll{},
	unix.SYS_RT_SIGACTION:      seccomp.MatchAll{},
	unix.SYS_RT_SIGPROCMASK:    seccomp.MatchAll{},
	unix.SYS_RT_SIGRETURN:      seccomp.MatchAll{},
	unix.SYS_SCHED_GETAFFINITY: seccomp.MatchAll{},
	unix.SYS_SCHED_YIELD:       seccomp.MatchAll{},
	// used to send nfqueue verdicts over netlink
	unix.SYS_SENDMSG: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(0),
	},
	unix.SYS_SIGALTSTACK: seccomp.MatchAll{},
	unix.SYS_TGKILL: seccomp.PerArg{
		seccomp.EqualTo(uint64(os.Getpid())),
	},
	unix.SYS_WRITE: seccomp.MatchAll{},
})

var networkSyscalls = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	unix.SYS_CONNECT:     seccomp.MatchAll{},
	unix.SYS_GETPEERNAME: seccomp.MatchAll{},
	unix.SYS_GETSOCKNAME: seccomp.MatchAll{},
	unix.SYS_MMAP: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(unix.PROT_NONE),
		seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
		seccomp.GreaterThan(0),
		seccomp.EqualTo(0),
	},
	// used to read system files such as resolver config and certificates
	unix.SYS_OPENAT: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(unix.O_RDONLY | unix.O_CLOEXEC),
	},
	unix.SYS_SETSOCKOPT: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_BROADCAST),
			seccomp.AnyValue{},
			seccomp.EqualTo(4),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_IPV6),
			seccomp.EqualTo(unix.IPV6_V6ONLY),
			seccomp.AnyValue{},
			seccomp.EqualTo(4),
		},
	},
	unix.SYS_SOCKET: seccomp.Or{
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_INET),
			seccomp.EqualTo(unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_INET),
			seccomp.EqualTo(unix.SOCK_DGRAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_INET6),
			seccomp.EqualTo(unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_INET6),
			seccomp.EqualTo(unix.SOCK_DGRAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
	},
})

// TODO: move getsockopt and setsockopt to above to handle TCP DNS?
var dohResolveInjectSyscalls = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	// used to bind the netlink socket used to enumerate interfaces
	unix.SYS_BIND: seccomp.MatchAll{},
	// used to read SO_ERROR to complete non-blocking connects
	unix.SYS_GETSOCKOPT: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.EqualTo(unix.SOL_SOCKET),
		seccomp.EqualTo(unix.SO_ERROR),
		seccomp.AnyValue{},
		seccomp.AnyValue{},
	},
	unix.SYS_GETRANDOM: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(0),
	},
	// additional mapping call by net/http and/or crypto/tls
	unix.SYS_MMAP: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.PROT_READ | unix.PROT_WRITE),
			seccomp.EqualTo(0x8 | unix.MAP_ANONYMOUS),
			seccomp.GreaterThan(0),
			seccomp.EqualTo(0),
		},
	},
	// used to read netlink interface-enumeration responses
	unix.SYS_RECVFROM: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(0),
	},
	// used to write netlink requests and inject synthesized DNS replies
	unix.SYS_SENDTO: seccomp.PerArg{
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.EqualTo(0),
	},
	unix.SYS_SETSOCKOPT: seccomp.Or{
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_TCP),
			seccomp.EqualTo(unix.TCP_NODELAY),
			seccomp.AnyValue{},
			seccomp.EqualTo(4),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_KEEPALIVE),
			seccomp.AnyValue{},
			seccomp.EqualTo(4),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_TCP),
			seccomp.EqualTo(unix.TCP_KEEPIDLE),
			seccomp.AnyValue{},
			seccomp.EqualTo(4),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_TCP),
			seccomp.EqualTo(unix.TCP_KEEPINTVL),
			seccomp.AnyValue{},
			seccomp.EqualTo(4),
		},
		seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOL_TCP),
			seccomp.EqualTo(unix.TCP_KEEPCNT),
			seccomp.AnyValue{},
			seccomp.EqualTo(4),
		},
	},
	// used for opening the AF_PACKET inject socket and AF_NETLINK
	// interface-lookup socket
	unix.SYS_SOCKET: seccomp.Or{
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_PACKET),
			seccomp.EqualTo(unix.SOCK_RAW | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_NETLINK),
			seccomp.EqualTo(unix.SOCK_RAW | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(unix.NETLINK_ROUTE),
		},
	},
})

type nullEmitter struct{}

func (nullEmitter) Emit(_ int, _ log.Level, _ time.Time, _ string, _ ...interface{}) {}

const violationAction = seccomp.KillProcess

func installSeccompFilters(logger *zap.Logger, needsNetworking, dohResolve bool) (int, error) {
	// only allow Egress Eddie to make outbound connections if DNS
	// requests will need to be made directly
	if needsNetworking {
		logger.Debug("allowing networking syscalls")
		allowedSyscalls.Merge(networkSyscalls)
	}
	if dohResolve {
		logger.Debug("allowing DoH syscalls")
		allowedSyscalls.Merge(dohResolveInjectSyscalls)
	}

	// disable logging from seccomp package
	log.SetTarget(&nullEmitter{})

	p := &seccomp.Program{
		RuleSets: []seccomp.RuleSet{
			{
				Rules:  seccomp.DenyNewExecMappings,
				Action: violationAction,
			},
			{
				Rules:  allowedSyscalls,
				Action: seccomp.Allow,
			},
		},
		Options: seccomp.ProgramOptions{
			DefaultAction: violationAction,
			BadArchAction: violationAction,
		},
	}

	return allowedSyscalls.Size(), p.Install()
}

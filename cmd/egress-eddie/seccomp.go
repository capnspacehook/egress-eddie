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
		seccomp.AnyValue{}, // newsp
		seccomp.EqualTo(0), // parent_tidptr
		seccomp.EqualTo(0), // child_tidptr
		seccomp.AnyValue{}, // tls
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
	unix.SYS_PRCTL: seccomp.PerArg{
		seccomp.EqualTo(unix.PR_SET_VMA),
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
		seccomp.AnyValue{},
	},
	unix.SYS_PREAD64: seccomp.MatchAll{},
	unix.SYS_READ:    seccomp.MatchAll{},
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
	},
	unix.SYS_RESTART_SYSCALL:   seccomp.MatchAll{},
	unix.SYS_RT_SIGACTION:      seccomp.MatchAll{},
	unix.SYS_RT_SIGPROCMASK:    seccomp.MatchAll{},
	unix.SYS_RT_SIGRETURN:      seccomp.MatchAll{},
	unix.SYS_SCHED_GETAFFINITY: seccomp.MatchAll{},
	unix.SYS_SCHED_YIELD:       seccomp.MatchAll{},
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
	unix.SYS_UNAME: seccomp.MatchAll{},
})

var networkSyscalls = seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
	unix.SYS_CONNECT:     seccomp.MatchAll{},
	unix.SYS_GETPEERNAME: seccomp.MatchAll{},
	unix.SYS_GETSOCKNAME: seccomp.MatchAll{},
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

type nullEmitter struct{}

func (nullEmitter) Emit(_ int, _ log.Level, _ time.Time, _ string, _ ...interface{}) {
}

func installSeccompFilters(logger *zap.Logger, needsNetworking bool) (int, error) {
	// only allow Egress Eddie to make outbound connections if DNS
	// requests will need to be made directly
	if needsNetworking {
		logger.Debug("allowing networking syscalls")
		allowedSyscalls.Merge(networkSyscalls)
	}

	// disable logging from seccomp package
	log.SetTarget(&nullEmitter{})

	return allowedSyscalls.Size(), seccomp.Install(allowedSyscalls, seccomp.DenyNewExecMappings, seccomp.DefaultProgramOptions())
}

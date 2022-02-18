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

var allowedSyscalls = seccomp.SyscallRules{
	unix.SYS_CLONE: {
		// parent_tidptr and child_tidptr are always 0 because neither
		// CLONE_PARENT_SETTID nor CLONE_CHILD_SETTID are used.
		{
			seccomp.EqualTo(
				unix.CLONE_VM |
					unix.CLONE_FS |
					unix.CLONE_FILES |
					unix.CLONE_SETTLS |
					unix.CLONE_SIGHAND |
					unix.CLONE_SYSVSEM |
					unix.CLONE_THREAD),
			seccomp.MatchAny{}, // newsp
			seccomp.EqualTo(0), // parent_tidptr
			seccomp.EqualTo(0), // child_tidptr
			seccomp.MatchAny{}, // tls
		},
	},
	unix.SYS_CLOSE: {},
	unix.SYS_EPOLL_CTL: {
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.EPOLL_CTL_ADD),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.EPOLL_CTL_DEL),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
		},
	},
	unix.SYS_EPOLL_PWAIT: {},
	unix.SYS_EXIT_GROUP:  {},
	unix.SYS_FCNTL: {
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_GETFL),
		},
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.F_SETFL),
		},
	},
	unix.SYS_FSTAT: {},
	unix.SYS_FUTEX: {
		seccomp.Rule{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
		seccomp.Rule{
			seccomp.MatchAny{},
			seccomp.EqualTo(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_GETPID:  {},
	unix.SYS_GETTID:  {},
	unix.SYS_MADVISE: {},
	unix.SYS_MMAP: {
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.PROT_READ | unix.PROT_WRITE),
			seccomp.EqualTo(unix.MAP_SHARED),
			seccomp.GreaterThan(0),
			seccomp.EqualTo(0),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.PROT_READ | unix.PROT_WRITE),
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
			seccomp.GreaterThan(0),
			seccomp.EqualTo(0),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.PROT_READ | unix.PROT_WRITE),
			seccomp.EqualTo(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS | unix.MAP_FIXED),
			seccomp.GreaterThan(0),
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_MUNMAP:     {},
	unix.SYS_NANOSLEEP:  {},
	unix.SYS_NEWFSTATAT: {},
	unix.SYS_READ:       {},
	unix.SYS_RECVMSG: {
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.MSG_PEEK),
		},
	},
	unix.SYS_RT_SIGPROCMASK: {},
	unix.SYS_RT_SIGRETURN:   {},
	unix.SYS_SCHED_YIELD:    {},
	unix.SYS_SENDMSG: {
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(0),
		},
	},
	unix.SYS_SIGALTSTACK: {},
	unix.SYS_TGKILL: {
		{
			seccomp.EqualTo(uint64(os.Getpid())),
		},
	},
	unix.SYS_UNAME: {},
	unix.SYS_WRITE: {},
}

var networkSyscalls = seccomp.SyscallRules{
	unix.SYS_CONNECT:     {},
	unix.SYS_GETPEERNAME: {},
	unix.SYS_GETSOCKNAME: {},
	unix.SYS_OPENAT: {
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.O_RDONLY | unix.O_CLOEXEC),
		},
	},
	unix.SYS_SETSOCKOPT: {
		{
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.SOL_SOCKET),
			seccomp.EqualTo(unix.SO_BROADCAST),
			seccomp.MatchAny{},
			seccomp.EqualTo(4),
		},
	},
	unix.SYS_SOCKET: {
		{
			seccomp.EqualTo(unix.AF_INET),
			seccomp.EqualTo(unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		{
			seccomp.EqualTo(unix.AF_INET),
			seccomp.EqualTo(unix.SOCK_DGRAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		{
			seccomp.EqualTo(unix.AF_INET6),
			seccomp.EqualTo(unix.SOCK_STREAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
		{
			seccomp.EqualTo(unix.AF_INET6),
			seccomp.EqualTo(unix.SOCK_DGRAM | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(0),
		},
	},
}

type nullEmitter struct{}

func (nullEmitter) Emit(depth int, level log.Level, timestamp time.Time, format string, v ...interface{}) {
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

	return len(allowedSyscalls), seccomp.Install(allowedSyscalls)
}

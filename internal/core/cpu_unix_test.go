//go:build unix

package core

import (
	"syscall"
	"time"
)

// processCPU is the CPU time this process has used, user and system.
func processCPU() time.Duration {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

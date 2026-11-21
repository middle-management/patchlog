//go:build !unix

package core

import "time"

func processCPU() time.Duration { return 0 }

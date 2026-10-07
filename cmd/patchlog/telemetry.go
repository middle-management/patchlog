package main

import (
	"context"
	"log"
	"runtime/debug"
	"time"

	"github.com/middle-management/patchlog/internal/telemetry"
)

// startTelemetry sets up OpenTelemetry from the OTEL_* environment for the
// subcommand cmd (service.name patchlog-<cmd> unless OTEL_SERVICE_NAME is
// set) and returns the function flushing it. Unconfigured, it does nothing.
func startTelemetry(cmd string) (stop func()) {
	sd, err := telemetry.Setup(context.Background(), "patchlog-"+cmd, buildVersion())
	if err != nil {
		log.Fatalf("OpenTelemetry: %v", err)
	}
	return func() { telemetry.ShutdownWithin(sd, 5*time.Second) }
}

// buildVersion is the version set at build time (-X main.version), else
// the module version go install recorded, else "dev".
func buildVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

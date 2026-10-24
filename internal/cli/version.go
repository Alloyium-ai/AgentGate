// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"flag"
	"runtime"
	"runtime/debug"
)

// version is set at build time:
//
//	go build -ldflags "-X alloyium.local/kernel-poc/internal/cli.version=0.2.6" ./cmd/agentgate
var version = "dev"

// Version is the CLI version, with the source revision when the build
// recorded one.
func Version() string {
	v := version
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				v += "+" + s.Value[:12]
			}
		}
	}
	return v
}

func init() {
	register(&command{name: "version", summary: "Print the CLI version.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error {
			if len(args) != 0 {
				return usageError("version takes no arguments")
			}
			out := map[string]string{"version": e.app.Version, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH}
			if e.g.json {
				return e.p.value(out)
			}
			e.p.line("agentgate %s (%s %s/%s)", out["version"], out["go"], out["os"], out["arch"])
			return nil
		}
	}})
}

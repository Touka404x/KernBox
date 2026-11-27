package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"sandbox_guard/internal/buildinfo"
	"sandbox_guard/internal/daemon"
)

func usage() int {
	fmt.Fprintln(os.Stderr, "usage: sandbox_guard <supervise | ctl <boot|reload-policy|upgrade-begin [ttl]|upgrade-end|bootstrap-pin|status|perf-status|perf-trace|pause-hot|variant-info|preset-apply|sync-hide|sync-policies|set-app-locale|prune-bloat|restore-bloat|flush-sandbox-conns|install-apk|stealth-status|stealth-toggle|start-sandbox|pause-sandbox|block> | version>")
	return 2
}

func main() {
	runtime.GOMAXPROCS(1)
	debug.SetGCPercent(10)
	debug.SetMemoryLimit(2 << 20)
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "version":
		fmt.Println(buildinfo.BuildString())
		return 0
	case "ctl":
		if len(args) < 2 {
			return usage()
		}
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "sandbox_guard requires root")
			return 1
		}
		if err := daemon.RunCtl(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "supervise":
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "sandbox_guard requires root")
			return 1
		}
		d, err := daemon.NewDaemon()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return d.Supervise()
	default:
		return usage()
	}
}

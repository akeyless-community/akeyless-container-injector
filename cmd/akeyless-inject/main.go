package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/akeyless-community/akeyless-container-injector/internal/config"
	"github.com/akeyless-community/akeyless-container-injector/internal/runner"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "init":
		spec, err := config.SpecPath(flagValue(os.Args, "--spec"))
		if err != nil {
			fatal(err)
		}
		if err := runner.Init(ctx, spec); err != nil {
			fatal(err)
		}
	case "run":
		spec, err := config.SpecPath(flagValue(os.Args, "--spec"))
		if err != nil {
			fatal(err)
		}
		cmd, err := commandAfterDoubleDash(os.Args)
		if err != nil {
			fatal(err)
		}
		if err := runner.Run(ctx, spec, cmd); err != nil {
			fatal(err)
		}
	case "watch":
		spec, err := config.SpecPath(flagValue(os.Args, "--spec"))
		if err != nil {
			fatal(err)
		}
		restartCmd := flagValue(os.Args, "--restart-cmd")
		if err := runner.Watch(ctx, spec, restartCmd); err != nil {
			fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func flagValue(args []string, name string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func commandAfterDoubleDash(args []string) ([]string, error) {
	for i, a := range args {
		if a == "--" {
			cmd := args[i+1:]
			if len(cmd) == 0 {
				return nil, fmt.Errorf("command required after --")
			}
			return cmd, nil
		}
	}
	return nil, fmt.Errorf("command required after --")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "akeyless-inject: %v\n", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(`
akeyless-inject — inject Akeyless secrets into Docker/Podman containers

  akeyless-inject init  --spec inject.yaml
  akeyless-inject run   --spec inject.yaml -- <command> [args...]
  akeyless-inject watch --spec inject.yaml [--restart-cmd "docker restart myapp"]

Environment:
  AKEYLESS_ACCESS_ID, AKEYLESS_ACCESS_KEY, AKEYLESS_GATEWAY_URL
  AKEYLESS_ACCESS_TYPE=universal_identity with AKEYLESS_UID_TOKEN or AKEYLESS_UID_TOKEN_FILE
  (default file: ~/.akeyless/uid_rotator/uid-token on Linux/macOS)
  AKEYLESS_INJECT_SPEC (alternative to --spec)

Refresh behavior is configured in the spec file (refresh.interval, refresh.on_change).
`))
}

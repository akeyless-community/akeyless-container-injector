package runner

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/akeyless-community/akeyless-container-injector/internal/akeyless"
	"github.com/akeyless-community/akeyless-container-injector/internal/config"
	"github.com/akeyless-community/akeyless-container-injector/internal/inject"
)

// Init fetches secrets once and writes them to disk/env (compose init-container mode).
func Init(ctx context.Context, specPath string) error {
	spec, err := config.LoadSpec(specPath)
	if err != nil {
		return err
	}
	auth := config.LoadAuth()
	if err := auth.Validate(); err != nil {
		return err
	}
	client, err := akeyless.NewClient(auth)
	if err != nil {
		return err
	}
	if err := client.Authenticate(ctx); err != nil {
		return err
	}
	materials, err := fetchAll(ctx, client, spec)
	if err != nil {
		return err
	}
	res, err := inject.Apply(spec, materials)
	if err != nil {
		return err
	}
	inject.SetProcessEnv(res.Env)
	return nil
}

// Run supervises a child process: inject secrets, poll for changes, restart on change (rollout-restart equivalent).
func Run(ctx context.Context, specPath string, command []string) error {
	if len(command) == 0 {
		return fmt.Errorf("command required after --")
	}
	spec, err := config.LoadSpec(specPath)
	if err != nil {
		return err
	}
	interval, err := spec.RefreshInterval()
	if err != nil {
		return err
	}
	auth := config.LoadAuth()
	if err := auth.Validate(); err != nil {
		return err
	}
	client, err := akeyless.NewClient(auth)
	if err != nil {
		return err
	}
	if err := client.Authenticate(ctx); err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		materials, err := fetchAll(ctx, client, spec)
		if err != nil {
			return err
		}
		res, err := inject.Apply(spec, materials)
		if err != nil {
			return err
		}
		inject.SetProcessEnv(res.Env)

		cmd := execCommand(command)
		cmd.Env = os.Environ()
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start command: %w", err)
		}
		log.Printf("started %q pid=%d", command[0], cmd.Process.Pid)

		restart := make(chan struct{}, 1)
		watchCtx, cancelWatch := context.WithCancel(ctx)
		go pollChanges(watchCtx, client, spec, res.Fingerprints, interval, spec.Refresh.OnChange, restart, cancelWatch)

		select {
		case <-sigCh:
			cancelWatch()
			_ = terminate(cmd.Process)
			return nil
		case err := <-waitProcess(cmd):
			cancelWatch()
			if err != nil {
				return fmt.Errorf("command exited: %w", err)
			}
			return nil
		case <-restart:
			cancelWatch()
			log.Printf("secret change detected; restarting %q", command[0])
			if err := terminate(cmd.Process); err != nil {
				return fmt.Errorf("terminate on secret change: %w", err)
			}
			if _, err := cmd.Process.Wait(); err != nil {
				log.Printf("wait after terminate: %v", err)
			}
			if err := client.Authenticate(ctx); err != nil {
				return fmt.Errorf("re-auth after secret change: %w", err)
			}
		}
	}
}

// Watch polls secrets and either updates files or runs an external restart command (sidecar mode).
func Watch(ctx context.Context, specPath, restartCmd string) error {
	spec, err := config.LoadSpec(specPath)
	if err != nil {
		return err
	}
	interval, err := spec.RefreshInterval()
	if err != nil {
		return err
	}
	auth := config.LoadAuth()
	if err := auth.Validate(); err != nil {
		return err
	}
	client, err := akeyless.NewClient(auth)
	if err != nil {
		return err
	}
	if err := client.Authenticate(ctx); err != nil {
		return err
	}

	materials, err := fetchAll(ctx, client, spec)
	if err != nil {
		return err
	}
	res, err := inject.Apply(spec, materials)
	if err != nil {
		return err
	}
	fps := res.Fingerprints

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := client.Authenticate(ctx); err != nil {
				log.Printf("re-auth failed: %v", err)
				continue
			}
			next, err := fetchAll(ctx, client, spec)
			if err != nil {
				log.Printf("fetch failed: %v", err)
				continue
			}
			changed := diffFingerprints(fps, next)
			if len(changed) == 0 {
				continue
			}
			log.Printf("secret change detected: %v", changed)
			switch spec.Refresh.OnChange {
			case config.OnChangeFile:
				if _, err := inject.Apply(spec, next); err != nil {
					log.Printf("apply files: %v", err)
					continue
				}
			case config.OnChangeRestart:
				if restartCmd == "" {
					log.Printf("on_change=restart but no --restart-cmd provided")
					continue
				}
				if err := runRestartCommand(restartCmd); err != nil {
					log.Printf("restart command failed: %v", err)
					continue
				}
			}
			for p, m := range next {
				fps[p] = m.Fingerprint
			}
		}
	}
}

func fetchAll(ctx context.Context, client *akeyless.Client, spec config.Spec) (map[string]akeyless.Material, error) {
	out := make(map[string]akeyless.Material, len(spec.Secrets))
	for _, target := range spec.Secrets {
		mat, err := client.Fetch(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("fetch %q: %w", target.Path, err)
		}
		out[mat.Path] = mat
	}
	return out, nil
}

func pollChanges(
	ctx context.Context,
	client *akeyless.Client,
	spec config.Spec,
	fps map[string]string,
	interval time.Duration,
	onChange config.OnChangeAction,
	restart chan<- struct{},
	cancel context.CancelFunc,
) {
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := client.Authenticate(ctx); err != nil {
				log.Printf("watch re-auth: %v", err)
				continue
			}
			next, err := fetchAll(ctx, client, spec)
			if err != nil {
				log.Printf("watch fetch: %v", err)
				continue
			}
			if len(diffFingerprints(fps, next)) == 0 {
				continue
			}
			switch onChange {
			case config.OnChangeFile:
				if _, err := inject.Apply(spec, next); err != nil {
					log.Printf("watch apply: %v", err)
					continue
				}
				for p, m := range next {
					fps[p] = m.Fingerprint
				}
			case config.OnChangeRestart:
				select {
				case restart <- struct{}{}:
				default:
				}
				return
			}
		}
	}
}

func diffFingerprints(prev map[string]string, next map[string]akeyless.Material) []string {
	var changed []string
	for path, mat := range next {
		if prev[path] != mat.Fingerprint {
			changed = append(changed, path)
		}
	}
	return changed
}

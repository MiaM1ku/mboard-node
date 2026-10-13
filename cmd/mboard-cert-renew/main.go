// mboard-cert-renew is a root-only one-shot. It prints one redacted JSON object.
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mboard.dev/node/internal/certificate"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	path := "/etc/mboard-node/cert-renew.json"
	check := false
	invalid := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--check":
			check = true
		case "--config":
			i++
			if i >= len(args) || args[i] == "" {
				invalid = true
			} else {
				path = args[i]
			}
		default:
			invalid = true
		}
	}
	if invalid {
		json.NewEncoder(os.Stdout).Encode(certificate.Result{Status: "invalid_arguments"})
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	result, err := certificate.Run(ctx, path, check)
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

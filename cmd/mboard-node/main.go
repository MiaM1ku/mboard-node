package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"mboard.dev/node/internal/node"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mboard-node:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: mboard-node <run|ingest|validate|version> [-config /etc/mboard-node/agent.json]")
	}
	if args[0] == "version" {
		fmt.Println(node.Version)
		return nil
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := fs.String("config", "/etc/mboard-node/agent.json", "agent JSON config")
	file := fs.String("file", "-", "ingest batch JSON file, or - for stdin")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if args[0] != "run" && args[0] != "ingest" && args[0] != "validate" {
		return errors.New("unknown command")
	}
	c, err := node.LoadConfig(*path)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch args[0] {
	case "run":
		return node.Run(ctx, c, os.Stderr)
	case "validate":
		fmt.Println("agent config valid (core/server config not checked)")
		return nil
	case "ingest":
		var r io.Reader = os.Stdin
		if *file != "-" {
			f, err := os.Open(*file)
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}
		b, err := node.ReadBatch(r)
		if err != nil {
			return err
		}
		if err = (node.Spool{Dir: filepath.Join(c.DataDir, "spool")}).Enqueue(b); err != nil {
			return err
		}
		fmt.Println(b.BatchID)
		return nil
	}
	return nil
}

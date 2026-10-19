// Package onepassword reads and writes secrets through the 1Password CLI.
// A value travels on the CLI's standard input and output and is in no
// argument, so it is in no process list.
package onepassword

import (
	"bytes"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"syscall"

	"github.com/maddiecs84/secretferry/internal/ferry"
)

// Binaries are tried in order: `op`, then `op.exe`, which is what WSL has (the
// Windows CLI, reached from Linux).
var Binaries = []string{"op", "op.exe"}

// Runner runs the CLI with these arguments and standard input and returns what
// it printed. A test passes its own.
type Runner func(args []string, stdin string) (string, error)

// ErrNotInstalled means neither `op` nor `op.exe` can be run.
var ErrNotInstalled = ferry.Errorf("The 1Password CLI (`op`, or `op.exe` on WSL) is not installed, not on PATH, or cannot be run.")

// ExecRunner runs the real CLI.
func ExecRunner() Runner { return newRunner(execBinary) }

func execBinary(bin string, args []string, stdin string) (string, error) {
	cmd := exec.Command(bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	// Standard error is dropped: it can name items, and it is never needed.
	err := cmd.Run()
	return out.String(), err
}

// newRunner tries each binary in turn. Only a missing program, or one that
// cannot be run at all (ENOEXEC, EACCES: `op.exe` without WSL interop), moves
// on to the next; an `op` that ran and failed is not run again as `op.exe`.
func newRunner(run func(bin string, args []string, stdin string) (string, error)) Runner {
	return func(args []string, stdin string) (string, error) {
		for _, bin := range Binaries {
			out, err := run(bin, args, stdin)
			if err == nil {
				return out, nil
			}
			if errors.Is(err, exec.ErrNotFound) || errors.Is(err, syscall.ENOEXEC) || errors.Is(err, syscall.EACCES) {
				continue
			}
			return "", err
		}
		return "", ErrNotInstalled
	}
}

// Client reads and writes items in one vault.
type Client struct {
	Vault string
	Run   Runner
}

// Get returns the password of the item with this title. ok is false when there
// is no such item or `op` is not signed in; err is set only when `op` cannot be
// run at all.
func (c *Client) Get(title string) (password string, ok bool, err error) {
	out, runErr := c.Run([]string{"item", "get", title, "--vault", c.Vault, "--fields", "label=password", "--reveal"}, "")
	if runErr != nil {
		if errors.Is(runErr, ErrNotInstalled) {
			return "", false, runErr
		}
		return "", false, nil
	}
	return strings.TrimSuffix(strings.TrimSuffix(out, "\n"), "\r"), true, nil
}

// Create saves a password item. The item is JSON on standard input.
func (c *Client) Create(title, password, notes string) error {
	item := map[string]any{
		"title":    title,
		"category": "PASSWORD",
		"fields": []map[string]string{
			{"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": password},
			{"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": notes},
		},
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		return ferry.Errorf("could not encode the 1Password item")
	}
	if _, err := c.Run([]string{"item", "create", "--vault", c.Vault, "-"}, string(encoded)); err != nil {
		if errors.Is(err, ErrNotInstalled) {
			return err
		}
		return ferry.Errorf("The 1Password CLI could not save the item: is `op` signed in?")
	}
	return nil
}

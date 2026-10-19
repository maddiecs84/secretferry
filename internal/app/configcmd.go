package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/maddiecs84/secretferry/internal/config"
	"github.com/maddiecs84/secretferry/internal/ferry"
)

// dispatchConfig runs `secretferry config validate|init`. Neither needs a token,
// the network or 1Password.
func dispatchConfig(args []string, env Env) ([]string, error) {
	if len(args) == 0 {
		return nil, ferry.Errorf("config needs a subcommand: validate or init.")
	}
	sub, rest := args[0], args[1:]
	allowed, ok := commandFlags["config "+sub]
	if !ok {
		// The word is not quoted: it may be the value itself.
		return nil, ferry.Errorf("Unknown config subcommand. The subcommands are validate and init. %s", valueHint)
	}
	opts, err := parseOptions("config "+sub, rest, allowed)
	if err != nil {
		return nil, err
	}
	if sub == "validate" {
		return runValidate(env, opts)
	}
	return runInit(env, opts)
}

// runValidate loads the configuration, which checks every rule in it, and
// describes what it means: each kind's name form, value rule and the names
// provision would make. Nothing leaves the machine.
func runValidate(env Env, opts *options) ([]string, error) {
	cfg, err := loadConfig(opts.config, env)
	if err != nil {
		return nil, err
	}
	lines := []string{
		fmt.Sprintf("%s is valid.", cfg.Path),
		fmt.Sprintf("Default source: %s", cfg.Source),
		"Secrets:",
	}
	for _, k := range cfg.Kinds {
		generates := "no (a value is supplied with set)"
		if k.Generate != "" {
			generates = k.Generate
		}
		lines = append(lines,
			"  "+k.Kind,
			"    name:      "+k.Template.Form(),
			"    value:     "+k.Rule.Spec(),
			"    generates: "+generates,
		)
		if missing := k.MissingDefaults(); len(missing) > 0 {
			var flags []string
			for _, param := range missing {
				flags = append(flags, "--param "+param+"=<value>")
			}
			lines = append(lines, "    provision needs: "+strings.Join(flags, " "))
			continue
		}
		names, err := k.Names(nil)
		if err != nil {
			return lines, err
		}
		lines = append(lines, "    provisions by default: "+strings.Join(names, ", "))
	}

	// Things that are not wrong in the file but will stop a command that needs them.
	if cfg.Cloudflare.AccountID == "" && strings.TrimSpace(env.Getenv("CLOUDFLARE_ACCOUNT_ID")) == "" {
		lines = append(lines, "Note: no Cloudflare account; set cloudflare.accountId or CLOUDFLARE_ACCOUNT_ID before set, rotate, list, check or provision.")
	}
	if cfg.OnePassword.Vault == "" {
		lines = append(lines, "Note: no 1Password vault; provision and --source 1password need onePassword.vault.")
	}
	return lines, nil
}

// runInit writes a starter secretferry.json, never over a file that is there,
// and checks what it wrote loads.
func runInit(env Env, opts *options) ([]string, error) {
	if opts.account != "" && !config.ValidAccountID(opts.account) {
		// Not quoted, like any word the user typed.
		return nil, ferry.Errorf("--account must be a 32-character Cloudflare account id.")
	}
	path := opts.config
	if path == "" {
		dir, err := env.Getwd()
		if err != nil {
			return nil, ferry.Errorf("could not find the working directory")
		}
		path = filepath.Join(dir, config.FileName)
	}

	text := starterConfig(opts.account, opts.vault)
	if _, err := config.Parse([]byte(text), path); err != nil {
		return nil, err // the starter must itself be valid: a bug here is ours, not the user's
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the path is the one the user gave with --config, or the working directory's
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, ferry.Errorf("%s already exists; init does not overwrite it. Edit it, then run `secretferry config validate`.", path)
		}
		return nil, ferry.Errorf("could not create %s; does its directory exist?", path)
	}
	if _, err := file.WriteString(text); err != nil {
		_ = file.Close()
		return nil, ferry.Errorf("could not write %s", path)
	}
	if err := file.Close(); err != nil {
		return nil, ferry.Errorf("could not write %s", path)
	}

	lines := []string{fmt.Sprintf("Wrote %s with one example secret.", path)}
	if opts.account == "" {
		lines = append(lines, "Add cloudflare.accountId (or set CLOUDFLARE_ACCOUNT_ID) before using it.")
	}
	if opts.vault == "" {
		lines = append(lines, "Add onePassword.vault to use provision or --source 1password.")
	}
	return append(lines, "Replace the example with your own names and rules, then run: secretferry config validate"), nil
}

// starterConfig is a small valid configuration with one example secret to edit.
func starterConfig(account, vault string) string {
	quote := func(s string) string {
		b, _ := json.Marshal(s)
		return string(b)
	}
	var b strings.Builder
	b.WriteString("{\n")
	if account != "" {
		fmt.Fprintf(&b, "  \"cloudflare\": { \"accountId\": %s },\n", quote(account))
	}
	if vault != "" {
		fmt.Fprintf(&b, "  \"onePassword\": { \"vault\": %s },\n", quote(vault))
	}
	b.WriteString(`  "secrets": [
    {
      "kind": "example-key",
      "name": "myapp-{env}-example-key",
      "params": { "env": "(sandbox|staging|production)-[0-9]{2}" },
      "value": { "rule": "base64-32" },
      "generate": "base64-32",
      "defaults": { "env": ["sandbox-01", "staging-01", "production-01"] },
      "rotateWarning": "say in one sentence what replacing this secret loses."
    }
  ]
}
`)
	return b.String()
}

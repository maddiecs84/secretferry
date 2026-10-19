package app

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/maddiecs84/secretferry/internal/config"
	"github.com/maddiecs84/secretferry/internal/ferry"
)

// dispatchConfig runs `secretferry config validate|init`. Neither needs a token,
// the network or 1Password.
func dispatchConfig(args []string, env Env) ([]string, error) {
	if len(args) == 0 {
		return nil, ferry.Errorf("config needs a subcommand: init, add-secret or validate.")
	}
	sub, rest := args[0], args[1:]
	allowed, ok := commandFlags["config "+sub]
	if !ok {
		// The word is not quoted: it may be the value itself.
		return nil, ferry.Errorf("Unknown config subcommand. The subcommands are init, add-secret and validate. %s", valueHint)
	}
	opts, err := parseOptions("config "+sub, rest, allowed)
	if err != nil {
		return nil, err
	}
	switch sub {
	case "validate":
		return runValidate(env, opts)
	case "add-secret":
		return runAddSecret(env, opts)
	default:
		return runInit(env, opts)
	}
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
	}
	if len(cfg.Kinds) == 0 {
		lines = append(lines, "Secrets: none yet. Add one with `secretferry config add-secret` (see the README).")
	} else {
		lines = append(lines, "Secrets:")
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

// runInit writes an empty secretferry.json, never over a file that is there,
// and checks what it wrote loads. Secrets are added with add-secret.
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

	text := config.Render(config.File{
		Cloudflare:  config.Cloudflare{AccountID: opts.account},
		OnePassword: config.OnePassword{Vault: opts.vault},
	})
	if _, err := config.Parse([]byte(text), path); err != nil {
		return nil, err // the starter must itself be valid: a bug here is ours, not the user's
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the path is the one the user gave with --config, or the working directory's
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, ferry.Errorf("%s already exists; init does not overwrite it. Add to it with `secretferry config add-secret`, or check it with `secretferry config validate`.", path)
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

	lines := []string{fmt.Sprintf("Wrote %s with no secrets in it.", path)}
	if opts.account == "" {
		lines = append(lines, "Add cloudflare.accountId (or set CLOUDFLARE_ACCOUNT_ID) before using it.")
	}
	if opts.vault == "" {
		lines = append(lines, "Add onePassword.vault to use provision or --source 1password.")
	}
	return append(lines, "Next, add a secret: secretferry config add-secret --kind <kind> --template <name-template> --pattern <placeholder>=<regex>"), nil
}

// runAddSecret adds one secret to the configuration. The result is checked as a
// whole (a duplicate kind, a template with no pattern, a generate form its own
// rule refuses, a name another secret also produces) before anything is
// written, and the file is replaced in one step, so a refused add leaves it as it was.
func runAddSecret(env Env, opts *options) ([]string, error) {
	if opts.kind == "" || opts.template == "" {
		return nil, ferry.Errorf("add-secret needs --kind and --template, and a --pattern <placeholder>=<regex> for each {placeholder} in the template.")
	}
	path, err := configPath(opts.config, env)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}

	secret := config.Secret{
		Kind:          opts.kind,
		Name:          opts.template,
		Value:         config.ValueRule{Rule: opts.rule, Message: opts.message},
		Generate:      opts.generate,
		RotateWarning: opts.rotateWarning,
	}
	if secret.Params, err = keyValues(opts.patterns, "--pattern", "env=(sandbox|staging|production)-[0-9]{2}"); err != nil {
		return nil, err
	}
	defaults, err := keyValueLists(opts.defaults, "--default", "env=sandbox-01")
	if err != nil {
		return nil, err
	}
	secret.Defaults = defaults

	raw := cfg.Raw
	raw.Secrets = append(append([]config.Secret(nil), raw.Secrets...), secret)
	text := config.Render(raw)
	added, err := config.Parse([]byte(text), path)
	if err != nil {
		return nil, err
	}
	if err := replaceFile(path, []byte(text)); err != nil {
		return nil, err
	}

	kind, _ := added.Kind(opts.kind)
	return []string{
		fmt.Sprintf("Added %s to %s.", kind.Kind, path),
		"  name: " + kind.Template.Form(),
		"Check it with: secretferry config validate",
	}, nil
}

// keyValues reads repeated name=value flags into a map; a name given twice is refused.
func keyValues(pairs []string, flagName, example string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range pairs {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || key == "" || value == "" {
			return nil, ferry.Errorf("%s takes name=value, such as %s %s.", flagName, flagName, example)
		}
		if _, dup := out[key]; dup {
			return nil, ferry.Errorf("%s was given twice for the same placeholder.", flagName)
		}
		out[key] = value
	}
	return out, nil
}

// keyValueLists reads repeated name=value flags into a map of lists, in the order given.
func keyValueLists(pairs []string, flagName, example string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, pair := range pairs {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || key == "" || value == "" {
			return nil, ferry.Errorf("%s takes name=value, such as %s %s.", flagName, flagName, example)
		}
		out[key] = append(out[key], value)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// replaceFile writes data to a temporary file beside path and renames it over
// path, keeping the file's permissions, so a failure part-way leaves the old file.
func replaceFile(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return ferry.Errorf("could not read %s", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".secretferry-*.tmp")
	if err != nil {
		return ferry.Errorf("could not write beside %s", path)
	}
	name := tmp.Name()
	fail := func() error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return ferry.Errorf("could not write %s", path)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail()
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil && runtime.GOOS != "windows" {
		return fail()
	}
	if err := tmp.Close(); err != nil {
		return fail()
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return ferry.Errorf("could not write %s", path)
	}
	return nil
}

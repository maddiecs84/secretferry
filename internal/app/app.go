// Package app is the command line: it parses arguments, reads the project's
// configuration and runs one command against the source and the target. It
// holds every decision about what the commands do; main only wires it to the
// process.
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/maddiecs84/secretferry/internal/config"
	"github.com/maddiecs84/secretferry/internal/ferry"
	"github.com/maddiecs84/secretferry/internal/prompt"
	"github.com/maddiecs84/secretferry/internal/source/onepassword"
	"github.com/maddiecs84/secretferry/internal/target/cloudflare"
	"github.com/maddiecs84/secretferry/internal/value"
)

// Env is everything the commands touch outside themselves, so a test can
// replace each of it.
type Env struct {
	Stdin io.Reader
	// StdinIsTerminal says whether standard input is a person at a terminal, which is
	// what lets `config add-secret` ask questions. Nil means no.
	StdinIsTerminal func() bool
	Stdout          io.Writer
	Stderr          io.Writer
	Getenv          func(string) string
	Getwd           func() (string, error)
	// HTTP and BaseURL point the Cloudflare client somewhere else; empty means the real API.
	HTTP    *http.Client
	BaseURL string
	// OP runs the 1Password CLI.
	OP onepassword.Runner
	// WranglerToken is the optional fallback for a token.
	WranglerToken func() (string, error)
	// ReadValue reads a value at the prompt or from standard input; nil uses the terminal.
	ReadValue func(promptText string) (string, error)
	// Random is where generated values come from; nil means crypto/rand.
	Random  io.Reader
	Version string
}

// DefaultEnv is the real process.
func DefaultEnv(version string) Env {
	return Env{
		Stdin:           os.Stdin,
		StdinIsTerminal: func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
		Getenv:          os.Getenv,
		Getwd:           os.Getwd,
		HTTP:            &http.Client{Timeout: httpTimeout},
		OP:              onepassword.ExecRunner(),
		WranglerToken:   cloudflare.WranglerAuthToken,
		Version:         version,
	}
}

const valueHint = "The value is never an argument: it is read from a prompt or standard input."

const usage = `secretferry moves a secret from where it is kept (1Password) to where it is used
(Cloudflare Secrets Store), without the value ever being an argument, a log line or an
error message.

Usage:
  secretferry set       (--name <name> | --secret <kind> [--param k=v ...]) [--source <source>] [--auto-generate]
  secretferry rotate    (--name <name> | --secret <kind> [--param k=v ...]) --confirm <name> [--source <source>]
  secretferry list
  secretferry check
  secretferry provision (--name <name>... | --secret <kind> [--param k=v ...])
  secretferry config init [--account <id>] [--vault <name>]
  secretferry config add-secret                (in a terminal, with no flags: asks step by step, with defaults)
  secretferry config add-secret --kind <kind> --template <name-template> --pattern <placeholder>=<regex>...
                                [--rule <rule>] [--message <text>] [--generate <form>]
                                [--default <placeholder>=<value>...] [--rotate-warning <text>]
  secretferry config validate
  secretferry version

Every command also takes --config <file> (default: the nearest secretferry.json). config
init, add-secret and validate need no token, network or 1Password: init writes an empty file
(never over one that is there), add-secret adds a secret to it after checking the result is
valid, and validate checks the file and shows what it means.

A name is whatever the configuration's name templates produce. --source says where set and
rotate read the value from: prompt (the default: typed or pasted and shown nowhere on a
terminal, else standard input), stdin (standard input to the end, even on a terminal) or
1password (the item the configuration names). The configuration's "source" sets a default.
With set --auto-generate, a value that is not given (a blank answer, blank standard input, or no
1Password item yet) is made in the secret's "generate" form, saved in 1Password and read back
before it is set. A value that is given but wrong is refused, never replaced. Cloudflare never shows a stored value again, so make
your copy BEFORE the value is set; provision does that for you: it makes the key, saves it
in 1Password, checks it reads back, and only then sets it.

Needs a token that can edit Secrets Store: CLOUDFLARE_API_TOKEN (Account Secrets Store:
Edit), or the login of wrangler (` + "`wrangler login`" + `) when wrangler is on your PATH.
CLOUDFLARE_ACCOUNT_ID overrides the configured account.
`

// Run executes one command line (without the program name) and returns the exit code.
func Run(args []string, env Env) int {
	if len(args) == 0 {
		_, _ = io.WriteString(env.Stdout, usage)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		_, _ = io.WriteString(env.Stdout, usage)
		return 0
	case "version", "--version":
		_, _ = fmt.Fprintf(env.Stdout, "secretferry %s\n", env.Version)
		return 0
	}

	lines, err := dispatch(context.Background(), args, env)
	if len(lines) > 0 {
		_, _ = fmt.Fprintln(env.Stdout, strings.Join(lines, "\n"))
	}
	if err != nil {
		var known *ferry.Error
		if errors.As(err, &known) {
			_, _ = fmt.Fprintln(env.Stderr, known.Error())
		} else {
			// Anything unexpected is shown as a bare fact; it carries no value.
			_, _ = fmt.Fprintln(env.Stderr, "secretferry: an unexpected error stopped the command.")
		}
		return 1
	}
	return 0
}

func dispatch(ctx context.Context, args []string, env Env) ([]string, error) {
	command, rest := args[0], args[1:]
	if command == "config" {
		return dispatchConfig(rest, env)
	}
	allowed, ok := commandFlags[command]
	if !ok {
		// The word is not quoted: it may be the value itself.
		return nil, ferry.Errorf("Unknown command. The commands are set, rotate, list, check, provision, config and version. %s", valueHint)
	}
	opts, err := parseOptions(command, rest, allowed)
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(opts.config, env)
	if err != nil {
		return nil, err
	}
	if command != "list" {
		if err := requireSecrets(cfg); err != nil {
			return nil, err
		}
	}

	switch command {
	case "set":
		return runSet(ctx, env, cfg, opts)
	case "rotate":
		return runRotate(ctx, env, cfg, opts)
	case "list":
		return runList(ctx, env, cfg)
	case "check":
		return runCheck(ctx, env, cfg)
	default:
		return runProvision(ctx, env, cfg, opts)
	}
}

// configPath is --config, else the nearest secretferry.json.
func configPath(path string, env Env) (string, error) {
	if path != "" {
		return path, nil
	}
	dir, err := env.Getwd()
	if err != nil {
		return "", ferry.Errorf("could not find the working directory")
	}
	return config.Find(dir)
}

func loadConfig(path string, env Env) (*config.Config, error) {
	path, err := configPath(path, env)
	if err != nil {
		return nil, err
	}
	return config.Load(path)
}

// requireSecrets refuses a command that acts on a declared secret when the file declares none.
func requireSecrets(cfg *config.Config) error {
	if len(cfg.Kinds) > 0 {
		return nil
	}
	return ferry.Errorf("%s declares no secrets yet. Add one with `secretferry config add-secret` (see the README).", cfg.Path)
}

func connect(ctx context.Context, env Env, cfg *config.Config) (*cloudflare.Store, error) {
	creds, err := cloudflare.ResolveCredentials(cfg.Cloudflare.AccountID, env.Getenv, env.WranglerToken)
	if err != nil {
		return nil, err
	}
	if creds.TokenFrom == "wrangler auth token" {
		_, _ = io.WriteString(env.Stderr, "Using the token from `wrangler auth token`.\n")
	}
	client := cloudflare.New(creds, cfg.Cloudflare.Scopes)
	if env.HTTP != nil {
		client.HTTP = env.HTTP
	}
	if env.BaseURL != "" {
		client.BaseURL = env.BaseURL
	}
	return client.Store(ctx)
}

func vaultClient(env Env, cfg *config.Config) (*onepassword.Client, error) {
	if cfg.OnePassword.Vault == "" {
		return nil, ferry.Errorf("onePassword.vault is not set in %s, and this command reads or writes 1Password.", cfg.Path)
	}
	return &onepassword.Client{Vault: cfg.OnePassword.Vault, Run: env.OP}, nil
}

func readValue(env Env, promptText string) (string, error) {
	if env.ReadValue != nil {
		return env.ReadValue(promptText)
	}
	return prompt.ReadValue(promptText, env.Stdin, env.Stderr)
}

// oneName resolves --name or --secret to exactly one name.
func oneName(cfg *config.Config, opts *options, command string) (string, *config.Kind, error) {
	names, err := resolveNames(cfg, opts, command)
	if err != nil {
		return "", nil, err
	}
	if len(names) != 1 {
		return "", nil, ferry.Errorf("%s acts on one secret at a time, and this names %d.", command, len(names))
	}
	kind, _, _ := cfg.Match(names[0])
	return names[0], kind, nil
}

func resolveNames(cfg *config.Config, opts *options, command string) ([]string, error) {
	if len(opts.names) > 0 && opts.secret != "" {
		return nil, ferry.Errorf("Give --name or --secret, not both.")
	}
	if len(opts.names) > 0 {
		for _, name := range opts.names {
			if _, _, ok := cfg.Match(name); !ok {
				// Not quoted, like every word the user typed that is not yet known to be a name.
				return nil, ferry.Errorf("That is not a name the configuration produces. A name is %s.", cfg.Forms())
			}
		}
		return opts.names, nil
	}
	if opts.secret == "" {
		return nil, ferry.Errorf("%s needs --name (a name is %s), or --secret <kind> (%s) with --param for each placeholder. %s",
			command, cfg.Forms(), strings.Join(cfg.KindNames(), ", "), valueHint)
	}
	kind, ok := cfg.Kind(opts.secret)
	if !ok {
		return nil, ferry.Errorf("There is no such secret kind; the kinds are %s.", strings.Join(cfg.KindNames(), ", "))
	}
	return kind.Names(opts.params)
}

// chooseSource is the --source flag, else the configuration's source, else the prompt.
func chooseSource(cfg *config.Config, opts *options) string {
	if opts.source != "" {
		return opts.source
	}
	return cfg.Source
}

// obtain returns the value to write, from the source the command line or configuration chose.
// absent is set, in place of a value, when the source had none to give: a blank answer or blank
// standard input, or no 1Password item. It holds the message to show if nothing is made instead.
func obtain(env Env, cfg *config.Config, opts *options, kind *config.Kind, name string) (raw string, absent error, err error) {
	switch chooseSource(cfg, opts) {
	case config.SourceOnePassword:
		vault, err := vaultClient(env, cfg)
		if err != nil {
			return "", nil, err
		}
		title := cfg.ItemTitle(name)
		password, found, err := vault.Get(title)
		if err != nil {
			return "", nil, err
		}
		if !found {
			return "", ferry.Errorf("1Password has no item '%s' in the %s vault, or `op` is not signed in.", title, vault.Vault), nil
		}
		return blankIsAbsent(password)
	case config.SourceStdin:
		raw, err := prompt.ReadStdin(env.Stdin, env.Stderr)
		if err != nil {
			return "", nil, err
		}
		return blankIsAbsent(raw)
	default:
		hint := ""
		if opts.autoGenerate && kind.Generate != "" && cfg.OnePassword.Vault != "" {
			hint = "; Enter to have secretferry make one"
		}
		raw, err := readValue(env, fmt.Sprintf("Value for %s (typed characters are not shown%s): ", name, hint))
		if err != nil {
			return "", nil, err
		}
		return blankIsAbsent(raw)
	}
}

// blankIsAbsent says a value that is only whitespace was not given.
func blankIsAbsent(raw string) (string, error, error) {
	if strings.TrimSpace(raw) == "" {
		return "", ferry.Errorf("The value is empty."), nil
	}
	return raw, nil, nil
}

// backup is what finding or making a secret's 1Password copy came to.
type backup struct {
	value   string
	existed bool // the item was already there
	created bool // this run made the value and saved the item
}

// backedUpValue returns the value the secret's 1Password item holds. If there is no item, it makes
// a value in the kind's generate form and saves it as one. Either way it reads the item back and
// stops unless the copy matches, and refuses a value the kind's rule rejects, so what the caller
// goes on to send to Cloudflare, which never shows it again, has a copy that is known to read back.
// label, if any, begins the messages.
func backedUpValue(env Env, cfg *config.Config, vault *onepassword.Client, kind *config.Kind, name, label string) (backup, error) {
	prefix := ""
	if label != "" {
		prefix = label + " "
	}
	title := cfg.ItemTitle(name)

	v, found, err := vault.Get(title)
	if err != nil {
		return backup{}, err
	}
	b := backup{value: v, existed: found}
	if !found {
		if kind.Generate == "" {
			return b, ferry.Errorf("%s1Password has no item '%s', and %q has no \"generate\" in the configuration, so there is nothing to make.", prefix, title, kind.Kind)
		}
		if b.value, err = value.Generate(kind.Generate, env.Random); err != nil {
			return b, err
		}
		notes := fmt.Sprintf("secretferry set --name %s --source 1password", name)
		if err := vault.Create(title, b.value, notes); err != nil {
			return b, err
		}
		b.created = true
	}

	if back, _, err := vault.Get(title); err != nil || back != b.value {
		return b, ferry.Errorf("%sThe 1Password copy does not match; stopped before Cloudflare.", prefix)
	}
	if err := kind.Rule.Check(b.value); err != nil {
		return b, ferry.Errorf("%sThe value in 1Password is not acceptable for %s: %v", prefix, name, err)
	}
	return b, nil
}

func runSet(ctx context.Context, env Env, cfg *config.Config, opts *options) ([]string, error) {
	name, kind, err := oneName(cfg, opts, "set")
	if err != nil {
		return nil, err
	}
	store, err := connect(ctx, env, cfg)
	if err != nil {
		return nil, err
	}
	// Neither command asks for the value until it knows it will write.
	if _, exists, err := store.Lookup(ctx, name); err != nil {
		return nil, err
	} else if exists {
		return nil, ferry.Errorf("%s is already set. To replace its value, use rotate.", name)
	}

	raw, absent, err := obtain(env, cfg, opts, kind, name)
	if err != nil {
		return nil, err
	}
	var v string
	var lines []string
	switch {
	case absent == nil:
		// A value was given. It is used as it is or refused: never replaced by a made one.
		if v, err = checkedValue(raw, kind); err != nil {
			return nil, err
		}
		lines = []string{
			fmt.Sprintf("Set %s.", name),
			"Cloudflare does not show a value again, to anyone, so the only copy is the one you made before this ran (a password manager, or the file it was read from).",
		}
	case !opts.autoGenerate:
		return nil, absent
	default:
		if v, lines, err = autoGenerated(env, cfg, kind, name); err != nil {
			return nil, err
		}
	}
	if err := store.Create(ctx, name, v); err != nil {
		return nil, err
	}
	return lines, nil
}

// autoGenerated is the value for a secret that was given none: whatever its 1Password item already
// holds, or a value made in the kind's generate form and saved as that item first. The lines
// say which, and that the item is now the copy.
func autoGenerated(env Env, cfg *config.Config, kind *config.Kind, name string) (string, []string, error) {
	if cfg.OnePassword.Vault == "" {
		return "", nil, ferry.Errorf("--auto-generate saves the value it makes in 1Password before setting it, so onePassword.vault must be set in %s.", cfg.Path)
	}
	vault, err := vaultClient(env, cfg)
	if err != nil {
		return "", nil, err
	}
	b, err := backedUpValue(env, cfg, vault, kind, name, "")
	if err != nil {
		return "", nil, err
	}
	title := cfg.ItemTitle(name)
	var made string
	if b.created {
		made = fmt.Sprintf("Made the value (%s) and saved it as '%s' in the %s vault, then read it back.", kind.Generate, title, vault.Vault)
	} else {
		made = fmt.Sprintf("No value was given, so it used the one already saved as '%s' in the %s vault.", title, vault.Vault)
	}
	return b.value, []string{
		made,
		fmt.Sprintf("Set %s.", name),
		"Cloudflare does not show a value again, to anyone, so that 1Password item is the copy.",
	}, nil
}

func runRotate(ctx context.Context, env Env, cfg *config.Config, opts *options) ([]string, error) {
	name, kind, err := oneName(cfg, opts, "rotate")
	if err != nil {
		return nil, err
	}
	// A rotation replaces a value Cloudflare cannot give back: the name is typed again, so a
	// recalled command line does not rotate a key by itself (it is no guard against pasting
	// the name twice).
	if opts.confirm != name {
		return nil, ferry.Errorf("rotate replaces the value for good: %s Repeat the name as --confirm %s to go on.", kind.Rotation(), name)
	}
	store, err := connect(ctx, env, cfg)
	if err != nil {
		return nil, err
	}
	id, exists, err := store.Lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, ferry.Errorf("%s is not set yet. To create it, use set.", name)
	}
	v, err := finalValue(env, cfg, opts, kind, name)
	if err != nil {
		return nil, err
	}
	if err := store.Replace(ctx, id, v); err != nil {
		return nil, err
	}
	return []string{
		fmt.Sprintf("Rotated %s.", name),
		"The old value is replaced in place and cannot be read back: anything that depended on it stays unreadable unless the old value was kept.",
	}, nil
}

func finalValue(env Env, cfg *config.Config, opts *options, kind *config.Kind, name string) (string, error) {
	raw, absent, err := obtain(env, cfg, opts, kind, name)
	if err != nil {
		return "", err
	}
	if absent != nil {
		return "", absent
	}
	return checkedValue(raw, kind)
}

// checkedValue is a value as given, once it is known to fit the store and the kind's rule.
func checkedValue(raw string, kind *config.Kind) (string, error) {
	v, err := value.Normalise(raw, cloudflare.MaxSecretBytes)
	if err != nil {
		return "", err
	}
	if err := kind.Rule.Check(v); err != nil {
		return "", err
	}
	return v, nil
}

func runList(ctx context.Context, env Env, cfg *config.Config) ([]string, error) {
	store, err := connect(ctx, env, cfg)
	if err != nil {
		return nil, err
	}
	return store.Names(ctx)
}

// runCheck lists the store's secrets that no name template produces: the ones
// the convention would not have let this tool write.
func runCheck(ctx context.Context, env Env, cfg *config.Config) ([]string, error) {
	store, err := connect(ctx, env, cfg)
	if err != nil {
		return nil, err
	}
	names, err := store.Names(ctx)
	if err != nil {
		return nil, err
	}
	var strays []string
	for _, name := range names {
		if _, _, ok := cfg.Match(name); !ok {
			strays = append(strays, name)
		}
	}
	if len(strays) == 0 {
		return []string{fmt.Sprintf("All %d secrets in the store follow the naming convention.", len(names))}, nil
	}
	lines := []string{"These secrets match no name template in the configuration:"}
	for _, stray := range strays {
		lines = append(lines, "  "+stray)
	}
	return lines, ferry.Errorf("%d of %d secrets do not follow the naming convention.", len(strays), len(names))
}

// runProvision, for each name in order: reuses the 1Password item if an earlier
// run made one (never a second), else makes the key and saves it; reads the
// item back and stops unless it matches; then sets it in Secrets Store unless it
// is already there. Safe to run again after a failure. It returns lines naming
// outcomes only.
func runProvision(ctx context.Context, env Env, cfg *config.Config, opts *options) ([]string, error) {
	names, err := resolveNames(cfg, opts, "provision")
	if err != nil {
		return nil, err
	}
	vault, err := vaultClient(env, cfg)
	if err != nil {
		return nil, err
	}
	store, err := connect(ctx, env, cfg)
	if err != nil {
		return nil, err
	}

	var lines []string
	for _, name := range names {
		kind, _, _ := cfg.Match(name)
		label := "[" + name + "]"
		title := cfg.ItemTitle(name)

		b, err := backedUpValue(env, cfg, vault, kind, name, label)
		switch {
		case b.created:
			lines = append(lines, fmt.Sprintf("%s saved '%s' in the %s vault.", label, title, vault.Vault))
		case b.existed:
			lines = append(lines, fmt.Sprintf("%s 1Password already has '%s'; using that value.", label, title))
		}
		if err != nil {
			return lines, err
		}
		v := b.value

		if _, exists, err := store.Lookup(ctx, name); err != nil {
			return lines, err
		} else if exists {
			lines = append(lines, fmt.Sprintf("%s %s is already set in Secrets Store; nothing to do.", label, name))
			continue
		}
		if err := store.Create(ctx, name, v); err != nil {
			return lines, err
		}
		lines = append(lines, fmt.Sprintf("%s set in Secrets Store.", label))
	}
	return append(lines, "Now check: secretferry list"), nil
}

// ---- options ----

type options struct {
	config  string
	names   []string
	secret  string
	params  map[string][]string
	confirm string
	source  string
	account string
	vault   string

	// set
	autoGenerate bool

	// config add-secret
	kind          string
	template      string
	rule          string
	message       string
	generate      string
	rotateWarning string
	patterns      []string
	defaults      []string
}

var commandFlags = map[string][]string{
	"set":       {"config", "name", "secret", "param", "source", "auto-generate"},
	"rotate":    {"config", "name", "secret", "param", "source", "confirm"},
	"list":      {"config"},
	"check":     {"config"},
	"provision": {"config", "name", "secret", "param"},

	"config validate": {"config"},
	"config init":     {"config", "account", "vault"},
	"config add-secret": {
		"config", "kind", "template", "pattern", "rule", "message", "generate", "default", "rotate-warning",
	},
}

type listFlag struct{ values []string }

func (l *listFlag) String() string     { return strings.Join(l.values, ",") }
func (l *listFlag) Set(s string) error { l.values = append(l.values, s); return nil }

// parseOptions reads the flags a command takes. There is no option for the
// value, and an unknown option or a stray word is refused without being quoted,
// since it may be the value itself.
func parseOptions(command string, args []string, allowed []string) (*options, error) {
	set := flag.NewFlagSet(command, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	has := func(name string) bool {
		for _, a := range allowed {
			if a == name {
				return true
			}
		}
		return false
	}
	var names, params, configs, secrets, confirms, sources, accounts, vaults listFlag
	var kinds, templates, patterns, rules, messages, generates, defaults, warnings listFlag
	var autoGenerate bool
	if has("config") {
		set.Var(&configs, "config", "")
	}
	if has("name") {
		set.Var(&names, "name", "")
	}
	if has("secret") {
		set.Var(&secrets, "secret", "")
	}
	if has("param") {
		set.Var(&params, "param", "")
	}
	if has("confirm") {
		set.Var(&confirms, "confirm", "")
	}
	if has("source") {
		set.Var(&sources, "source", "")
	}
	if has("auto-generate") {
		set.BoolVar(&autoGenerate, "auto-generate", false, "")
	}
	if has("account") {
		set.Var(&accounts, "account", "")
	}
	if has("vault") {
		set.Var(&vaults, "vault", "")
	}
	for flagName, target := range map[string]*listFlag{
		"kind": &kinds, "template": &templates, "pattern": &patterns, "rule": &rules, "message": &messages,
		"generate": &generates, "default": &defaults, "rotate-warning": &warnings,
	} {
		if has(flagName) {
			set.Var(target, flagName, "")
		}
	}

	if err := set.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, ferry.Errorf("%s", strings.TrimSpace(usage))
		}
		return nil, ferry.Errorf("Only --%s are options for %s. %s", strings.Join(allowed, ", --"), command, valueHint)
	}
	if set.NArg() > 0 {
		return nil, ferry.Errorf("Unexpected word. %s", valueHint)
	}

	opts := &options{params: map[string][]string{}, autoGenerate: autoGenerate}
	once := func(flagName string, l listFlag) (string, error) {
		if len(l.values) > 1 {
			return "", ferry.Errorf("--%s was given more than once.", flagName)
		}
		if len(l.values) == 1 {
			return l.values[0], nil
		}
		return "", nil
	}
	var err error
	if opts.config, err = once("config", configs); err != nil {
		return nil, err
	}
	if opts.secret, err = once("secret", secrets); err != nil {
		return nil, err
	}
	if opts.confirm, err = once("confirm", confirms); err != nil {
		return nil, err
	}
	if opts.source, err = once("source", sources); err != nil {
		return nil, err
	}
	if opts.account, err = once("account", accounts); err != nil {
		return nil, err
	}
	if opts.vault, err = once("vault", vaults); err != nil {
		return nil, err
	}
	for flagName, dest := range map[string]struct {
		from listFlag
		to   *string
	}{
		"kind": {kinds, &opts.kind}, "template": {templates, &opts.template}, "rule": {rules, &opts.rule},
		"message": {messages, &opts.message}, "generate": {generates, &opts.generate},
		"rotate-warning": {warnings, &opts.rotateWarning},
	} {
		if *dest.to, err = once(flagName, dest.from); err != nil {
			return nil, err
		}
	}
	opts.patterns, opts.defaults = patterns.values, defaults.values
	// Not quoted, like every word the user typed that is not yet known to be one of ours.
	if opts.source != "" && !config.ValidSource(opts.source) {
		return nil, ferry.Errorf("That is not a source; the sources are %s.", strings.Join(config.Sources, ", "))
	}
	opts.names = names.values
	if command != "provision" && len(names.values) > 1 {
		return nil, ferry.Errorf("--name was given more than once.")
	}
	for _, p := range params.values {
		key, val, ok := strings.Cut(p, "=")
		if !ok || key == "" || val == "" {
			return nil, ferry.Errorf("--param takes name=value, such as --param env=staging.")
		}
		opts.params[key] = append(opts.params[key], val)
	}
	return opts, nil
}

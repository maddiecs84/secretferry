package app

import (
	"bufio"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/maddiecs84/secretferry/internal/config"
	"github.com/maddiecs84/secretferry/internal/ferry"
	"github.com/maddiecs84/secretferry/internal/naming"
	"github.com/maddiecs84/secretferry/internal/value"
)

var errCancelled = ferry.Errorf("Cancelled; nothing was written.")

var (
	kindRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	nonKindChars = regexp.MustCompile(`[^a-z0-9]+`)
)

// What a placeholder is offered, by its name. Anything else is a word, or letters and
// digits joined by hyphens; the person can type their own for any of them.
const (
	patternEnv     = "(sandbox|staging|production)-[0-9]{2}"
	patternVersion = "[1-9][0-9]{0,5}"
	patternWord    = "[a-z0-9]+(-[a-z0-9]+)*"
	defaultsEnv    = "sandbox-01,staging-01,production-01"
	standardWarn   = "the standard warning"
)

func defaultPattern(placeholder string) string {
	switch placeholder {
	case "env":
		return patternEnv
	case "version":
		return patternVersion
	default:
		return patternWord
	}
}

// project is a name for the project the configuration is in: the directory it
// lives in, as lower-case words, for the default name template.
func project(configPath string) string {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		abs = configPath
	}
	name := strings.Trim(nonKindChars.ReplaceAllString(strings.ToLower(filepath.Base(filepath.Dir(abs))), "-"), "-")
	if name == "" {
		return "myapp"
	}
	return name
}

// asker puts questions to a person and reads their answers a line at a time. What
// is typed is not secret (names, patterns, sentences), so it is shown.
type asker struct {
	in  *bufio.Reader
	env Env
}

func (a *asker) say(format string, args ...any) {
	_, _ = fmt.Fprintf(a.env.Stdout, format, args...)
}

// line reads one answer. Running out of input before any is typed cancels the whole setup.
func (a *asker) line(prompt string) (string, error) {
	a.say("%s", prompt)
	text, err := a.in.ReadString('\n')
	if err != nil && text == "" {
		a.say("\n")
		return "", errCancelled
	}
	return strings.TrimSpace(text), nil
}

// ask puts a question until check accepts the answer. An empty answer takes the default, if
// there is one. check sees the empty answer too when there is no default, so it decides whether
// an answer is needed.
func (a *asker) ask(question, def string, check func(string) error) (string, error) {
	prompt := question
	if def != "" {
		prompt += " [" + def + "]"
	}
	prompt += ": "
	for {
		answer, err := a.line(prompt)
		if err != nil {
			return "", err
		}
		if answer == "" {
			answer = def
		}
		if check != nil {
			if err := check(answer); err != nil {
				a.say("  %s\n", err.Error())
				continue
			}
		}
		return answer, nil
	}
}

// choose offers numbered options, the default being the one in def (counting from 1).
func (a *asker) choose(question string, options []string, def int) (int, error) {
	a.say("%s\n", question)
	for i, option := range options {
		a.say("  %d. %s\n", i+1, option)
	}
	answer, err := a.ask("Choice", strconv.Itoa(def), func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > len(options) {
			return ferry.Errorf("Choose a number from 1 to %d.", len(options))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	n, _ := strconv.Atoi(answer)
	return n, nil
}

// runGuided asks for each part of a secret in turn, offering a default where there is a sensible
// one, shows what it will add and the flags that would do the same, and adds it once confirmed.
func runGuided(env Env, cfg *config.Config, path string) ([]string, error) {
	a := &asker{in: bufio.NewReader(env.Stdin), env: env}
	a.say("Adding a secret to %s. Press Enter to accept a default shown in [brackets]; Ctrl-C to stop.\n\n", path)

	taken := map[string]bool{}
	for _, k := range cfg.Kinds {
		taken[k.Kind] = true
	}
	suggestion := ""
	if !taken["api-key"] {
		suggestion = "api-key"
	}
	kind, err := a.ask("Kind: a short name for this secret, such as signing-key", suggestion, func(s string) error {
		switch {
		case s == "":
			return ferry.Errorf("A kind is needed.")
		case !kindRe.MatchString(s):
			return ferry.Errorf("A kind is lower-case letters, digits and hyphens.")
		case taken[s]:
			return ferry.Errorf("There is already a secret of that kind.")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	a.say("\nA name template says how the secret is named in each place it is used. {env} is a\nplaceholder: it is filled in with a different value for each.\n")
	template, err := a.ask("Name template", project(path)+"-{env}-"+kind, func(s string) error {
		if s == "" {
			return ferry.Errorf("A name template is needed.")
		}
		probe := map[string]string{}
		for _, p := range naming.Placeholders(s) {
			probe[p] = ".*"
		}
		_, err := naming.Compile(s, probe)
		return err
	})
	if err != nil {
		return nil, err
	}

	placeholders := naming.Placeholders(template)
	patterns := map[string]string{}
	if len(placeholders) > 0 {
		a.say("\nEach placeholder is held to a pattern (a regular expression the whole value must match).\n")
	}
	for _, p := range placeholders {
		patterns[p], err = a.ask(fmt.Sprintf("Pattern for {%s}", p), defaultPattern(p), func(s string) error {
			if s == "" {
				return ferry.Errorf("A pattern is needed.")
			}
			if _, err := regexp.Compile("^(?:" + s + ")$"); err != nil {
				return ferry.Errorf("That is not a valid regular expression.")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	compiled, err := naming.Compile(template, patterns)
	if err != nil {
		return nil, err
	}

	secret := config.Secret{Kind: kind, Name: template, Params: patterns}
	if len(patterns) == 0 {
		secret.Params = nil
	}

	a.say("\n")
	who, err := a.choose("Who makes the value?", []string{
		"secretferry makes it: 32 random bytes as padded base64",
		"secretferry makes it: 32 random bytes as base64url (no padding)",
		"someone else issues it, and you supply it with `set`",
	}, 1)
	if err != nil {
		return nil, err
	}
	generated := who != 3
	switch who {
	case 1:
		secret.Generate, secret.Value.Rule = "base64-32", "base64-32"
	case 2:
		secret.Generate, secret.Value.Rule = "base64url-32", "base64url-32"
	default:
		a.say("\n")
		secret.Value.Rule, err = a.ask("What must the value look like? (any, base64-32, base64url-32, printable, regex:<pattern>)", "printable", func(s string) error {
			_, err := value.ParseRule(s, "")
			return err
		})
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(secret.Value.Rule, "regex:") {
			secret.Value.Message, err = a.ask("What should it say when a value does not match? (Enter for the standard text)", "", nil)
			if err != nil {
				return nil, err
			}
		}
	}

	if len(placeholders) > 0 {
		a.say("\nprovision can make every environment's secret in one go. Give the values it should use\nfor each placeholder, separated by commas (Enter for none: then give them with --param).\n")
	}
	for _, p := range placeholders {
		def := ""
		if generated && p == "env" {
			def = defaultsEnv
		}
		answer, err := a.ask(fmt.Sprintf("Values for {%s}", p), def, func(s string) error {
			for _, v := range splitList(s) {
				if !compiled.Check(p, v) {
					return ferry.Errorf("%q does not match the pattern for {%s}.", v, p)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if values := splitList(answer); len(values) > 0 {
			if secret.Defaults == nil {
				secret.Defaults = map[string][]string{}
			}
			secret.Defaults[p] = values
		}
	}

	a.say("\n")
	warning, err := a.ask("What does replacing it lose? One sentence, shown when someone rotates it (Enter for "+standardWarn+")", "", nil)
	if err != nil {
		return nil, err
	}
	secret.RotateWarning = warning

	a.say("\nThis will add to %s:\n", path)
	a.say("  kind:  %s\n  name:  %s\n  value: %s%s\n", secret.Kind, compiled.Form(), secret.Value.Rule, madeBy(secret))
	if names, err := namesFor(secret, compiled); err == nil && len(names) > 0 {
		a.say("  provision makes by default: %s\n", strings.Join(names, ", "))
	}
	a.say("The same thing as a command:\n  %s\n\n", commandLine(secret))

	sure, err := a.ask("Add it?", "Y", func(s string) error {
		if !strings.EqualFold(s, "y") && !strings.EqualFold(s, "n") && !strings.EqualFold(s, "yes") && !strings.EqualFold(s, "no") {
			return ferry.Errorf("Answer y or n.")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.ToLower(sure), "n") {
		return []string{"Nothing was written."}, nil
	}

	lines, err := commitSecret(cfg, path, secret)
	if err != nil {
		return nil, ferry.Errorf("%v Nothing was written.", err)
	}
	return lines, nil
}

func madeBy(s config.Secret) string {
	if s.Generate != "" {
		return ", made by secretferry"
	}
	return ", supplied with set"
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// namesFor is the names provision would make from the secret's defaults.
func namesFor(s config.Secret, t *naming.Template) ([]string, error) {
	if len(s.Defaults) == 0 && len(t.Params()) > 0 {
		return nil, nil
	}
	k := &config.Kind{Secret: s, Template: t}
	return k.Names(nil)
}

// commandLine is the add-secret command that describes the secret, as a POSIX shell would take it.
func commandLine(s config.Secret) string {
	parts := []string{"secretferry", "config", "add-secret"}
	for _, arg := range secretArgs(s) {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

// secretArgs are the add-secret flags that describe the secret: what secretFromOptions reads back.
func secretArgs(s config.Secret) []string {
	args := []string{"--kind", s.Kind, "--template", s.Name}
	for _, p := range naming.Placeholders(s.Name) {
		if pattern, ok := s.Params[p]; ok {
			args = append(args, "--pattern", p+"="+pattern)
		}
	}
	if s.Value.Rule != "" {
		args = append(args, "--rule", s.Value.Rule)
	}
	if s.Value.Message != "" {
		args = append(args, "--message", s.Value.Message)
	}
	if s.Generate != "" {
		args = append(args, "--generate", s.Generate)
	}
	for _, p := range naming.Placeholders(s.Name) {
		for _, v := range s.Defaults[p] {
			args = append(args, "--default", p+"="+v)
		}
	}
	if s.RotateWarning != "" {
		args = append(args, "--rotate-warning", s.RotateWarning)
	}
	return args
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// shellQuote quotes one word for a POSIX shell, leaving a plain word as it is.
func shellQuote(word string) string {
	if shellSafe.MatchString(word) {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
}

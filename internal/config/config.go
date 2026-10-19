// Package config reads a project's secretferry.json: which account and vault
// it uses, and the naming convention and value rule of each kind of secret.
// Nothing project-specific lives in the tool itself.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/maddiecs84/secretferry/internal/ferry"
	"github.com/maddiecs84/secretferry/internal/naming"
	"github.com/maddiecs84/secretferry/internal/value"
)

// FileName is what Find looks for, in the working directory and then each parent.
const FileName = "secretferry.json"

// DefaultItemTitle names a 1Password item when the configuration does not.
const DefaultItemTitle = "secretferry - {name}"

var (
	accountRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	kindRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
)

// File is secretferry.json as written.
type File struct {
	Cloudflare  Cloudflare  `json:"cloudflare"`
	OnePassword OnePassword `json:"onePassword"`
	Secrets     []Secret    `json:"secrets"`
}

// Cloudflare is where secrets are written.
type Cloudflare struct {
	// AccountID is the 32-character account id. CLOUDFLARE_ACCOUNT_ID overrides it.
	AccountID string `json:"accountId"`
	// Scopes are the services allowed to bind a new secret (default: workers).
	Scopes []string `json:"scopes"`
}

// OnePassword is where the copy of a secret that outlives the store is kept.
type OnePassword struct {
	Vault string `json:"vault"`
	// ItemTitle is the title of a secret's item; {name} is the secret's name.
	ItemTitle string `json:"itemTitle"`
}

// Secret is one kind of secret: how it is named, what its value must be, and
// what to say when it is replaced.
type Secret struct {
	// Kind is the short name the --secret flag takes.
	Kind string `json:"kind"`
	// Name is the name template, such as "acme-{env}-api-key".
	Name string `json:"name"`
	// Params gives each {placeholder} a regular expression its value must match in full.
	Params map[string]string `json:"params"`
	// Value is the rule the value is held to: any, base64-32, base64url-32, printable or regex:<pattern>.
	Value ValueRule `json:"value"`
	// Generate makes the value when provisioning: base64-32 or base64url-32. Empty means
	// the tool cannot make this secret, only set a value you supply.
	Generate string `json:"generate"`
	// Defaults are the values each placeholder takes when provision is given none, one run per combination.
	Defaults map[string][]string `json:"defaults"`
	// RotateWarning says what replacing the value loses, so rotation asks for the name twice.
	RotateWarning string `json:"rotateWarning"`
}

// ValueRule is a rule and, optionally, the message a failure shows.
type ValueRule struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// Kind is a Secret with its template and rule compiled.
type Kind struct {
	Secret
	Template *naming.Template
	Rule     value.Rule
}

// Config is a validated configuration.
type Config struct {
	File
	Path  string
	Kinds []*Kind
}

// Find returns the path of secretferry.json in dir or the nearest parent.
func Find(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", ferry.Errorf("could not resolve the working directory")
	}
	for {
		candidate := filepath.Join(dir, FileName)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ferry.Errorf("no %s found here or in a parent directory; create one (see the README) or pass --config", FileName)
		}
		dir = parent
	}
}

// Load reads and validates the file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is the one the user gave with --config, or found by walking up
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ferry.Errorf("the configuration file %s does not exist", path)
		}
		return nil, ferry.Errorf("could not read %s", path)
	}
	return Parse(data, path)
}

// Parse validates configuration text. path is only used in messages.
func Parse(data []byte, path string) (*Config, error) {
	var file File
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, ferry.Errorf("%s is not valid: %v", path, err)
	}
	if decoder.More() {
		return nil, ferry.Errorf("%s has more than one JSON document", path)
	}
	cfg := &Config{File: file, Path: path}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Cloudflare.AccountID != "" && !accountRe.MatchString(c.Cloudflare.AccountID) {
		return ferry.Errorf("cloudflare.accountId must be a 32-character account id")
	}
	if c.OnePassword.ItemTitle == "" {
		c.OnePassword.ItemTitle = DefaultItemTitle
	}
	if strings.Count(c.OnePassword.ItemTitle, "{name}") != 1 {
		return ferry.Errorf("onePassword.itemTitle must contain {name} exactly once")
	}
	if len(c.Cloudflare.Scopes) == 0 {
		c.Cloudflare.Scopes = []string{"workers"}
	}
	if len(c.Secrets) == 0 {
		return ferry.Errorf("%s declares no secrets; add at least one entry to \"secrets\"", c.Path)
	}

	seen := map[string]bool{}
	for i := range c.Secrets {
		s := c.Secrets[i]
		if !kindRe.MatchString(s.Kind) {
			return ferry.Errorf("secrets[%d].kind must be lower-case letters, digits and hyphens", i)
		}
		if seen[s.Kind] {
			return ferry.Errorf("the kind %q is declared twice", s.Kind)
		}
		seen[s.Kind] = true

		template, err := naming.Compile(s.Name, s.Params)
		if err != nil {
			return ferry.Errorf("secret %q: %v", s.Kind, err)
		}
		rule, err := value.ParseRule(s.Value.Rule, s.Value.Message)
		if err != nil {
			return ferry.Errorf("secret %q: %v", s.Kind, err)
		}
		if s.Generate != "" {
			if _, err := value.Generate(s.Generate, strings.NewReader(strings.Repeat("x", 32))); err != nil {
				return ferry.Errorf("secret %q: %v", s.Kind, err)
			}
		}
		for param, values := range s.Defaults {
			if !hasParam(template, param) {
				return ferry.Errorf("secret %q: defaults names {%s}, which the name does not use", s.Kind, param)
			}
			for _, v := range values {
				if !template.Check(param, v) {
					return ferry.Errorf("secret %q: the default %q is not a valid {%s}", s.Kind, v, param)
				}
			}
		}
		c.Kinds = append(c.Kinds, &Kind{Secret: s, Template: template, Rule: rule})
	}
	return nil
}

func hasParam(t *naming.Template, name string) bool {
	for _, p := range t.Params() {
		if p == name {
			return true
		}
	}
	return false
}

// Match finds the kind whose template produces name, and the placeholder
// values it was made from. ok is false for a name no kind produces.
func (c *Config) Match(name string) (kind *Kind, params map[string]string, ok bool) {
	for _, k := range c.Kinds {
		if values, matched := k.Template.Parse(name); matched {
			return k, values, true
		}
	}
	return nil, nil, false
}

// Kind returns the kind declared under this short name.
func (c *Config) Kind(name string) (*Kind, bool) {
	for _, k := range c.Kinds {
		if k.Kind == name {
			return k, true
		}
	}
	return nil, false
}

// Forms describes every name the configuration produces, for a message.
func (c *Config) Forms() string {
	forms := make([]string, 0, len(c.Kinds))
	for _, k := range c.Kinds {
		forms = append(forms, k.Template.Form())
	}
	return strings.Join(forms, " or ")
}

// KindNames lists the declared kinds, sorted.
func (c *Config) KindNames() []string {
	names := make([]string, 0, len(c.Kinds))
	for _, k := range c.Kinds {
		names = append(names, k.Kind)
	}
	sort.Strings(names)
	return names
}

// ItemTitle is the 1Password item that holds the named secret.
func (c *Config) ItemTitle(name string) string {
	return strings.Replace(c.OnePassword.ItemTitle, "{name}", name, 1)
}

// Names expands a kind into the names to provision: the cartesian product of
// the values given for each placeholder, falling back to the kind's defaults.
// Every placeholder must end up with at least one value.
func (k *Kind) Names(given map[string][]string) ([]string, error) {
	for param := range given {
		if !hasParam(k.Template, param) {
			return nil, ferry.Errorf("secret %q has no such placeholder", k.Kind)
		}
	}
	combos := []map[string]string{{}}
	for _, param := range k.Template.Params() {
		values := given[param]
		if len(values) == 0 {
			values = k.Defaults[param]
		}
		if len(values) == 0 {
			return nil, ferry.Errorf("secret %q needs a value for {%s}: --param %s=<value>", k.Kind, param, param)
		}
		var next []map[string]string
		for _, combo := range combos {
			for _, v := range values {
				extended := map[string]string{param: v}
				for key, existing := range combo {
					extended[key] = existing
				}
				next = append(next, extended)
			}
		}
		combos = next
	}
	names := make([]string, 0, len(combos))
	for _, combo := range combos {
		name, err := k.Template.Build(combo)
		if err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// Rotation is what to say rotation loses.
func (k *Kind) Rotation() string {
	if k.RotateWarning != "" {
		return k.RotateWarning
	}
	return "the old value is gone from here, so keep it until the new one is checked."
}

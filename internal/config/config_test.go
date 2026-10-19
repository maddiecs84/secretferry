package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const examplePath = "../../examples/secretferry.json"

func loadExample(t *testing.T) *Config {
	t.Helper()
	cfg, err := Load(examplePath)
	if err != nil {
		t.Fatalf("the example configuration does not load: %v", err)
	}
	return cfg
}

func TestTheExampleLoadsAndEveryKindWorks(t *testing.T) {
	cfg := loadExample(t)
	if got := strings.Join(cfg.KindNames(), ","); got != "signing-key,vendor-api-key,wrapping-key" {
		t.Fatalf("kinds = %s", got)
	}
	for _, kind := range cfg.Kinds {
		given := map[string][]string{"env": {"sandbox-01"}}
		for _, param := range kind.Template.Params() {
			if param == "version" {
				given["version"] = []string{"1"}
			}
		}
		names, err := kind.Names(given)
		if err != nil {
			t.Fatalf("%s: %v", kind.Kind, err)
		}
		for _, name := range names {
			matched, _, ok := cfg.Match(name)
			if !ok || matched.Kind != kind.Kind {
				t.Errorf("%s produced %q, which matches %v", kind.Kind, name, matched)
			}
		}
	}
}

func TestMatchAndForms(t *testing.T) {
	cfg := loadExample(t)

	kind, params, ok := cfg.Match("acme-production-01-wrapping-key-3")
	if !ok || kind.Kind != "wrapping-key" || params["env"] != "production-01" || params["version"] != "3" {
		t.Fatalf("Match = %v, %v, %v", kind, params, ok)
	}
	for _, name := range []string{"acme-qa-01-signing-key", "acme-sandbox-01-wrapping-key-0", "other-sandbox-01-signing-key", ""} {
		if _, _, ok := cfg.Match(name); ok {
			t.Errorf("Match accepted %q", name)
		}
	}
	forms := cfg.Forms()
	for _, want := range []string{"acme-<env>-signing-key", "acme-<env>-wrapping-key-<version>"} {
		if !strings.Contains(forms, want) {
			t.Errorf("Forms() = %q, missing %q", forms, want)
		}
	}
}

func TestNamesExpandDefaultsAndOverrides(t *testing.T) {
	cfg := loadExample(t)
	signing, _ := cfg.Kind("signing-key")

	got, err := signing.Names(nil)
	want := []string{"acme-production-01-signing-key", "acme-sandbox-01-signing-key", "acme-staging-01-signing-key"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("defaults: %v, %v", got, err)
	}

	got, err = signing.Names(map[string][]string{"env": {"staging-01"}})
	if err != nil || !reflect.DeepEqual(got, []string{"acme-staging-01-signing-key"}) {
		t.Fatalf("override: %v, %v", got, err)
	}
}

func TestNamesIsTheProductOfEveryPlaceholder(t *testing.T) {
	wrapping, _ := loadExample(t).Kind("wrapping-key")
	got, err := wrapping.Names(map[string][]string{"env": {"sandbox-01", "staging-01"}, "version": {"1", "2"}})
	if err != nil || len(got) != 4 {
		t.Fatalf("Names = %v, %v", got, err)
	}
}

func TestNamesRefusals(t *testing.T) {
	cfg := loadExample(t)
	wrapping, _ := cfg.Kind("wrapping-key")
	vendor, _ := cfg.Kind("vendor-api-key")

	// version has no default, so it must be given.
	if _, err := wrapping.Names(nil); err == nil || !strings.Contains(err.Error(), "{version}") {
		t.Errorf("a placeholder with no value: %v", err)
	}
	// vendor-api-key has no defaults at all.
	if _, err := vendor.Names(nil); err == nil || !strings.Contains(err.Error(), "{env}") {
		t.Errorf("no defaults: %v", err)
	}
	if _, err := vendor.Names(map[string][]string{"env": {"nowhere-01"}}); err == nil {
		t.Error("a value the pattern rejects was accepted")
	}
	if _, err := vendor.Names(map[string][]string{"env": {"sandbox-01"}, "typo": {"x"}}); err == nil {
		t.Error("a placeholder the name does not have was accepted")
	}
}

func TestItemTitleAndRotation(t *testing.T) {
	cfg := loadExample(t)
	if got := cfg.ItemTitle("acme-x"); got != "secretferry - acme-x" {
		t.Errorf("ItemTitle = %q", got)
	}
	signing, _ := cfg.Kind("signing-key")
	if !strings.Contains(signing.Rotation(), "stops verifying") {
		t.Errorf("Rotation = %q", signing.Rotation())
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`{"secrets":[{"kind":"k","name":"n"}]}`), "test.json")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OnePassword.ItemTitle != DefaultItemTitle {
		t.Errorf("itemTitle = %q", cfg.OnePassword.ItemTitle)
	}
	if !reflect.DeepEqual(cfg.Cloudflare.Scopes, []string{"workers"}) {
		t.Errorf("scopes = %v", cfg.Cloudflare.Scopes)
	}
	k := cfg.Kinds[0]
	if k.Rule.Spec() != "any" || !strings.Contains(k.Rotation(), "keep it until") {
		t.Errorf("rule %q, rotation %q", k.Rule.Spec(), k.Rotation())
	}
}

func TestValidationRefusals(t *testing.T) {
	const ok = `{"kind":"k","name":"acme-{env}","params":{"env":"[a-z]+"}`
	cases := map[string]struct{ json, want string }{
		"unknown field":       {`{"secrets":[],"surprise":1}`, "surprise"},
		"not json":            {`{`, "not valid"},
		"two documents":       {`{"secrets":[{"kind":"k","name":"n"}]} {}`, "more than one"},
		"bad account":         {`{"cloudflare":{"accountId":"nope"},"secrets":[{"kind":"k","name":"n"}]}`, "accountId"},
		"title no name":       {`{"onePassword":{"itemTitle":"fixed"},"secrets":[{"kind":"k","name":"n"}]}`, "{name}"},
		"title two names":     {`{"onePassword":{"itemTitle":"{name}{name}"},"secrets":[{"kind":"k","name":"n"}]}`, "exactly once"},
		"bad kind":            {`{"secrets":[{"kind":"Bad Kind","name":"n"}]}`, "kind"},
		"duplicate kind":      {`{"secrets":[{"kind":"k","name":"a"},{"kind":"k","name":"b"}]}`, "twice"},
		"bad template":        {`{"secrets":[{"kind":"k","name":"a-{x}"}]}`, "no pattern"},
		"bad rule":            {`{"secrets":[{"kind":"k","name":"n","value":{"rule":"hex"}}]}`, "unknown value rule"},
		"bad generator":       {`{"secrets":[{"kind":"k","name":"n","generate":"hex"}]}`, "cannot generate"},
		"default off name":    {`{"secrets":[` + ok + `,"defaults":{"nope":["a"]}}]}`, "does not use"},
		"default off pattern": {`{"secrets":[` + ok + `,"defaults":{"env":["UPPER"]}}]}`, "not a valid"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.json), "test.json")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want one containing %q", err, c.want)
			}
		})
	}
}

func TestFindWalksUp(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(deep); err == nil || !strings.Contains(err.Error(), FileName) {
		t.Fatalf("with no file: %v", err)
	}
	want := filepath.Join(root, "a", FileName)
	if err := os.WriteFile(want, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Find(deep)
	if err != nil || got != want {
		t.Errorf("Find = %q, %v; want %q", got, err, want)
	}
	// A directory with the file's name is not the file.
	if err := os.MkdirAll(filepath.Join(deep, FileName), 0o750); err != nil {
		t.Fatal(err)
	}
	if got, _ := Find(deep); got != want {
		t.Errorf("a directory named %s was taken for the file: %q", FileName, got)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %v", err)
	}
}

func TestSourceDefaultsToThePromptAndIsChecked(t *testing.T) {
	cfg, err := Parse([]byte(`{"secrets":[{"kind":"k","name":"n"}]}`), "test.json")
	if err != nil || cfg.Source != SourcePrompt {
		t.Fatalf("source = %q, %v", cfg.Source, err)
	}
	for _, source := range []string{SourcePrompt, SourceStdin} {
		if _, err := Parse([]byte(`{"source":"`+source+`","secrets":[{"kind":"k","name":"n"}]}`), "test.json"); err != nil {
			t.Errorf("source %q: %v", source, err)
		}
	}

	if _, err := Parse([]byte(`{"source":"bitwarden","secrets":[{"kind":"k","name":"n"}]}`), "test.json"); err == nil || !strings.Contains(err.Error(), "prompt, stdin, 1password") {
		t.Errorf("an unknown source: %v", err)
	}
	// A source that reads the vault needs a vault, and that is found when the file loads.
	if _, err := Parse([]byte(`{"source":"1password","secrets":[{"kind":"k","name":"n"}]}`), "test.json"); err == nil || !strings.Contains(err.Error(), "onePassword.vault") {
		t.Errorf("1password without a vault: %v", err)
	}
	if _, err := Parse([]byte(`{"source":"1password","onePassword":{"vault":"V"},"secrets":[{"kind":"k","name":"n"}]}`), "test.json"); err != nil {
		t.Errorf("1password with a vault: %v", err)
	}
}

func TestAGeneratedValueMustPassItsOwnRule(t *testing.T) {
	const kind = `"kind":"k","name":"n"`
	for name, c := range map[string]struct {
		secret string
		ok     bool
	}{
		"matching form":         {`{` + kind + `,"value":{"rule":"base64-32"},"generate":"base64-32"}`, true},
		"matching url form":     {`{` + kind + `,"value":{"rule":"base64url-32"},"generate":"base64url-32"}`, true},
		"no rule at all":        {`{` + kind + `,"generate":"base64-32"}`, true},
		"a custom pattern met":  {`{` + kind + `,"value":{"rule":"regex:[A-Za-z0-9+/]{43}="},"generate":"base64-32"}`, true},
		"padded rule, url form": {`{` + kind + `,"value":{"rule":"base64-32"},"generate":"base64url-32"}`, false},
		"url rule, padded form": {`{` + kind + `,"value":{"rule":"base64url-32"},"generate":"base64-32"}`, false},
		"a pattern never met":   {`{` + kind + `,"value":{"rule":"regex:sk-.*"},"generate":"base64-32"}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(`{"secrets":[`+c.secret+`]}`), "test.json")
			switch {
			case c.ok && err != nil:
				t.Errorf("refused: %v", err)
			case !c.ok && (err == nil || !strings.Contains(err.Error(), "does not pass its own value rule")):
				t.Errorf("error = %v", err)
			}
		})
	}
}

func TestTwoKindsMayNotProduceTheSameName(t *testing.T) {
	secrets := func(a, b string) string {
		return `{"secrets":[
			{"kind":"a","name":"` + a + `","params":{"env":"[a-z]+"},"defaults":{"env":["dev"]}},
			{"kind":"b","name":"` + b + `","params":{"env":"[a-z]+"},"defaults":{"env":["dev"]}}]}`
	}
	_, err := Parse([]byte(secrets("acme-{env}-key", "acme-{env}-key")), "test.json")
	if err == nil || !strings.Contains(err.Error(), `"a" and "b" both produce "acme-dev-key"`) {
		t.Errorf("identical templates: %v", err)
	}
	// One template can swallow another's names without being identical.
	_, err = Parse([]byte(`{"secrets":[
		{"kind":"a","name":"acme-{env}","params":{"env":"[a-z-]+"},"defaults":{"env":["dev"]}},
		{"kind":"b","name":"acme-{env}-key","params":{"env":"[a-z]+"},"defaults":{"env":["dev"]}}]}`), "test.json")
	if err == nil || !strings.Contains(err.Error(), "both produce") {
		t.Errorf("overlapping templates: %v", err)
	}
	if _, err := Parse([]byte(secrets("acme-{env}-key", "acme-{env}-token")), "test.json"); err != nil {
		t.Errorf("distinct templates: %v", err)
	}
	// Without defaults there is nothing to sample, so nothing is claimed.
	if _, err := Parse([]byte(`{"secrets":[
		{"kind":"a","name":"acme-{env}","params":{"env":"[a-z]+"}},
		{"kind":"b","name":"acme-{env}","params":{"env":"[a-z]+"}}]}`), "test.json"); err != nil {
		t.Errorf("no defaults: %v", err)
	}
}

func TestMissingDefaultsAndAccountIDs(t *testing.T) {
	cfg := loadExample(t)
	wrapping, _ := cfg.Kind("wrapping-key")
	signing, _ := cfg.Kind("signing-key")
	vendor, _ := cfg.Kind("vendor-api-key")
	if got := strings.Join(wrapping.MissingDefaults(), ","); got != "version" {
		t.Errorf("wrapping-key lacks %q", got)
	}
	if len(signing.MissingDefaults()) != 0 {
		t.Errorf("signing-key lacks %v", signing.MissingDefaults())
	}
	if got := strings.Join(vendor.MissingDefaults(), ","); got != "env" {
		t.Errorf("vendor-api-key lacks %q", got)
	}
	if !ValidAccountID(strings.Repeat("a", 32)) || ValidAccountID("A"+strings.Repeat("a", 31)) || ValidAccountID("short") || ValidAccountID("") {
		t.Error("ValidAccountID accepts or refuses the wrong thing")
	}
}

func TestAnEmptyConfigurationIsValid(t *testing.T) {
	for _, text := range []string{`{}`, `{"secrets":[]}`} {
		cfg, err := Parse([]byte(text), "test.json")
		if err != nil || len(cfg.Kinds) != 0 {
			t.Errorf("%s: %v, %d kinds", text, err, len(cfg.Kinds))
		}
	}
}

func TestRawIsTheFileAsWrittenNotAsDefaulted(t *testing.T) {
	cfg, err := Parse([]byte(`{"secrets":[{"kind":"k","name":"n"}]}`), "test.json")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Source != SourcePrompt || cfg.OnePassword.ItemTitle != DefaultItemTitle || len(cfg.Cloudflare.Scopes) != 1 {
		t.Fatalf("the working copy lacks its defaults: %+v", cfg.File)
	}
	if cfg.Raw.Source != "" || cfg.Raw.OnePassword.ItemTitle != "" || cfg.Raw.Cloudflare.Scopes != nil {
		t.Errorf("Raw picked up defaults the file never said: %+v", cfg.Raw)
	}
}

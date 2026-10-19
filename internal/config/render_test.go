package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestRenderRoundTripsTheExampleAndIsStable(t *testing.T) {
	cfg := loadExample(t)
	text := Render(cfg.Raw)

	again, err := Parse([]byte(text), "rendered.json")
	if err != nil {
		t.Fatalf("what Render wrote does not load: %v\n%s", err, text)
	}
	if !reflect.DeepEqual(again.Raw, cfg.Raw) {
		t.Errorf("the rendered file says something different\nwas:  %+v\nnow:  %+v", cfg.Raw, again.Raw)
	}
	if second := Render(again.Raw); second != text {
		t.Errorf("rendering is not stable:\n%s\nthen\n%s", text, second)
	}
}

func TestRenderLeavesOutWhatIsNotSet(t *testing.T) {
	text := Render(File{})
	if text != "{\n  \"secrets\": []\n}\n" {
		t.Errorf("an empty file renders as %q", text)
	}
	for _, field := range []string{"source", "cloudflare", "onePassword", "scopes", "itemTitle", "generate", "defaults", "value"} {
		if strings.Contains(text, field) {
			t.Errorf("an empty file mentions %q", field)
		}
	}

	minimal := Render(File{Secrets: []Secret{{Kind: "k", Name: "n"}}})
	for _, field := range []string{"params", "value", "generate", "defaults", "rotateWarning"} {
		if strings.Contains(minimal, field) {
			t.Errorf("a secret with only a kind and a name mentions %q:\n%s", field, minimal)
		}
	}
	if _, err := Parse([]byte(minimal), "test.json"); err != nil {
		t.Errorf("minimal secret does not load: %v", err)
	}
}

func TestRenderEscapesWhatNeedsEscapingAndOnlyThat(t *testing.T) {
	const warning = `has "quotes", a \ backslash, <html> & an ampersand, and ünïcode`
	f := File{
		OnePassword: OnePassword{Vault: `My "Vault"`},
		Secrets:     []Secret{{Kind: "k", Name: "n", RotateWarning: warning}},
	}
	text := Render(f)
	if strings.Contains(text, `\u003c`) || strings.Contains(text, `\u0026`) {
		t.Errorf("HTML characters were escaped for no reason:\n%s", text)
	}
	cfg, err := Parse([]byte(text), "test.json")
	if err != nil {
		t.Fatalf("does not load: %v\n%s", err, text)
	}
	if cfg.Raw.Secrets[0].RotateWarning != warning || cfg.Raw.OnePassword.Vault != `My "Vault"` {
		t.Errorf("did not round-trip: %+v", cfg.Raw)
	}
}

func TestRenderListsParamsAndDefaultsInTheOrderTheTemplateUsesThem(t *testing.T) {
	f := File{Secrets: []Secret{{
		Kind: "k", Name: "{zebra}-{apple}-{mango}",
		Params:   map[string]string{"apple": "a", "mango": "m", "zebra": "z"},
		Defaults: map[string][]string{"mango": {"m"}, "zebra": {"z"}, "apple": {"a"}},
	}}}
	text := Render(f)
	for _, line := range []string{
		`"params": { "zebra": "z", "apple": "a", "mango": "m" }`,
		`"defaults": { "zebra": ["z"], "apple": ["a"], "mango": ["m"] }`,
	} {
		if !strings.Contains(text, line) {
			t.Errorf("missing %q in:\n%s", line, text)
		}
	}
}

func TestRenderKeepsWhatTheFileSaidExplicitly(t *testing.T) {
	f := File{
		Source:      SourceStdin,
		Cloudflare:  Cloudflare{AccountID: strings.Repeat("a", 32), Scopes: []string{"workers", "secrets"}},
		OnePassword: OnePassword{Vault: "V", ItemTitle: "mine - {name}"},
	}
	cfg, err := Parse([]byte(Render(f)), "test.json")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Raw, f.withEmptySecrets()) {
		t.Errorf("Raw = %+v", cfg.Raw)
	}
}

// withEmptySecrets is f as Parse reads it back: an empty list, not nil.
func (f File) withEmptySecrets() File {
	f.Secrets = []Secret{}
	return f
}

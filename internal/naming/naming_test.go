package naming

import (
	"strings"
	"testing"
)

func mustCompile(t *testing.T, source string, params map[string]string) *Template {
	t.Helper()
	tpl, err := Compile(source, params)
	if err != nil {
		t.Fatalf("Compile(%q): %v", source, err)
	}
	return tpl
}

var envParams = map[string]string{"env": "(sandbox|production)-[0-9]{2}"}

func TestBuildAndParseRoundTrip(t *testing.T) {
	tpl := mustCompile(t, "acme-{env}-api-key", envParams)

	name, err := tpl.Build(map[string]string{"env": "sandbox-01"})
	if err != nil || name != "acme-sandbox-01-api-key" {
		t.Fatalf("Build = %q, %v", name, err)
	}
	values, ok := tpl.Parse(name)
	if !ok || values["env"] != "sandbox-01" {
		t.Fatalf("Parse(%q) = %v, %v", name, values, ok)
	}
}

func TestParseRefusesWhatBuildWouldNotProduce(t *testing.T) {
	tpl := mustCompile(t, "acme-{env}-api-key", envParams)
	for _, name := range []string{
		"acme-staging-01-api-key",       // a stage the pattern does not allow
		"acme-sandbox-1-api-key",        // one digit
		"acme-sandbox-01-api-key-extra", // the template is matched in full, not as a prefix
		"x-acme-sandbox-01-api-key",     // ...nor as a suffix
		"",
	} {
		if _, ok := tpl.Parse(name); ok {
			t.Errorf("Parse(%q) accepted a name the template does not produce", name)
		}
	}
}

func TestBuildRefusesAValueItsPatternRejects(t *testing.T) {
	tpl := mustCompile(t, "acme-{env}-api-key", envParams)
	if _, err := tpl.Build(map[string]string{"env": "staging-01"}); err == nil {
		t.Error("Build accepted an env its pattern rejects")
	}
	// The pattern is matched in full: a value that merely contains a match is refused.
	if _, err := tpl.Build(map[string]string{"env": "sandbox-01-and-more"}); err == nil {
		t.Error("Build accepted a value that only partly matches")
	}
}

func TestBuildRefusesMissingAndUnknownPlaceholders(t *testing.T) {
	tpl := mustCompile(t, "acme-{env}-api-key", envParams)
	if _, err := tpl.Build(map[string]string{}); err == nil || !strings.Contains(err.Error(), "{env}") {
		t.Errorf("missing value: %v", err)
	}
	if _, err := tpl.Build(map[string]string{"env": "sandbox-01", "extra": "x"}); err == nil {
		t.Error("Build accepted a value for a placeholder the template does not have")
	}
}

func TestSeveralPlaceholders(t *testing.T) {
	tpl := mustCompile(t, "{app}-{env}-key-{version}", map[string]string{
		"app": "[a-z]+", "env": "prod|dev", "version": "[1-9][0-9]{0,5}",
	})
	name, err := tpl.Build(map[string]string{"app": "acme", "env": "prod", "version": "12"})
	if err != nil || name != "acme-prod-key-12" {
		t.Fatalf("Build = %q, %v", name, err)
	}
	values, ok := tpl.Parse(name)
	if !ok || values["app"] != "acme" || values["env"] != "prod" || values["version"] != "12" {
		t.Fatalf("Parse = %v, %v", values, ok)
	}
	if _, ok := tpl.Parse("acme-prod-key-012"); ok {
		t.Error("a version with a leading zero was accepted")
	}
	if got := tpl.Params(); strings.Join(got, ",") != "app,env,version" {
		t.Errorf("Params = %v, want order of appearance", got)
	}
}

func TestLiteralTextIsNotARegularExpression(t *testing.T) {
	tpl := mustCompile(t, "a.b-{x}", map[string]string{"x": "[0-9]"})
	if _, ok := tpl.Parse("aXb-1"); ok {
		t.Error("the dot in a literal matched any character")
	}
	if _, ok := tpl.Parse("a.b-1"); !ok {
		t.Error("the literal did not match itself")
	}
}

func TestAlternationStaysInsideItsPlaceholder(t *testing.T) {
	tpl := mustCompile(t, "pre-{x}-post", map[string]string{"x": "a|b"})
	if _, ok := tpl.Parse("pre-a-post"); !ok {
		t.Error("a did not match")
	}
	if _, ok := tpl.Parse("b"); ok {
		t.Error("an alternation leaked out of its placeholder")
	}
}

func TestCompileRefusals(t *testing.T) {
	cases := map[string]struct {
		source string
		params map[string]string
		want   string
	}{
		"missing pattern":    {"a-{x}", map[string]string{}, "no pattern"},
		"unused pattern":     {"a-b", map[string]string{"x": "y"}, "does not use"},
		"repeated":           {"{x}-{x}", map[string]string{"x": "a"}, "more than once"},
		"stray open brace":   {"a-{x", map[string]string{}, "stray brace"},
		"stray close brace":  {"a-}", map[string]string{}, "stray brace"},
		"upper-case holder":  {"a-{X}", map[string]string{"X": "a"}, "stray brace"},
		"invalid expression": {"a-{x}", map[string]string{"x": "("}, "regular expression"},
		"empty":              {"", map[string]string{}, "empty"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Compile(c.source, c.params)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Compile(%q) error = %v, want one containing %q", c.source, err, c.want)
			}
		})
	}
}

func TestFormAndCheck(t *testing.T) {
	tpl := mustCompile(t, "acme-{env}-api-key", envParams)
	if got := tpl.Form(); got != "acme-<env>-api-key" {
		t.Errorf("Form = %q", got)
	}
	if !tpl.Check("env", "sandbox-01") || tpl.Check("env", "nope") || tpl.Check("other", "sandbox-01") {
		t.Error("Check disagrees with the pattern")
	}
	if tpl.Source() != "acme-{env}-api-key" {
		t.Errorf("Source = %q", tpl.Source())
	}
}

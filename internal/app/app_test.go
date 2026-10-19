package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maddiecs84/secretferry/internal/source/onepassword"
	"github.com/maddiecs84/secretferry/internal/testfake"
)

const (
	example = "../../examples/secretferry.json"
	// A value every kind's rule accepts is not possible (they differ), so each test says which it uses.
	signingValue = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	vendorValue  = "vendor-key-THE-SECRET-123"
)

type harness struct {
	t      *testing.T
	api    *testfake.API
	stdout bytes.Buffer
	stderr bytes.Buffer
	env    Env

	// The fake 1Password vault: item title to password.
	items        map[string]string
	opNotInstall bool
	// breakReadback makes a created item read back as something else; breakOnly limits it to
	// titles containing that text.
	breakReadback bool
	breakOnly     string
	opCalls       [][]string
	opStdin       []string

	// What the prompt answers, and how many times it was asked.
	answer string
	asked  int

	envVars map[string]string
}

func newHarness(t *testing.T, opts testfake.Options) *harness {
	t.Helper()
	h := &harness{
		t:       t,
		api:     testfake.New(opts),
		items:   map[string]string{},
		envVars: map[string]string{"CLOUDFLARE_API_TOKEN": "tok"},
	}
	t.Cleanup(h.api.Server.Close)
	h.env = Env{
		Stdin:         strings.NewReader(""),
		Stdout:        &h.stdout,
		Stderr:        &h.stderr,
		Getenv:        func(k string) string { return h.envVars[k] },
		Getwd:         os.Getwd,
		HTTP:          http.DefaultClient,
		BaseURL:       h.api.URL(),
		OP:            h.op,
		WranglerToken: func() (string, error) { return "", errors.New("no wrangler") },
		ReadValue:     func(string) (string, error) { h.asked++; return h.answer, nil },
		Random:        &counting{},
		Version:       "test",
	}
	return h
}

// counting is a random source that never repeats itself: each byte is one more than the last.
type counting struct{ next byte }

func (c *counting) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.next
		c.next++
	}
	return len(p), nil
}

// op is a fake 1Password CLI for the two calls the tool makes.
func (h *harness) op(args []string, stdin string) (string, error) {
	h.opCalls = append(h.opCalls, args)
	h.opStdin = append(h.opStdin, stdin)
	if h.opNotInstall {
		return "", onepassword.ErrNotInstalled
	}
	switch {
	case len(args) >= 3 && args[0] == "item" && args[1] == "get":
		password, ok := h.items[args[2]]
		if !ok {
			return "", errors.New("isn't an item")
		}
		return password + "\n", nil
	case len(args) >= 2 && args[0] == "item" && args[1] == "create":
		var item struct {
			Title  string
			Fields []struct{ Label, Value string }
		}
		if err := json.Unmarshal([]byte(stdin), &item); err != nil {
			return "", err
		}
		for _, f := range item.Fields {
			if f.Label == "password" {
				if h.breakReadback && strings.Contains(item.Title, h.breakOnly) {
					h.items[item.Title] = f.Value + "-changed"
				} else {
					h.items[item.Title] = f.Value
				}
			}
		}
		return "", nil
	}
	return "", errors.New("unexpected op call")
}

func (h *harness) run(args ...string) int {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	full := append(append([]string{}, args...), configFlag(args, example)...)
	return Run(full, h.env)
}

// configFlag appends --config unless the call is one that takes none or already has it.
func configFlag(args []string, path string) []string {
	switch args[0] {
	case "version", "help", "-h", "--help", "--version":
		return nil
	}
	for _, a := range args {
		if a == "--config" {
			return nil
		}
	}
	return []string{"--config", path}
}

// assertNeverShown fails if the value is in anything the tool printed or sent in a URL or argument.
func (h *harness) assertNeverShown(value string) {
	h.t.Helper()
	if value == "" {
		return // nothing to hide; "" is a substring of everything
	}
	if strings.Contains(h.stdout.String(), value) {
		h.t.Errorf("the value is on stdout: %q", h.stdout.String())
	}
	if strings.Contains(h.stderr.String(), value) {
		h.t.Errorf("the value is on stderr: %q", h.stderr.String())
	}
	for _, r := range h.api.Requests() {
		if strings.Contains(r.URL, value) {
			h.t.Errorf("the value is in a URL: %s", r.URL)
		}
	}
	for _, args := range h.opCalls {
		if strings.Contains(strings.Join(args, " "), value) {
			h.t.Errorf("the value is in an op argument: %v", args)
		}
	}
}

func (h *harness) posts() int {
	n := 0
	for _, r := range h.api.Requests() {
		if r.Method == "POST" || r.Method == "PATCH" {
			n++
		}
	}
	return n
}

const (
	signingA  = "acme-sandbox-01-signing-key"
	signingB  = "acme-staging-01-signing-key"
	signingC  = "acme-production-01-signing-key"
	vendorKey = "acme-sandbox-01-vendor-api-key"
)

// ---- set ----

func TestSetWritesTheValueAndPrintsNamesOnly(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.answer = signingValue + "\n"

	if code := h.run("set", "--name", signingA); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	got, ok := h.api.Inspect(signingA)
	if !ok || got.Value != signingValue || strings.Join(got.Scopes, ",") != "workers" {
		t.Fatalf("stored %+v, %v", got, ok)
	}
	if !strings.Contains(h.stdout.String(), "Set "+signingA) || !strings.Contains(h.stdout.String(), "only copy") {
		t.Errorf("stdout = %q", h.stdout.String())
	}
	h.assertNeverShown(signingValue)
}

func TestSetBuildsTheNameFromSecretAndParam(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.answer = vendorValue
	if code := h.run("set", "--secret", "vendor-api-key", "--param", "env=sandbox-01"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if _, ok := h.api.Inspect(vendorKey); !ok {
		t.Error("the secret was not written under the built name")
	}
}

func TestSetRefusesAnExistingSecretAndNeverAsksForTheValue(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.api.Seed(signingA, "old")
	h.answer = signingValue
	if code := h.run("set", "--name", signingA); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stderr.String(), "already set") || !strings.Contains(h.stderr.String(), "rotate") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	if h.asked != 0 {
		t.Error("the value was asked for before the tool knew it would write")
	}
	if got, _ := h.api.Inspect(signingA); got.Value != "old" {
		t.Error("the existing value was changed")
	}
}

func TestSetRefusesAValueItsRuleRejectsWithoutQuotingIt(t *testing.T) {
	cases := map[string]struct{ name, value string }{
		"not base64":          {signingA, "NOT-BASE64-SECRET"},
		"wrong length":        {signingA, "AAEC"},
		"a space in a key":    {vendorKey, "vendor key SECRET"},
		"a line break":        {vendorKey, "vendor\nSECRET"},
		"blank":               {vendorKey, "   "},
		"over the size limit": {vendorKey, strings.Repeat("S", 65_537)},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			h := newHarness(t, testfake.Options{})
			h.answer = c.value
			if code := h.run("set", "--name", c.name); code != 1 {
				t.Fatalf("exit %d", code)
			}
			if h.posts() != 0 {
				t.Error("a value that fails its rule was sent")
			}
			h.assertNeverShown(strings.TrimSpace(c.value))
		})
	}
}

func TestSetUsesTheKindsOwnMessage(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.answer = "has a space"
	h.run("set", "--name", vendorKey)
	if !strings.Contains(h.stderr.String(), "as the vendor gives it") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
}

func TestANameNoTemplateProducesNeverReachesTheNetwork(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.answer = signingValue
	for _, name := range []string{"acme-qa-01-signing-key", "unrelated", "acme-sandbox-01-signing-key-extra"} {
		if code := h.run("set", "--name", name); code != 1 {
			t.Fatalf("%s: exit %d", name, code)
		}
		if !strings.Contains(h.stderr.String(), "acme-<env>-signing-key") {
			t.Errorf("the refusal does not show the forms: %q", h.stderr.String())
		}
	}
	if len(h.api.Requests()) != 0 || h.asked != 0 {
		t.Errorf("requests=%d asked=%d", len(h.api.Requests()), h.asked)
	}
}

// ---- rotate ----

func TestRotateNeedsTheNameAgainAndSaysWhatItLoses(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.api.Seed(signingA, "old")
	h.answer = signingValue

	for label, args := range map[string][]string{
		"no confirm":    {"rotate", "--name", signingA},
		"wrong confirm": {"rotate", "--name", signingA, "--confirm", signingB},
	} {
		if code := h.run(args...); code != 1 {
			t.Fatalf("%s: exit %d", label, code)
		}
		if !strings.Contains(h.stderr.String(), "stops verifying") || !strings.Contains(h.stderr.String(), "--confirm "+signingA) {
			t.Errorf("%s: stderr = %q", label, h.stderr.String())
		}
	}
	if len(h.api.Requests()) != 0 || h.asked != 0 {
		t.Error("a rotation that was not confirmed went further")
	}
}

func TestRotateReplacesTheValueInPlace(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.api.Seed(signingA, "old")
	h.answer = signingValue
	if code := h.run("rotate", "--name", signingA, "--confirm", signingA); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got, _ := h.api.Inspect(signingA); got.Value != signingValue {
		t.Errorf("value = %q", got.Value)
	}
	if !strings.Contains(h.stdout.String(), "Rotated "+signingA) {
		t.Errorf("stdout = %q", h.stdout.String())
	}
	h.assertNeverShown(signingValue)
}

func TestRotateOfAnUnsetSecretAsksForNothing(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.answer = signingValue
	if code := h.run("rotate", "--name", signingA, "--confirm", signingA); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stderr.String(), "not set yet") || h.asked != 0 {
		t.Errorf("stderr = %q, asked %d", h.stderr.String(), h.asked)
	}
}

func TestEachKindHasItsOwnRotationWarning(t *testing.T) {
	for name, want := range map[string]string{
		"acme-sandbox-01-wrapping-key-1": "add a new version instead",
		vendorKey:                        "keep it until the new one is checked",
	} {
		h := newHarness(t, testfake.Options{})
		h.run("rotate", "--name", name)
		if !strings.Contains(h.stderr.String(), want) {
			t.Errorf("%s: stderr = %q", name, h.stderr.String())
		}
	}
}

// ---- list and check ----

func TestListPrintsSortedNames(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.api.Seed(signingB, "v")
	h.api.Seed(signingA, "v")
	if code := h.run("list"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got := h.stdout.String(); got != signingA+"\n"+signingB+"\n" {
		t.Errorf("stdout = %q", got)
	}
	h.assertNeverShown("v\n")
}

func TestCheckFlagsSecretsNoTemplateProduces(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.api.Seed(signingA, "v")
	if code := h.run("check"); code != 0 || !strings.Contains(h.stdout.String(), "All 1 secrets") {
		t.Fatalf("exit %d, stdout %q", code, h.stdout.String())
	}

	h.api.Seed("someone-elses-secret", "v")
	if code := h.run("check"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stdout.String(), "someone-elses-secret") || strings.Contains(h.stdout.String(), signingA) {
		t.Errorf("stdout = %q", h.stdout.String())
	}
	if !strings.Contains(h.stderr.String(), "1 of 2") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
}

// ---- arguments ----

func TestWithNoArgumentsItPrintsUsageAndExitsTwo(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	if code := Run(nil, h.env); code != 2 || !strings.Contains(h.stdout.String(), "Usage:") {
		t.Errorf("exit %d, stdout %q", code, h.stdout.String())
	}
	for _, flag := range []string{"-h", "--help", "help"} {
		h.stdout.Reset()
		if code := Run([]string{flag}, h.env); code != 0 || !strings.Contains(h.stdout.String(), "Usage:") {
			t.Errorf("%s: exit %d", flag, code)
		}
	}
}

func TestVersion(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	if code := h.run("version"); code != 0 || h.stdout.String() != "secretferry test\n" {
		t.Errorf("exit %d, stdout %q", code, h.stdout.String())
	}
}

func TestThereIsNoWayToPassTheValueAndNothingEchoesAWordThatMightBeIt(t *testing.T) {
	const word = "WORD-THAT-MIGHT-BE-THE-VALUE"
	for label, args := range map[string][]string{
		"--value flag":         {"set", "--name", signingA, "--value", word},
		"--value=…":            {"set", "--name", signingA, "--value=" + word},
		"stray word":           {"set", word},
		"stray word after":     {"set", "--name", signingA, word},
		"unknown command":      {word},
		"flag on list":         {"list", "--name", word},
		"param without equals": {"set", "--secret", "signing-key", "--param", word},
		"value as --name":      {"set", "--name", word},
		"value as --secret":    {"set", "--secret", word},
		"value as a param":     {"set", "--secret", "signing-key", "--param", "env=" + word},
		"value as a param key": {"set", "--secret", "signing-key", "--param", word + "=sandbox-01"},
		"value as --confirm":   {"rotate", "--name", signingA, "--confirm", word},
	} {
		h := newHarness(t, testfake.Options{})
		h.answer = signingValue
		if code := h.run(args...); code != 1 {
			t.Errorf("%s: exit %d", label, code)
		}
		if strings.Contains(h.stderr.String(), word) || strings.Contains(h.stdout.String(), word) {
			t.Errorf("%s: a word that might be the value was printed: %q", label, h.stderr.String())
		}
		if h.posts() != 0 {
			t.Errorf("%s: something was written", label)
		}
	}
}

func TestFlagsGivenTwiceAreRefused(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	for label, args := range map[string][]string{
		"--name":    {"set", "--name", signingA, "--name", signingB},
		"--secret":  {"set", "--secret", "signing-key", "--secret", "wrapping-key"},
		"--confirm": {"rotate", "--name", signingA, "--confirm", signingA, "--confirm", signingA},
	} {
		if code := h.run(args...); code != 1 || !strings.Contains(h.stderr.String(), "more than once") {
			t.Errorf("%s: exit %d, stderr %q", label, code, h.stderr.String())
		}
	}
}

func TestNameAndSecretAreAlternatives(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	if code := h.run("set", "--name", signingA, "--secret", "signing-key"); code != 1 || !strings.Contains(h.stderr.String(), "not both") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
	if code := h.run("set"); code != 1 || !strings.Contains(h.stderr.String(), "needs --name") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
	if code := h.run("set", "--secret", "nonesuch"); code != 1 || !strings.Contains(h.stderr.String(), "signing-key, vendor-api-key, wrapping-key") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
	// A kind with several defaults names several secrets, and set acts on one.
	if code := h.run("set", "--secret", "signing-key"); code != 1 || !strings.Contains(h.stderr.String(), "one secret at a time") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
}

// ---- configuration and credentials ----

func TestTheConfigurationIsFoundFromTheWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile(example)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secretferry.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, testfake.Options{})
	h.api.Seed(signingA, "v")
	h.env.Getwd = func() (string, error) { return filepath.Join(dir), nil }

	// No --config: Run is called directly so the harness does not add one.
	if code := Run([]string{"list"}, h.env); code != 0 || !strings.Contains(h.stdout.String(), signingA) {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}

	h.stdout.Reset()
	h.stderr.Reset()
	h.env.Getwd = func() (string, error) { return t.TempDir(), nil }
	if code := Run([]string{"list"}, h.env); code != 1 || !strings.Contains(h.stderr.String(), "secretferry.json") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
}

func TestNoTokenIsSaidBeforeAnythingIsSent(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.envVars = map[string]string{}
	if code := h.run("list"); code != 1 || !strings.Contains(h.stderr.String(), "No token") {
		t.Errorf("exit %d, stderr %q", code, h.stderr.String())
	}
	if len(h.api.Requests()) != 0 {
		t.Error("a request was sent without a token")
	}
}

func TestWranglerIsAnOptionalFallbackAndIsSaidAloud(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.envVars = map[string]string{}
	h.env.WranglerToken = func() (string, error) { return "banner\nwrangler-token\n", nil }
	h.api.Seed(signingA, "v")
	if code := h.run("list"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), "wrangler auth token") {
		t.Errorf("the borrowed token was not mentioned: %q", h.stderr.String())
	}
	if got := h.api.Requests()[0].Authorization; got != "Bearer wrangler-token" {
		t.Errorf("authorization = %q", got)
	}
}

// ---- --source and the configured source ----

func TestSourceOnePasswordReadsTheItemTheConfigurationNames(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.items["secretferry - "+vendorKey] = vendorValue
	if code := h.run("set", "--name", vendorKey, "--source", "1password"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got, _ := h.api.Inspect(vendorKey); got.Value != vendorValue {
		t.Errorf("value = %q", got.Value)
	}
	if h.asked != 0 {
		t.Error("the prompt was used as well")
	}
	h.assertNeverShown(vendorValue)
}

func TestSourceOnePasswordRefusals(t *testing.T) {
	t.Run("no such item", func(t *testing.T) {
		h := newHarness(t, testfake.Options{})
		if code := h.run("set", "--name", vendorKey, "--source", "1password"); code != 1 || !strings.Contains(h.stderr.String(), "no item") {
			t.Errorf("exit %d, stderr %q", code, h.stderr.String())
		}
	})
	t.Run("op not installed", func(t *testing.T) {
		h := newHarness(t, testfake.Options{})
		h.opNotInstall = true
		if code := h.run("set", "--name", vendorKey, "--source", "1password"); code != 1 || !strings.Contains(h.stderr.String(), "not installed") {
			t.Errorf("exit %d, stderr %q", code, h.stderr.String())
		}
	})
	t.Run("the item holds a value the rule rejects", func(t *testing.T) {
		h := newHarness(t, testfake.Options{})
		h.items["secretferry - "+vendorKey] = "has a space SECRET"
		if code := h.run("set", "--name", vendorKey, "--source", "1password"); code != 1 || h.posts() != 0 {
			t.Errorf("exit %d, posts %d", code, h.posts())
		}
		h.assertNeverShown("SECRET")
	})
	t.Run("no vault configured", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secretferry.json")
		cfg := `{"cloudflare":{"accountId":"` + testfake.Account + `"},"secrets":[{"kind":"k","name":"acme-k"}]}`
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		h := newHarness(t, testfake.Options{})
		if code := Run([]string{"set", "--name", "acme-k", "--source", "1password", "--config", path}, h.env); code != 1 || !strings.Contains(h.stderr.String(), "onePassword.vault") {
			t.Errorf("exit %d, stderr %q", code, h.stderr.String())
		}
	})
}

// ---- provision ----

func TestProvisionMakesTheKeySavesItReadsItBackThenSetsIt(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	if code := h.run("provision", "--name", signingA); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	stored, ok := h.api.Inspect(signingA)
	if !ok {
		t.Fatal("not set in the store")
	}
	if kept := h.items["secretferry - "+signingA]; kept == "" || kept != stored.Value {
		t.Errorf("1Password holds %q, the store %q: they must be the same value", kept, stored.Value)
	}
	for _, want := range []string{"saved 'secretferry - " + signingA + "' in the Acme vault", "set in Secrets Store", "Now check: secretferry list"} {
		if !strings.Contains(h.stdout.String(), want) {
			t.Errorf("stdout lacks %q: %s", want, h.stdout.String())
		}
	}
	h.assertNeverShown(stored.Value)
}

func TestProvisionBacksUpBeforeItSends(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.run("provision", "--name", signingA)
	// The item is created before the first write to Cloudflare.
	created := -1
	for i, args := range h.opCalls {
		if len(args) > 1 && args[1] == "create" {
			created = i
		}
	}
	if created == -1 || h.posts() != 1 {
		t.Fatalf("created at %d, posts %d", created, h.posts())
	}
	if !strings.Contains(h.opStdin[created], `"CONCEALED"`) {
		t.Error("the password field is not concealed")
	}
}

func TestProvisionIsSafeToRunAgain(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.run("provision", "--name", signingA)
	first := h.items["secretferry - "+signingA]
	creates := len(h.items)
	posts := h.posts()

	if code := h.run("provision", "--name", signingA); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if h.items["secretferry - "+signingA] != first || len(h.items) != creates {
		t.Error("a second run made a second item or changed the first")
	}
	if !strings.Contains(h.stdout.String(), "already has") || !strings.Contains(h.stdout.String(), "already set in Secrets Store; nothing to do") {
		t.Errorf("stdout = %q", h.stdout.String())
	}
	if h.posts() != posts {
		t.Error("the second run wrote to Cloudflare again")
	}
}

func TestProvisionResumesAfterAFailureBetweenTheTwoSteps(t *testing.T) {
	// An earlier run saved the item and died before Cloudflare: the item's value is used, not a new one.
	h := newHarness(t, testfake.Options{})
	h.items["secretferry - "+signingA] = signingValue
	if code := h.run("provision", "--name", signingA); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got, _ := h.api.Inspect(signingA); got.Value != signingValue {
		t.Errorf("the store holds %q, not the backed-up value", got.Value)
	}
	if !strings.Contains(h.stdout.String(), "using that value") {
		t.Errorf("stdout = %q", h.stdout.String())
	}
}

func TestProvisionStopsBeforeCloudflareWhenTheBackupDoesNotReadBack(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.breakReadback = true
	if code := h.run("provision", "--name", signingA); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stderr.String(), "does not match") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	if len(h.api.Requests()) > 1 || h.posts() != 0 {
		t.Errorf("the store was written to, or reached for its names, before the backup was proven: %d requests", len(h.api.Requests()))
	}
}

func TestProvisionExpandsTheKindsDefaults(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	if code := h.run("provision", "--secret", "signing-key"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	for _, name := range []string{signingA, signingB, signingC} {
		if _, ok := h.api.Inspect(name); !ok {
			t.Errorf("%s was not provisioned", name)
		}
	}
	a, _ := h.api.Inspect(signingA)
	b, _ := h.api.Inspect(signingB)
	if a.Value == b.Value {
		t.Error("two environments were given the same key")
	}
}

func TestProvisionMakesEachKindInItsOwnForm(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	if code := h.run("provision", "--secret", "wrapping-key", "--param", "env=sandbox-01", "--param", "version=2"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	got, ok := h.api.Inspect("acme-sandbox-01-wrapping-key-2")
	if !ok || len(got.Value) != 43 || strings.ContainsAny(got.Value, "+/=") {
		t.Errorf("stored %+v, %v: want 43 base64url characters", got, ok)
	}
}

func TestProvisionOfAKindItCannotMakeNeedsTheItemToExist(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	if code := h.run("provision", "--name", vendorKey); code != 1 || !strings.Contains(h.stderr.String(), "nothing to make") {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	if h.posts() != 0 {
		t.Error("something was written")
	}

	// With the item there (the owner put the vendor's key in it), provision sets it.
	h.items["secretferry - "+vendorKey] = vendorValue
	if code := h.run("provision", "--name", vendorKey); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got, _ := h.api.Inspect(vendorKey); got.Value != vendorValue {
		t.Errorf("value = %q", got.Value)
	}
}

func TestProvisionRefusesABackedUpValueTheRuleRejects(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.items["secretferry - "+signingA] = "NOT-A-KEY-SECRET"
	if code := h.run("provision", "--name", signingA); code != 1 || h.posts() != 0 {
		t.Errorf("exit %d, posts %d", code, h.posts())
	}
	h.assertNeverShown("NOT-A-KEY-SECRET")
}

func TestProvisionRefusalsBeforeAnyWork(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	if code := h.run("provision"); code != 1 || !strings.Contains(h.stderr.String(), "needs --name") {
		t.Errorf("no target: exit %d, stderr %q", code, h.stderr.String())
	}
	if code := h.run("provision", "--name", "not-a-name"); code != 1 {
		t.Errorf("a name no template produces: exit %d", code)
	}
	if len(h.opCalls) != 0 || len(h.api.Requests()) != 0 {
		t.Error("work started before the arguments were checked")
	}
}

func TestProvisionReportsWhatItDidBeforeAFailure(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.breakReadback, h.breakOnly = true, "staging"
	if code := h.run("provision", "--name", signingA, "--name", signingB); code != 1 {
		t.Fatalf("exit %d", code)
	}
	// The first environment finished and says so; the second stopped before Cloudflare.
	if !strings.Contains(h.stdout.String(), "["+signingA+"] set in Secrets Store") {
		t.Errorf("stdout = %q", h.stdout.String())
	}
	if _, ok := h.api.Inspect(signingA); !ok {
		t.Error("the first environment was not set")
	}
	if _, ok := h.api.Inspect(signingB); ok {
		t.Error("the second environment was set despite a backup that did not read back")
	}
	if !strings.Contains(h.stderr.String(), "["+signingB+"]") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
}

func TestAPipedValueReachesTheStoreThroughTheRealReader(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.env.ReadValue = nil // the real prompt package, reading standard input
	h.env.Stdin = strings.NewReader(vendorValue + "\n")

	if code := h.run("set", "--name", vendorKey); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got, _ := h.api.Inspect(vendorKey); got.Value != vendorValue {
		t.Errorf("stored %q", got.Value)
	}
	// The reader says what it is waiting for, on stderr, so a run with nothing piped is not silent.
	if !strings.Contains(h.stderr.String(), "standard input until it ends") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	h.assertNeverShown(vendorValue)
}

// writeConfig writes a small configuration with the given top-level source ("" for none).
func writeConfig(t *testing.T, source string) string {
	t.Helper()
	cfg := map[string]any{
		"cloudflare":  map[string]any{"accountId": testfake.Account},
		"onePassword": map[string]any{"vault": "Acme"},
		"secrets": []any{map[string]any{
			"kind": "api-key", "name": "acme-api-key", "value": map[string]any{"rule": "printable"},
		}},
	}
	if source != "" {
		cfg["source"] = source
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "secretferry.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const plainSecret = "acme-api-key"

func TestTheDefaultSourceIsThePromptAndNameItExplicitly(t *testing.T) {
	for _, args := range [][]string{
		{"set", "--name", plainSecret},
		{"set", "--name", plainSecret, "--source", "prompt"},
	} {
		h := newHarness(t, testfake.Options{})
		h.answer = "from-the-prompt"
		h.items["secretferry - "+plainSecret] = "from-1password"
		if code := Run(append(args, "--config", writeConfig(t, "")), h.env); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, h.stderr.String())
		}
		if got, _ := h.api.Inspect(plainSecret); got.Value != "from-the-prompt" || h.asked != 1 || len(h.opCalls) != 0 {
			t.Errorf("%v: stored %q, asked %d, op calls %d", args, got.Value, h.asked, len(h.opCalls))
		}
	}
}

func TestTheConfiguredSourceIsUsedWhenNoFlagIsGiven(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.answer = "from-the-prompt"
	h.items["secretferry - "+plainSecret] = "from-1password"

	if code := Run([]string{"set", "--name", plainSecret, "--config", writeConfig(t, "1password")}, h.env); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got, _ := h.api.Inspect(plainSecret); got.Value != "from-1password" || h.asked != 0 {
		t.Errorf("stored %q, asked %d: the configured source was not used", got.Value, h.asked)
	}
}

func TestTheFlagOverridesTheConfiguredSource(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.answer = "from-the-prompt"
	h.items["secretferry - "+plainSecret] = "from-1password"

	if code := Run([]string{"set", "--name", plainSecret, "--source", "prompt", "--config", writeConfig(t, "1password")}, h.env); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got, _ := h.api.Inspect(plainSecret); got.Value != "from-the-prompt" || len(h.opCalls) != 0 {
		t.Errorf("stored %q with %d op calls: the flag did not win", got.Value, len(h.opCalls))
	}
}

func TestSourceStdinReadsStandardInputEvenWhereThePromptWouldBeUsed(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.answer = "WRONG-the-prompt-was-used" // ReadValue stands for the prompt
	h.env.Stdin = strings.NewReader("from-stdin\n")

	if code := Run([]string{"set", "--name", plainSecret, "--source", "stdin", "--config", writeConfig(t, "")}, h.env); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got, _ := h.api.Inspect(plainSecret); got.Value != "from-stdin" || h.asked != 0 {
		t.Errorf("stored %q, asked %d", got.Value, h.asked)
	}
	if !strings.Contains(h.stderr.String(), "standard input until it ends") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
}

func TestRotateTakesASourceToo(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.api.Seed(vendorKey, "old")
	h.items["secretferry - "+vendorKey] = vendorValue
	if code := h.run("rotate", "--name", vendorKey, "--confirm", vendorKey, "--source", "1password"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got, _ := h.api.Inspect(vendorKey); got.Value != vendorValue {
		t.Errorf("value = %q", got.Value)
	}
}

func TestAnUnknownSourceIsRefusedBeforeAnythingElseWithoutQuotingIt(t *testing.T) {
	const word = "WORD-THAT-MIGHT-BE-THE-VALUE"
	h := newHarness(t, testfake.Options{})
	for _, args := range [][]string{
		{"set", "--name", signingA, "--source", word},
		{"set", "--name", signingA, "--source=" + word},
		{"rotate", "--name", signingA, "--confirm", signingA, "--source", word},
	} {
		if code := h.run(args...); code != 1 {
			t.Fatalf("%v: exit %d", args, code)
		}
		if strings.Contains(h.stderr.String(), word) || !strings.Contains(h.stderr.String(), "prompt, stdin, 1password") {
			t.Errorf("%v: stderr = %q", args, h.stderr.String())
		}
	}
	// The old flag is gone, not aliased.
	if code := h.run("set", "--name", signingA, "--from-1password"); code != 1 || !strings.Contains(h.stderr.String(), "--source") {
		t.Errorf("--from-1password: exit %d, stderr %q", code, h.stderr.String())
	}
	if len(h.api.Requests()) != 0 || len(h.opCalls) != 0 || h.asked != 0 {
		t.Error("work started before the source was checked")
	}
}

func TestSourceIsGivenOnceAndOnlyToSetAndRotate(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	if code := h.run("set", "--name", signingA, "--source", "prompt", "--source", "stdin"); code != 1 || !strings.Contains(h.stderr.String(), "more than once") {
		t.Errorf("twice: exit %d, stderr %q", code, h.stderr.String())
	}
	for _, command := range []string{"list", "check", "provision"} {
		args := []string{command, "--source", "1password"}
		if command == "provision" {
			args = append(args, "--name", signingA)
		}
		if code := h.run(args...); code != 1 || !strings.Contains(h.stderr.String(), "Only --") {
			t.Errorf("%s: exit %d, stderr %q", command, code, h.stderr.String())
		}
	}
}

func TestProvisionLeavesANoteThatNamesTheRealFlag(t *testing.T) {
	h := newHarness(t, testfake.Options{})
	h.run("provision", "--name", signingA)
	var notes string
	for _, stdin := range h.opStdin {
		if strings.Contains(stdin, "notesPlain") {
			notes = stdin
		}
	}
	if !strings.Contains(notes, "secretferry set --name "+signingA+" --source 1password") || strings.Contains(notes, "--from-1password") {
		t.Errorf("the item's note = %s", notes)
	}
}

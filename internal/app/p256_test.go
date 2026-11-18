package app

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/maddiecs84/secretferry/internal/value"
)

const (
	clientKeyName = "acme-sandbox-01-client-key"
	clientItem    = "secretferry - " + clientKeyName
	// The example key of RFC 7515, appendix A.3: a P-256 key whose halves belong together.
	rfcKey = `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}`
	rfcD   = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
)

// clientKeys is a configuration with one secret an ES256 key is made for, in the sandbox only.
func clientKeys(t *testing.T) (*harness, string) {
	t.Helper()
	h, path := initialised(t)
	if code := h.runPlain("config", "add-secret",
		"--kind", "client-key",
		"--template", "acme-{env}-client-key",
		"--pattern", "env=(sandbox|staging|production)-[0-9]{2}",
		"--rule", "p256-jwk",
		"--generate", "p256-jwk",
		"--default", "env=sandbox-01"); code != 0 {
		t.Fatalf("add-secret: exit %d: %s", code, h.stderr.String())
	}
	h.envVars = map[string]string{"CLOUDFLARE_API_TOKEN": "tok"}
	return h, path
}

func privateHalf(t *testing.T, jwk string) string {
	t.Helper()
	var k struct{ D string }
	if err := json.Unmarshal([]byte(jwk), &k); err != nil || k.D == "" {
		t.Fatalf("not a key with a d: %v", err)
	}
	return k.D
}

// The 1Password copy is read back before Cloudflare is written to, and a JSON key is full of what
// `op` quotes a value for. Both ways it can print it must give the key that was saved.
func TestProvisionMakesAnES256KeyBacksItUpAndSetsIt(t *testing.T) {
	for name, quotes := range map[string]bool{"op prints the value as it is": false, "op quotes it as a CSV field": true} {
		t.Run(name, func(t *testing.T) {
			h, path := clientKeys(t)
			h.opQuotesCSV = quotes
			if code := h.runPlain("provision", "--secret", "client-key", "--config", path); code != 0 {
				t.Fatalf("provision: exit %d: %s", code, h.stderr.String())
			}
			stored, ok := h.api.Inspect(clientKeyName)
			if !ok {
				t.Fatalf("%s was not provisioned", clientKeyName)
			}
			rule, err := value.ParseRule("p256-jwk", "")
			if err != nil {
				t.Fatal(err)
			}
			if err := rule.Check(stored.Value); err != nil {
				t.Errorf("what was stored is not an ES256 key: %v", err)
			}
			if h.items[clientItem] != stored.Value {
				t.Errorf("1Password holds %q, Cloudflare %q", h.items[clientItem], stored.Value)
			}
			h.assertNeverShown(stored.Value)
			h.assertNeverShown(privateHalf(t, stored.Value))
		})
	}
}

func TestProvisionWritesNothingToCloudflareWhenAKeyDoesNotReadBackFromOnePassword(t *testing.T) {
	h, path := clientKeys(t)
	h.breakReadback = true
	if code := h.runPlain("provision", "--secret", "client-key", "--config", path); code == 0 {
		t.Fatal("provision went on with a copy that does not read back")
	}
	if _, ok := h.api.Inspect(clientKeyName); ok || h.posts() != 0 {
		t.Errorf("Cloudflare was written to: %d writes", h.posts())
	}
}

func TestSetTakesAnES256KeyAndRefusesOneThatIsNotBeforeAnythingIsSent(t *testing.T) {
	h, path := clientKeys(t)
	h.answer = rfcKey
	if code := h.runPlain("set", "--name", clientKeyName, "--config", path); code != 0 {
		t.Fatalf("set: exit %d: %s", code, h.stderr.String())
	}
	if stored, ok := h.api.Inspect(clientKeyName); !ok || stored.Value != rfcKey {
		t.Fatalf("stored %+v, %v", stored, ok)
	}
	h.assertNeverShown(rfcD)

	for name, bad := range map[string]string{
		"a public key":      strings.Replace(rfcKey, `,"d":"`+rfcD+`"`, "", 1),
		"another curve":     strings.Replace(rfcKey, "P-256", "P-384", 1),
		"a base64 secret":   signingValue,
		"a key that is not": "not a key",
	} {
		t.Run(name, func(t *testing.T) {
			before := h.posts()
			h.answer = bad
			if code := h.runPlain("rotate", "--name", clientKeyName, "--confirm", clientKeyName, "--config", path); code == 0 {
				t.Fatal("a value the rule rejects was accepted")
			}
			if !strings.Contains(h.stderr.String(), "P-256 private key as a JSON Web Key") {
				t.Errorf("stderr does not say what the value must be:\n%s", h.stderr.String())
			}
			if h.posts() != before {
				t.Error("Cloudflare was written to")
			}
			h.assertNeverShown(bad)
		})
	}
}

func TestSetAutoGenerateMakesAnES256KeyWhenTheAnswerIsBlank(t *testing.T) {
	h, path := clientKeys(t)
	h.answer = ""
	if code := h.runPlain("set", "--name", clientKeyName, "--auto-generate", "--config", path); code != 0 {
		t.Fatalf("set: exit %d: %s", code, h.stderr.String())
	}
	stored, ok := h.api.Inspect(clientKeyName)
	if !ok || h.items[clientItem] != stored.Value {
		t.Fatalf("stored %+v, %v; 1Password holds %q", stored, ok, h.items[clientItem])
	}
	if !strings.Contains(h.stdout.String(), "Made the value (p256-jwk) and saved it as '"+clientItem+"'") {
		t.Errorf("stdout:\n%s", h.stdout.String())
	}
	h.assertNeverShown(privateHalf(t, stored.Value))
}

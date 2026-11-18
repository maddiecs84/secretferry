package value

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

const key32 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" // 0x00..0x1f, padded base64

func TestRules(t *testing.T) {
	urlKey := strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(key32), "=")
	cases := []struct {
		spec  string
		value string
		ok    bool
	}{
		{"any", "anything at all", true},
		{"", "empty spec means any", true},

		{"base64-32", key32, true},
		{"base64-32", strings.TrimRight(key32, "="), false}, // unpadded
		{"base64-32", base64.StdEncoding.EncodeToString(make([]byte, 31)), false},
		{"base64-32", base64.StdEncoding.EncodeToString(make([]byte, 33)), false},
		{"base64-32", "not base64!", false},
		{"base64-32", key32 + "\n", false},

		{"base64url-32", urlKey, true},
		{"base64url-32", key32, false}, // padded
		{"base64url-32", urlKey[:42], false},
		{"base64url-32", urlKey + "A", false},
		{"base64url-32", strings.Repeat("!", 43), false},

		{"printable", "vendor_live_AbC_dEf-123", true},
		{"printable", "has a space", false},
		{"printable", "has\nline", false},
		{"printable", "naïve", false},
		{"printable", "", false},

		{"regex:sk-[a-z]+", "sk-abc", true},
		{"regex:sk-[a-z]+", "xsk-abc", false}, // matched in full, not a prefix
		{"regex:sk-[a-z]+", "sk-abcX", false},
	}
	for _, c := range cases {
		rule, err := ParseRule(c.spec, "")
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", c.spec, err)
		}
		if got := rule.Check(c.value) == nil; got != c.ok {
			t.Errorf("%q accepts %q = %v, want %v", c.spec, c.value, got, c.ok)
		}
	}
}

func TestAFailureSaysNothingOfTheValue(t *testing.T) {
	const secret = "SUPERSECRETVALUE"
	for _, spec := range []string{"base64-32", "base64url-32", "printable", "regex:x+"} {
		rule, _ := ParseRule(spec, "")
		err := rule.Check(secret + " ")
		if err == nil {
			t.Fatalf("%s accepted the bad value", spec)
		}
		if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: the message quotes the value: %v", spec, err)
		}
	}
}

func TestACustomMessageReplacesTheDefault(t *testing.T) {
	rule, err := ParseRule("regex:x+", "Use the key from the dashboard.")
	if err != nil {
		t.Fatal(err)
	}
	if got := rule.Check("y"); got == nil || got.Error() != "Use the key from the dashboard." {
		t.Errorf("Check = %v", got)
	}
}

func TestParseRuleRefusals(t *testing.T) {
	for _, spec := range []string{"base64", "regex:(", "REGEX:a", "printable "} {
		if _, err := ParseRule(spec, ""); err == nil {
			t.Errorf("ParseRule(%q) accepted a bad spec", spec)
		}
	}
}

func TestGenerateMakesAValueItsOwnRuleAccepts(t *testing.T) {
	for _, spec := range Generators {
		v, err := Generate(spec, nil)
		if err != nil {
			t.Fatalf("Generate(%q): %v", spec, err)
		}
		rule, _ := ParseRule(spec, "")
		if err := rule.Check(v); err != nil {
			t.Errorf("a %s value fails its own rule: %v", spec, err)
		}
		other, _ := Generate(spec, nil)
		if v == other {
			t.Errorf("two %s values are equal", spec)
		}
	}
}

func TestGenerateReadsExactly32BytesFromTheSource(t *testing.T) {
	src := bytes.NewReader(make([]byte, 31))
	if _, err := Generate("base64-32", src); err == nil {
		t.Error("a short source was accepted")
	}
	if _, err := Generate("hex", nil); err == nil {
		t.Error("an unknown generator was accepted")
	}
	want := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if got, _ := Generate("base64-32", bytes.NewReader(bytes.Repeat([]byte{7}, 64))); got != want {
		t.Errorf("Generate = %q, want %q", got, want)
	}
}

func TestNormalise(t *testing.T) {
	ok := map[string]string{
		"abc":        "abc",
		"abc\n":      "abc",
		"abc\r\n":    "abc",
		"abc\n\n":    "abc\n", // one trailing line break only
		" abc ":      " abc ", // nothing else changed
		"abc\r":      "abc\r", // a lone carriage return is part of the value
		"two\nlines": "two\nlines",
	}
	for in, want := range ok {
		got, err := Normalise(in, 100)
		if err != nil || got != want {
			t.Errorf("Normalise(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "\n", "   ", "  \r\n"} {
		if _, err := Normalise(in, 100); err == nil {
			t.Errorf("Normalise(%q) accepted a blank value", in)
		}
	}
}

func TestNormaliseCountsBytesNotCharacters(t *testing.T) {
	if _, err := Normalise(strings.Repeat("a", 10), 10); err != nil {
		t.Errorf("exactly the limit: %v", err)
	}
	if _, err := Normalise(strings.Repeat("a", 11), 10); err == nil {
		t.Error("one byte over was accepted")
	}
	// Three characters, six bytes.
	if _, err := Normalise("éèà", 5); err == nil {
		t.Error("multi-byte characters were counted as one byte each")
	}
	if _, err := Normalise(strings.Repeat("a", 1_000_000), 0); err != nil {
		t.Errorf("no limit: %v", err)
	}
}

// The EC P-256 example key of RFC 7515, appendix A.3. Its public half was worked out by someone
// else, so a generator that derives it wrongly cannot agree with it.
const (
	rfcD = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
	rfcX = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	rfcY = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
)

func rfcJWK(extra string) string {
	return `{"kty":"EC","crv":"P-256","x":"` + rfcX + `","y":"` + rfcY + `","d":"` + rfcD + `"` + extra + `}`
}

func TestGenerateP256JWKMakesTheRFCPublicHalfFromItsPrivateKey(t *testing.T) {
	d, err := base64.RawURLEncoding.DecodeString(rfcD)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Generate("p256-jwk", bytes.NewReader(d))
	if err != nil {
		t.Fatal(err)
	}
	var jwk map[string]any
	if err := json.Unmarshal([]byte(got), &jwk); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	want := map[string]any{"kty": "EC", "crv": "P-256", "x": rfcX, "y": rfcY, "d": rfcD, "ext": true, "key_ops": []any{"sign"}}
	if !reflect.DeepEqual(jwk, want) {
		t.Errorf("made %v, want %v", jwk, want)
	}
}

func TestGenerateP256JWKMakesAKeyThatSignsAndVerifies(t *testing.T) {
	got, err := Generate("p256-jwk", nil) // crypto/rand
	if err != nil {
		t.Fatal(err)
	}
	var jwk struct{ D, X, Y string }
	if err := json.Unmarshal([]byte(got), &jwk); err != nil {
		t.Fatal(err)
	}
	num := func(s string) *big.Int {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("%q is not 32 bytes of unpadded base64url", s)
		}
		return new(big.Int).SetBytes(b)
	}
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: num(jwk.X), Y: num(jwk.Y)}, D: num(jwk.D)}
	digest := sha256.Sum256([]byte("client assertion"))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	// Signed with d, verified with x and y: true only when the pair belongs together.
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Error("what d signs, x and y do not verify")
	}
	if err := mustRule(t, "p256-jwk").Check(got); err != nil {
		t.Errorf("a made key fails its own rule: %v", err)
	}
}

func TestGenerateP256JWKDiffersEachTime(t *testing.T) {
	a, _ := Generate("p256-jwk", nil)
	b, _ := Generate("p256-jwk", nil)
	if a == b {
		t.Error("two keys are the same")
	}
}

func TestGenerateP256JWKAsksAgainWhenTheBytesAreNotAKey(t *testing.T) {
	d, _ := base64.RawURLEncoding.DecodeString(rfcD)
	notAKey := [][]byte{make([]byte, 32), bytes.Repeat([]byte{0xff}, 32)} // zero, and above the group's order
	for _, first := range notAKey {
		got, err := Generate("p256-jwk", io.MultiReader(bytes.NewReader(first), bytes.NewReader(d)))
		if err != nil || !strings.Contains(got, rfcX) {
			t.Errorf("after %x...: %q, %v: want the key the second read makes", first[:2], got, err)
		}
	}
}

func TestGenerateP256JWKGivesUpOnASourceThatIsNotRandom(t *testing.T) {
	_, err := Generate("p256-jwk", bytes.NewReader(bytes.Repeat([]byte{0xff}, 32*20)))
	if err == nil || !strings.Contains(err.Error(), "could not make a valid P-256 key") {
		t.Errorf("err = %v", err)
	}
}

func TestGenerateP256JWKSaysNothingOfWhatItReadWhenTheSourceFails(t *testing.T) {
	_, err := Generate("p256-jwk", bytes.NewReader([]byte("short")))
	if err == nil || err.Error() != "could not read random bytes" {
		t.Errorf("err = %v", err)
	}
}

func TestP256JWKRule(t *testing.T) {
	swapped := `{"kty":"EC","crv":"P-256","x":"` + rfcY + `","y":"` + rfcX + `","d":"` + rfcD + `"}`
	cases := map[string]struct {
		value string
		ok    bool
	}{
		"the RFC key":                 {rfcJWK(""), true},
		"as WebCrypto exports it":     {rfcJWK(`,"ext":true,"key_ops":["sign"]`), true},
		"with alg, use and a kid":     {rfcJWK(`,"alg":"ES256","use":"sig","kid":"web-1"`), true},
		"with whitespace":             {"{\n  \"kty\": \"EC\", \"crv\": \"P-256\",\n  \"x\": \"" + rfcX + "\", \"y\": \"" + rfcY + "\", \"d\": \"" + rfcD + "\"\n}", true},
		"the public half only":        {`{"kty":"EC","crv":"P-256","x":"` + rfcX + `","y":"` + rfcY + `"}`, false},
		"x and y swapped":             {swapped, false},
		"another curve":               {strings.Replace(rfcJWK(""), "P-256", "P-384", 1), false},
		"another key type":            {strings.Replace(rfcJWK(""), `"EC"`, `"OKP"`, 1), false},
		"alg that is not ES256":       {rfcJWK(`,"alg":"ES384"`), false},
		"use that is not sig":         {rfcJWK(`,"use":"enc"`), false},
		"key_ops without sign":        {rfcJWK(`,"key_ops":["verify"]`), false},
		"key_ops that is not a list":  {rfcJWK(`,"key_ops":"sign"`), false},
		"d of 31 bytes":               {strings.Replace(rfcJWK(""), rfcD, rfcD[:41], 1), false},
		"d with padding":              {strings.Replace(rfcJWK(""), rfcD, rfcD+"=", 1), false},
		"d that is not base64url":     {strings.Replace(rfcJWK(""), rfcD, strings.Repeat("!", 43), 1), false},
		"d that is a number":          {strings.Replace(rfcJWK(""), `"`+rfcD+`"`, "5", 1), false},
		"d of zero":                   {strings.Replace(rfcJWK(""), rfcD, strings.Repeat("A", 43), 1), false},
		"a field spelled in capitals": {strings.Replace(rfcJWK(""), `"kty"`, `"KTY"`, 1), false},
		"not JSON":                    {"not a key", false},
		"JSON that is not an object":  {`["EC","P-256"]`, false},
		"null":                        {"null", false},
		"a key then something else":   {rfcJWK("") + " trailing", false},
		"two keys":                    {rfcJWK("") + rfcJWK(""), false},
		"empty":                       {"", false},
		"padded base64, not a key":    {key32, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := mustRule(t, "p256-jwk").Check(c.value) == nil; got != c.ok {
				t.Errorf("accepted = %v, want %v", got, c.ok)
			}
		})
	}
}

func TestP256JWKRuleSaysWhatIsWrongWithoutQuotingTheValue(t *testing.T) {
	err := mustRule(t, "p256-jwk").Check(rfcJWK(`,"alg":"ES384"`))
	if err == nil || !strings.Contains(err.Error(), "P-256 private key as a JSON Web Key") {
		t.Fatalf("err = %v", err)
	}
	for _, secret := range []string{rfcD, rfcX, rfcY} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the message quotes the value: %v", err)
		}
	}
}

func TestEachGeneratorIsListedAndAnswersItsOwnRule(t *testing.T) {
	for _, spec := range Generators {
		got, err := Generate(spec, &bytes.Buffer{})
		if err == nil {
			t.Errorf("%s made %q from no bytes", spec, got)
		}
		made, err := Generate(spec, nil)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if err := mustRule(t, spec).Check(made); err != nil {
			t.Errorf("a %s value fails the %s rule: %v", spec, spec, err)
		}
	}
	for _, spec := range Generators {
		found := false
		for _, s := range Specs {
			found = found || s == spec
		}
		if !found {
			t.Errorf("%s makes values but is not a rule in Specs", spec)
		}
	}
}

func mustRule(t *testing.T, spec string) Rule {
	t.Helper()
	r, err := ParseRule(spec, "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

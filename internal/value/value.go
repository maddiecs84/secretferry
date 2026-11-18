// Package value holds the rules a secret's value is checked against before
// anything is sent, and the generators for values the tool makes itself. No
// message here quotes a value.
package value

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/maddiecs84/secretferry/internal/ferry"
)

// Rule is a named check on a value.
type Rule struct {
	spec    string
	check   func(string) bool
	message string
}

var (
	printable   = regexp.MustCompile(`^[\x21-\x7e]+$`)
	base64urlRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	// 32 bytes as padded base64 is 43 characters and one "=". The shape is checked first
	// because Go's decoder silently skips line breaks, which a pasted key can carry.
	base64Re = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
)

// Specs lists the built-in rules, for messages and the README.
var Specs = []string{"any", "base64-32", "base64url-32", "p256-jwk", "printable", "regex:<pattern>"}

// ParseRule reads a rule spec: any, base64-32 (padded base64 of exactly 32
// bytes), base64url-32 (the unpadded form, 43 characters), p256-jwk (a P-256
// private key as a JSON Web Key, whose d, x and y belong together), printable
// (ASCII with no spaces or line breaks, as a request header carries) or
// regex:<pattern> (a pattern the whole value must match). message replaces the
// default failure text when it is not empty.
func ParseRule(spec, message string) (Rule, error) {
	if spec == "" {
		spec = "any"
	}
	r := Rule{spec: spec, message: message}
	switch {
	case spec == "any":
		r.check = func(string) bool { return true }
	case spec == "base64-32":
		r.check = func(v string) bool {
			if !base64Re.MatchString(v) {
				return false
			}
			b, err := base64.StdEncoding.Strict().DecodeString(v)
			return err == nil && len(b) == 32
		}
		r.defaultMessage("The value must be 32 bytes as padded base64, such as `openssl rand -base64 32` makes.")
	case spec == "base64url-32":
		r.check = func(v string) bool {
			if !base64urlRe.MatchString(v) {
				return false
			}
			b, err := base64.RawURLEncoding.Strict().DecodeString(v)
			return err == nil && len(b) == 32
		}
		r.defaultMessage("The value must be 32 random bytes as 43 base64url characters, such as `head -c 32 /dev/urandom | basenc --base64url | tr -d =` makes.")
	case spec == "p256-jwk":
		r.check = isP256JWK
		r.defaultMessage("The value must be a P-256 private key as a JSON Web Key (an ES256 signing key): an object with kty EC, crv P-256, and a d, x and y that belong together. `secretferry provision` makes one for a secret whose generate form is p256-jwk.")
	case spec == "printable":
		r.check = printable.MatchString
		r.defaultMessage("The value must be printable characters with no spaces or line breaks.")
	case strings.HasPrefix(spec, "regex:"):
		re, err := regexp.Compile("^(?:" + strings.TrimPrefix(spec, "regex:") + ")$")
		if err != nil {
			return Rule{}, ferry.Errorf("the value rule %q is not a valid regular expression: %v", spec, err)
		}
		r.check = re.MatchString
		r.defaultMessage("The value is not in the form this secret requires.")
	default:
		return Rule{}, ferry.Errorf("unknown value rule %q; the rules are %s", spec, strings.Join(Specs, ", "))
	}
	return r, nil
}

func (r *Rule) defaultMessage(text string) {
	if r.message == "" {
		r.message = text
	}
}

// Spec is the rule as written.
func (r Rule) Spec() string { return r.spec }

// Check refuses a value the rule does not accept. The error says nothing of it.
func (r Rule) Check(v string) error {
	if r.check == nil || r.check(v) {
		return nil
	}
	return ferry.Errorf("%s", r.message)
}

// Generators lists what Generate can make.
var Generators = []string{"base64-32", "base64url-32", "p256-jwk"}

// Generate makes a value in the named form, reading its randomness from r
// (crypto/rand when r is nil): 32 random bytes as base64 or base64url, or a
// P-256 private key as a JSON Web Key (p256-jwk, which reads 32 bytes, and 32
// more in the one case in 2^32 that they are not a valid key).
func Generate(spec string, r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	var encode func([]byte) string
	switch spec {
	case "base64-32":
		encode = base64.StdEncoding.EncodeToString
	case "base64url-32":
		encode = base64.RawURLEncoding.EncodeToString
	case "p256-jwk":
		return generateP256JWK(r)
	default:
		return "", ferry.Errorf("cannot generate %q; the generators are %s", spec, strings.Join(Generators, ", "))
	}
	b := make([]byte, 32)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", ferry.Errorf("could not read random bytes")
	}
	return encode(b), nil
}

// Normalise is what was typed or piped, as the value: one trailing line break
// dropped (an echo, openssl or a typed Enter leaves one), nothing else
// changed. A blank value and one over maxBytes are refused.
func Normalise(raw string, maxBytes int) (string, error) {
	v := raw
	if strings.HasSuffix(v, "\n") {
		v = strings.TrimSuffix(strings.TrimSuffix(v, "\n"), "\r")
	}
	if strings.TrimSpace(v) == "" {
		return "", ferry.Errorf("The value is empty.")
	}
	if maxBytes > 0 && len(v) > maxBytes {
		return "", ferry.Errorf("The value is over %d bytes, the most the store accepts.", maxBytes)
	}
	return v, nil
}

// p256JWK is an ES256 private key as WebCrypto exports it (crypto.subtle.exportKey("jwk", key)),
// so what is made here is what a script using WebCrypto would have made, and crypto.subtle.importKey
// reads it. The fields are in the order Node writes them.
type p256JWK struct {
	Crv    string   `json:"crv"`
	D      string   `json:"d"`
	Ext    bool     `json:"ext"`
	KeyOps []string `json:"key_ops"`
	Kty    string   `json:"kty"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
}

// validScalarTries is how many 32-byte reads generateP256JWK makes before it gives up. A random
// 32-byte value is not a private key (it is zero, or not below the group's order) about once in
// 2^32, so a second read is all but never needed and a ninth is a source that is not random.
const validScalarTries = 8

// generateP256JWK makes a P-256 key from r: the private scalar is 32 bytes read from r, asked for
// again when they are not a valid one, and the public half is worked out from it, so d, x and y
// always belong together.
func generateP256JWK(r io.Reader) (string, error) {
	curve := ecdh.P256()
	for range validScalarTries {
		d := make([]byte, 32)
		if _, err := io.ReadFull(r, d); err != nil {
			return "", ferry.Errorf("could not read random bytes")
		}
		priv, err := curve.NewPrivateKey(d)
		if err != nil {
			continue
		}
		// The public key is 0x04, then X and Y as 32 bytes each.
		pub := priv.PublicKey().Bytes()
		enc := base64.RawURLEncoding.EncodeToString
		out, err := json.Marshal(p256JWK{Crv: "P-256", D: enc(priv.Bytes()), Ext: true, KeyOps: []string{"sign"}, Kty: "EC", X: enc(pub[1:33]), Y: enc(pub[33:65])})
		if err != nil {
			return "", ferry.Errorf("could not encode the key")
		}
		return string(out), nil
	}
	return "", ferry.Errorf("could not make a valid P-256 key from the random bytes")
}

// isP256JWK reports whether v is a P-256 private key as a JSON Web Key that WebCrypto can sign
// with: kty EC, crv P-256, and a d, x and y of 32 bytes each (unpadded base64url) where d
// is a valid private key and x and y are its public half. A key with a mismatched pair would sign
// with one key and publish another, which no check downstream would see. alg, use and key_ops are
// checked only when present, since a key without them is still a signing key.
func isP256JWK(v string) bool {
	var jwk map[string]any
	if err := json.Unmarshal([]byte(v), &jwk); err != nil || jwk == nil {
		return false
	}
	text := func(name string) (string, bool) {
		s, ok := jwk[name].(string)
		return s, ok
	}
	if kty, _ := text("kty"); kty != "EC" {
		return false
	}
	if crv, _ := text("crv"); crv != "P-256" {
		return false
	}
	if alg, ok := text("alg"); ok && alg != "ES256" {
		return false
	}
	if use, ok := text("use"); ok && use != "sig" {
		return false
	}
	if ops, present := jwk["key_ops"]; present {
		list, ok := ops.([]any)
		if !ok {
			return false
		}
		signs := false
		for _, op := range list {
			signs = signs || op == "sign"
		}
		if !signs {
			return false
		}
	}
	part := func(name string) []byte {
		s, ok := text(name)
		if !ok {
			return nil
		}
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil || len(b) != 32 {
			return nil
		}
		return b
	}
	d, x, y := part("d"), part("x"), part("y")
	if d == nil || x == nil || y == nil {
		return false
	}
	priv, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		return false
	}
	pub := priv.PublicKey().Bytes()
	return bytes.Equal(pub[1:33], x) && bytes.Equal(pub[33:65], y)
}

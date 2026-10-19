package config

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/maddiecs84/secretferry/internal/naming"
)

// jstr is a JSON string. HTML characters are left alone: a pattern is not a web page.
func jstr(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return strings.TrimSuffix(buf.String(), "\n")
}

func inline(pairs ...[2]string) string {
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, jstr(p[0])+": "+p[1])
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func jlist(values []string) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, jstr(v))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// ordered returns the keys of m in the order the name template uses its
// placeholders, then any others alphabetically, so a rendered file reads the
// way the template does.
func ordered[V any](m map[string]V, template string) []string {
	var keys []string
	seen := map[string]bool{}
	for _, name := range naming.Placeholders(template) {
		if _, ok := m[name]; ok && !seen[name] {
			keys = append(keys, name)
			seen[name] = true
		}
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(keys, rest...)
}

// Render writes a configuration as text in the one layout the commands that
// write it use (config init, config add-secret): small objects on one line, each
// secret spread over a few. Fields that are not set are left out, so a file
// round-trips to what it said. The result is valid for Parse whenever the File is.
func Render(f File) string {
	var sections []string
	if f.Source != "" {
		sections = append(sections, "  "+jstr("source")+": "+jstr(f.Source))
	}

	var cloudflare [][2]string
	if f.Cloudflare.AccountID != "" {
		cloudflare = append(cloudflare, [2]string{"accountId", jstr(f.Cloudflare.AccountID)})
	}
	if len(f.Cloudflare.Scopes) > 0 {
		cloudflare = append(cloudflare, [2]string{"scopes", jlist(f.Cloudflare.Scopes)})
	}
	if len(cloudflare) > 0 {
		sections = append(sections, "  "+jstr("cloudflare")+": "+inline(cloudflare...))
	}

	var onePassword [][2]string
	if f.OnePassword.Vault != "" {
		onePassword = append(onePassword, [2]string{"vault", jstr(f.OnePassword.Vault)})
	}
	if f.OnePassword.ItemTitle != "" {
		onePassword = append(onePassword, [2]string{"itemTitle", jstr(f.OnePassword.ItemTitle)})
	}
	if len(onePassword) > 0 {
		sections = append(sections, "  "+jstr("onePassword")+": "+inline(onePassword...))
	}

	if len(f.Secrets) == 0 {
		sections = append(sections, "  "+jstr("secrets")+": []")
	} else {
		blocks := make([]string, 0, len(f.Secrets))
		for _, s := range f.Secrets {
			blocks = append(blocks, renderSecret(s))
		}
		sections = append(sections, "  "+jstr("secrets")+": [\n"+strings.Join(blocks, ",\n")+"\n  ]")
	}
	return "{\n" + strings.Join(sections, ",\n") + "\n}\n"
}

func renderSecret(s Secret) string {
	fields := []string{
		"      " + jstr("kind") + ": " + jstr(s.Kind),
		"      " + jstr("name") + ": " + jstr(s.Name),
	}
	if len(s.Params) > 0 {
		var pairs [][2]string
		for _, k := range ordered(s.Params, s.Name) {
			pairs = append(pairs, [2]string{k, jstr(s.Params[k])})
		}
		fields = append(fields, "      "+jstr("params")+": "+inline(pairs...))
	}
	if s.Value.Rule != "" || s.Value.Message != "" {
		var pairs [][2]string
		if s.Value.Rule != "" {
			pairs = append(pairs, [2]string{"rule", jstr(s.Value.Rule)})
		}
		if s.Value.Message != "" {
			pairs = append(pairs, [2]string{"message", jstr(s.Value.Message)})
		}
		fields = append(fields, "      "+jstr("value")+": "+inline(pairs...))
	}
	if s.Generate != "" {
		fields = append(fields, "      "+jstr("generate")+": "+jstr(s.Generate))
	}
	if len(s.Defaults) > 0 {
		var pairs [][2]string
		for _, k := range ordered(s.Defaults, s.Name) {
			pairs = append(pairs, [2]string{k, jlist(s.Defaults[k])})
		}
		fields = append(fields, "      "+jstr("defaults")+": "+inline(pairs...))
	}
	if s.RotateWarning != "" {
		fields = append(fields, "      "+jstr("rotateWarning")+": "+jstr(s.RotateWarning))
	}
	return "    {\n" + strings.Join(fields, ",\n") + "\n    }"
}

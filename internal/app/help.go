package app

import (
	"errors"
	"fmt"
	"strings"
)

// errHelp is what parsing a command's options returns when --help or -h was one of them.
var errHelp = errors.New("help requested")

const helpWidth = 78

type flagDoc struct {
	name string // without the dashes
	arg  string // the placeholder shown after it, if it takes a value
	desc string
}

type commandDoc struct {
	name     string
	summary  string
	usage    []string
	flags    []flagDoc
	notes    []string
	examples []string
}

var (
	docConfig = flagDoc{"config", "file", "Use this configuration file instead of the nearest secretferry.json (looked for in the working directory, then each parent)."}
	docName   = flagDoc{"name", "name", "The secret's full name, which must be one a name template in the configuration produces."}
	docSecret = flagDoc{"secret", "kind", "Name the secret by its kind instead, with --param for each placeholder in its name template."}
	docParam  = flagDoc{"param", "placeholder=value", "A value for a placeholder in the name, such as env=staging-01. Repeat for each placeholder."}
	docSource = flagDoc{"source", "source", "Where to read the value from: prompt (the default: typed or pasted at a prompt that shows nothing, or standard input when there is no terminal), stdin (standard input to the end, even at a terminal) or 1password (the item the configuration names). The configuration's \"source\" sets a different default."}
)

// commandDocs is every command's help. A test holds each entry to the options its command accepts, and
// every example to options that exist, so this cannot say what the command does not do.
var commandDocs = []commandDoc{
	{
		name:    "set",
		summary: "Set a new secret in Cloudflare Secrets Store.",
		usage: []string{
			"secretferry set (--name <name> | --secret <kind> [--param <placeholder>=<value> ...])\n" +
				"                [--source <source>] [--auto-generate]",
		},
		flags: []flagDoc{
			docConfig, docName, docSecret, docParam, docSource,
			{"auto-generate", "", "If no value is given, make one in the secret's generate form, save it as a 1Password item, read it back, and only then set it. A value that is given but wrong is refused, never replaced."},
		},
		notes: []string{
			"The value is never an argument, so it is not in a process list or a shell history. A secret that is already set is refused: use rotate to replace it.",
			"Cloudflare never shows a stored value again, so make your copy before it is set (secretferry provision and --auto-generate do that for you).",
		},
		examples: []string{
			"secretferry set --name acme-sandbox-01-signing-key",
			"secretferry set --name acme-sandbox-01-signing-key < key.txt",
			"secretferry set --secret signing-key --param env=sandbox-01 --source 1password",
			"secretferry set --name acme-sandbox-01-signing-key --auto-generate",
		},
	},
	{
		name:    "rotate",
		summary: "Replace a secret's value for good.",
		usage: []string{
			"secretferry rotate (--name <name> | --secret <kind> [--param <placeholder>=<value> ...])\n" +
				"                   --confirm <name> [--source <source>]",
		},
		flags: []flagDoc{
			docConfig, docName, docSecret, docParam, docSource,
			{"confirm", "name", "The secret's name again. Rotation replaces a value that cannot be read back, so it asks twice; without this it says what would be lost and stops."},
		},
		notes: []string{
			"Rotating overwrites the stored value in place. What depended on the old value stays unreadable unless the old value was kept somewhere else. The configuration's rotateWarning says what that is for each secret.",
		},
		examples: []string{
			"secretferry rotate --name acme-sandbox-01-signing-key --confirm acme-sandbox-01-signing-key",
			"secretferry rotate --name acme-sandbox-01-signing-key --confirm acme-sandbox-01-signing-key --source 1password",
		},
	},
	{
		name:    "list",
		summary: "List the secrets in the store: names only, sorted.",
		usage:   []string{"secretferry list"},
		flags:   []flagDoc{docConfig},
		notes: []string{
			"Cloudflare never returns a value, so there is none to show. It lists every secret in the account's store, whether or not the configuration names it: use check for that.",
		},
		examples: []string{"secretferry list"},
	},
	{
		name:    "check",
		summary: "Find secrets in the store that no name template in the configuration produces.",
		usage:   []string{"secretferry check"},
		flags:   []flagDoc{docConfig},
		notes: []string{
			"Exits 1 and lists them if there are any: they are secrets this tool would not have let you write, such as one under another project's name or a typo.",
		},
		examples: []string{"secretferry check"},
	},
	{
		name:    "provision",
		summary: "Make keys, back each up in 1Password, check the copy reads back, then set it.",
		usage: []string{
			"secretferry provision (--name <name> ... |\n" +
				"                       --secret <kind> [--param <placeholder>=<value> ...])",
		},
		flags: []flagDoc{
			docConfig,
			{"name", "name", "A secret's full name. Repeat to provision several."},
			{"secret", "kind", "Provision a kind: one secret for each combination of its placeholders' values (from --param, else the kind's defaults)."},
			{"param", "placeholder=value", "A value for a placeholder. Repeat for several values; each combination is provisioned."},
		},
		notes: []string{
			"For each name, in order: it uses the 1Password item if an earlier run made one (never a second), otherwise makes the key in the secret's generate form and saves it; reads the item back and stops unless it matches; then sets it in Secrets Store unless it is already there. It is safe to run again after a failure.",
			"Needs onePassword.vault in the configuration and the 1Password CLI (op) signed in.",
		},
		examples: []string{
			"secretferry provision --secret signing-key",
			"secretferry provision --name acme-sandbox-01-signing-key",
			"secretferry provision --secret wrapping-key --param env=sandbox-01 --param version=2",
		},
	},
	{
		name:    "config init",
		summary: "Write a secretferry.json with no secrets in it.",
		usage:   []string{"secretferry config init [--account <id>] [--vault <name>]"},
		flags: []flagDoc{
			docConfig,
			{"account", "id", "Your 32-character Cloudflare account id, written into the file."},
			{"vault", "name", "The 1Password vault that holds backups, written into the file."},
		},
		notes: []string{
			"Never overwrites a file that is there. Needs no token, network or 1Password. Add secrets with config add-secret.",
		},
		examples: []string{
			"secretferry config init",
			"secretferry config init --account 0123456789abcdef0123456789abcdef --vault Acme",
		},
	},
	{
		name:    "config add-secret",
		summary: "Add a secret to the configuration, step by step or with flags.",
		usage: []string{
			"secretferry config add-secret",
			"secretferry config add-secret --kind <kind> --template <name-template>\n" +
				"                              --pattern <placeholder>=<regex> ... [options]",
		},
		flags: []flagDoc{
			docConfig,
			{"kind", "kind", "A short name for the secret: lower-case letters, digits and hyphens. What --secret takes."},
			{"template", "name-template", "How the secret is named, with {placeholders} that vary, such as acme-{env}-signing-key."},
			{"pattern", "placeholder=regex", "The pattern a placeholder's value must match in full, such as env=(sandbox|staging|production)-[0-9]{2}. Give one for each placeholder."},
			{"rule", "rule", "What the value must look like: any, base64-32, base64url-32, printable or regex:<pattern>. Default: any."},
			{"message", "text", "What to say when a value does not match the rule. Must not contain a value."},
			{"generate", "form", "How secretferry makes the value: base64-32 or base64url-32. Leave out for a key someone else issues. It must satisfy --rule."},
			{"default", "placeholder=value", "A value provision uses for a placeholder when --param gives none. Repeat for each value."},
			{"rotate-warning", "text", "What replacing this secret loses, shown when rotate is not confirmed."},
		},
		notes: []string{
			"With no flags, in a terminal, it asks one question at a time and offers a default for each. Nothing is written until you confirm, and it prints the flags that would do the same. Without a terminal, or with some but not all of the required flags, it does not ask.",
			"The file with the new secret in it is checked as a whole before it is written, and replaced in one step: a secret that is refused (a kind that is taken, a placeholder with no pattern, a generate form its rule rejects, a name another secret also produces) leaves the file as it was. Needs no token, network or 1Password.",
		},
		examples: []string{
			"secretferry config add-secret",
			"secretferry config add-secret --kind signing-key --template 'acme-{env}-signing-key' \\\n" +
				"    --pattern 'env=(sandbox|staging|production)-[0-9]{2}' --rule base64-32 --generate base64-32 \\\n" +
				"    --default env=sandbox-01 --default env=staging-01",
		},
	},
	{
		name:    "config validate",
		summary: "Check secretferry.json and show what it means.",
		usage:   []string{"secretferry config validate"},
		flags:   []flagDoc{docConfig},
		notes: []string{
			"Loads the file, which checks every rule in it, and shows each secret's name form, value rule and the names provision would make. Exits 1 with the reason if the file is wrong, so it suits CI. Needs no token, network or 1Password.",
		},
		examples: []string{"secretferry config validate", "secretferry config validate --config path/to/secretferry.json"},
	},
	{
		name:     "version",
		summary:  "Print the version.",
		usage:    []string{"secretferry version"},
		examples: []string{"secretferry version"},
	},
}

// docFor finds a command's help by its name ("set", "config add-secret").
func docFor(name string) (commandDoc, bool) {
	for _, d := range commandDocs {
		if d.name == name {
			return d, true
		}
	}
	return commandDoc{}, false
}

// wrap breaks text into lines of at most width characters at spaces. A word longer than the width is kept whole.
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func (f flagDoc) spec() string {
	if f.arg == "" {
		return "--" + f.name
	}
	return "--" + f.name + " <" + f.arg + ">"
}

// commandHelp is one command's help text.
func commandHelp(d commandDoc) string {
	var b strings.Builder
	for _, line := range wrap(d.summary, helpWidth) {
		fmt.Fprintf(&b, "%s\n", line)
	}
	b.WriteString("\nUsage:\n")
	for _, u := range d.usage {
		fmt.Fprintf(&b, "  %s\n", strings.ReplaceAll(u, "\n", "\n  "))
	}

	if len(d.flags) > 0 {
		left := 0
		for _, f := range d.flags {
			left = max(left, len(f.spec()))
		}
		b.WriteString("\nOptions:\n")
		for _, f := range d.flags {
			lines := wrap(f.desc, helpWidth-left-4)
			fmt.Fprintf(&b, "  %-*s  %s\n", left, f.spec(), lines[0])
			for _, line := range lines[1:] {
				fmt.Fprintf(&b, "  %*s  %s\n", left, "", line)
			}
		}
		fmt.Fprintf(&b, "  %-*s  %s\n", left, "--help", "Show this help.")
	}

	for _, note := range d.notes {
		b.WriteString("\n")
		for _, line := range wrap(note, helpWidth) {
			fmt.Fprintf(&b, "%s\n", line)
		}
	}
	if len(d.examples) > 0 {
		b.WriteString("\nExamples:\n")
		for _, e := range d.examples {
			fmt.Fprintf(&b, "  %s\n", strings.ReplaceAll(e, "\n", "\n  "))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// configHelp lists the config subcommands.
func configHelp() string {
	var b strings.Builder
	b.WriteString("secretferry config: create and check secretferry.json.\n\nUsage:\n  secretferry config <command>\n\nCommands:\n")
	for _, d := range commandDocs {
		if sub, ok := strings.CutPrefix(d.name, "config "); ok {
			fmt.Fprintf(&b, "  %-12s %s\n", sub, d.summary)
		}
	}
	b.WriteString("\nRun `secretferry config <command> --help` for a command's options and examples.\nNone of them needs a token, the network or 1Password.")
	return b.String()
}

// overview is the help for the program as a whole.
func overview() string {
	var b strings.Builder
	b.WriteString("secretferry moves a secret from where it is kept (1Password) to where it is used\n")
	b.WriteString("(Cloudflare Secrets Store), without the value ever being an argument, a log line or\n")
	b.WriteString("an error message.\n\n")
	b.WriteString("Usage:\n  secretferry <command> [options]\n\nCommands:\n")
	rows := [][2]string{}
	for _, name := range []string{"set", "rotate", "list", "check", "provision"} {
		d, _ := docFor(name)
		rows = append(rows, [2]string{name, d.summary})
	}
	version, _ := docFor("version")
	rows = append(rows,
		[2]string{"config", "Create and check secretferry.json: init, add-secret, validate."},
		[2]string{"version", version.summary},
		[2]string{"help", "Show this help, or a command's: secretferry help <command>."},
	)
	const nameWidth = 10
	for _, row := range rows {
		lines := wrap(row[1], helpWidth-nameWidth-3)
		fmt.Fprintf(&b, "  %-*s %s\n", nameWidth, row[0], lines[0])
		for _, line := range lines[1:] {
			fmt.Fprintf(&b, "  %*s %s\n", nameWidth, "", line)
		}
	}
	b.WriteString("\nRun `secretferry <command> --help` for a command's options and examples.\n")
	b.WriteString(`
Configuration:
  Every command except version and config init reads a secretferry.json, found in the
  working directory or the nearest parent, or named with --config. Create one with
  'secretferry config init', then add secrets with 'secretferry config add-secret'.

Environment:
  CLOUDFLARE_API_TOKEN    A token with the account permission Secrets Store: Edit. If it is
                          not set and wrangler is on your PATH, 'wrangler auth token' is used.
  CLOUDFLARE_ACCOUNT_ID   Overrides cloudflare.accountId in the configuration.

Exit status: 0 on success, 1 on an error, 2 when run with no arguments.
`)
	return strings.TrimRight(b.String(), "\n")
}

// helpFor answers `secretferry help [command [subcommand]]`. ok is false for a command with no help.
func helpFor(words []string) (string, bool) {
	switch {
	case len(words) == 0:
		return overview(), true
	case len(words) == 1 && words[0] == "config":
		return configHelp(), true
	}
	if d, ok := docFor(strings.Join(words, " ")); ok {
		return commandHelp(d), true
	}
	return "", false
}

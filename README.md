# secretferry

Moves a secret from where it is kept to where it is used, without the value ever being an
argument, a log line or an error message.

Today that means **1Password → Cloudflare Secrets Store**. The tool is built around two plain
ideas so that other sources and targets (AWS Secrets Manager, for one) can be added later:

- a **source** is where a value is read from or backed up to (1Password, standard input, a prompt);
- a **target** is where a value is written (Cloudflare Secrets Store).

It is one static binary with no runtime. Each project describes its own account, vault and
naming convention in a `secretferry.json`; nothing project-specific is in the tool.

## Status

Early. The commands below are implemented and covered by tests that run against an in-memory
fake of the Cloudflare API and a fake `op`. **It has not yet been run against a real Cloudflare
account or a real 1Password vault**: try it on a throwaway secret in a sandbox account first.

## Install

```sh
go install github.com/maddiecs84/secretferry/cmd/secretferry@latest
```

Prebuilt binaries are not published yet. It builds for Linux, macOS and Windows (amd64 and arm64).

You also need:

- a Cloudflare token that can edit Secrets Store (`CLOUDFLARE_API_TOKEN`, with the account
  permission *Secrets Store: Edit*). If `wrangler` is on your `PATH` and you have run
  `wrangler login`, secretferry will borrow that login when no token is set; wrangler is never
  required, and that login may lack the permission;
- the [1Password CLI](https://developer.1password.com/docs/cli/) (`op`, or `op.exe` under WSL),
  signed in, for `provision` and `--source 1password`.

## Getting help

```sh
secretferry --help                    # the commands, the environment variables, the configuration
secretferry <command> --help          # a command's usage, every option, and examples
secretferry help <command>            # the same
secretferry config --help             # the config commands: init, add-secret, validate
secretferry config add-secret --help
```

Help needs no configuration file, token, network or 1Password, and exits 0. Each command's options
are described in its own help, which is checked against what the command accepts, and every example
in it is checked to parse and to fit [`examples/secretferry.json`](examples/secretferry.json).

## Quick start

Every command reads a `secretferry.json`. Make one, add the secrets it should manage, and check it.
None of these steps needs a token, the network or 1Password.

```sh
# 1. An empty configuration, with your Cloudflare account and 1Password vault.
secretferry config init --account 0123456789abcdef0123456789abcdef --vault Acme

# 2. Describe a secret: what it is called, what its value must look like, and how to make it.
#    (This is the scriptable form. Without any flags, in a terminal, it asks instead: see below.)
secretferry config add-secret \
  --kind signing-key \
  --template 'acme-{env}-signing-key' \
  --pattern 'env=(sandbox|staging|production)-[0-9]{2}' \
  --rule base64-32 \
  --generate base64-32 \
  --default env=sandbox-01 --default env=staging-01 --default env=production-01 \
  --rotate-warning 'anything signed with it stops verifying unless the old value was kept.'

# 3. Check it, and see what it means.
secretferry config validate
```

`init` writes a file with no secrets in it, never over one that is there. Each `add-secret` adds one
secret to it.

### Let it ask

Run `add-secret` with no arguments **in a terminal** and it asks one question at a time, offering a
default for each (press Enter to accept it). Nothing is written until you confirm at the end, and
Ctrl-C stops it:

```text
$ secretferry config add-secret
Adding a secret to /work/acme/secretferry.json. Press Enter to accept a default shown in [brackets]; Ctrl-C to stop.

Kind: a short name for this secret, such as signing-key [api-key]: signing-key

Name template [acme-{env}-signing-key]:
Pattern for {env} [(sandbox|staging|production)-[0-9]{2}]:

Who makes the value?
  1. secretferry makes it: 32 random bytes as padded base64
  2. secretferry makes it: 32 random bytes as base64url (no padding)
  3. someone else issues it, and you supply it with `set`
Choice [1]:
Values for {env} [sandbox-01,staging-01,production-01]:
What does replacing it lose? One sentence, shown when someone rotates it (Enter for the standard warning):

This will add to /work/acme/secretferry.json:
  kind:  signing-key
  name:  acme-<env>-signing-key
  value: base64-32, made by secretferry
  provision makes by default: acme-production-01-signing-key, acme-sandbox-01-signing-key, acme-staging-01-signing-key
The same thing as a command:
  secretferry config add-secret --kind signing-key --template 'acme-{env}-signing-key' --pattern 'env=(sandbox|staging|production)-[0-9]{2}' --rule base64-32 --generate base64-32 --default env=sandbox-01 --default env=staging-01 --default env=production-01

Add it? [Y]:
```

The defaults are: the kind `api-key` (until you have one); the name template
`<your directory's name>-{env}-<kind>`; for each placeholder a pattern by its name (`env`:
`(sandbox|staging|production)-[0-9]{2}`, `version`: `[1-9][0-9]{0,5}`, anything else: lower-case words
joined by hyphens); a value that secretferry makes, as padded base64; and, for `env` only, the values
`sandbox-01,staging-01,production-01` for `provision` to make. Choose option 3 for a key someone else
issues, and it asks what the value must look like (default `printable`). A wrong answer is explained and
asked again, and the whole file is checked before it is written, exactly as with flags. The command it
prints at the end is the flags form of what you just answered: copy it into a script or a runbook.

It only asks when standard input is a terminal and you give no flags (other than `--config`). In a
script or CI, or with some flags but not all of the required ones, it does not ask: it says what is
missing.

### With flags

Step 2 above makes this file (add `--rule printable` and no `--generate` for a key
someone else issues, which you supply with `set`):

```json
{
  "cloudflare": { "accountId": "0123456789abcdef0123456789abcdef" },
  "onePassword": { "vault": "Acme" },
  "secrets": [
    {
      "kind": "signing-key",
      "name": "acme-{env}-signing-key",
      "params": { "env": "(sandbox|staging|production)-[0-9]{2}" },
      "value": { "rule": "base64-32" },
      "generate": "base64-32",
      "defaults": { "env": ["sandbox-01", "staging-01", "production-01"] },
      "rotateWarning": "anything signed with it stops verifying unless the old value was kept."
    }
  ]
}
```

`add-secret` checks the whole file with the new secret in it **before** writing, and replaces the
file in one step, so a refused add (a kind that is taken, a template placeholder with no pattern, a
`--generate` form its own `--rule` rejects, a name another secret also produces) leaves it exactly as
it was. It rewrites the file in the layout above; JSON has no comments, so nothing is lost, but hand
formatting is normalised.

`validate` loads the file, which checks every rule in it, and shows what it means: each secret's name
form, value rule, and the names `provision` would make. It exits 1 with the reason if the file is
wrong, so it also suits CI. There is no command that changes or removes a secret: edit the JSON by
hand and run `validate`. You can also write the file by hand from the start (see
[`examples/secretferry.json`](examples/secretferry.json)).

Then use it:

```sh
export CLOUDFLARE_API_TOKEN=…

# Make a key for every environment, save each in 1Password, check the copy reads back,
# and only then set it in Secrets Store. Safe to run again after a failure.
secretferry provision --secret signing-key

# Or set a value you already have. --source says where it is read from:
#   prompt    (the default) a prompt that shows nothing on a terminal, else standard input
#   stdin     standard input to the end, even on a terminal
#   1password the item the configuration names
secretferry set --name acme-sandbox-01-signing-key
secretferry set --name acme-sandbox-01-signing-key < key.txt
secretferry set --secret signing-key --param env=sandbox-01 --source 1password

# Or have secretferry make the value, if you give none. A blank answer, blank standard input, or (with
# --source 1password) no item yet all count as "none given":
secretferry set --name acme-sandbox-01-signing-key --auto-generate

# Replace a value for good. The name is typed twice so a recalled command line does not do it.
secretferry rotate --name acme-sandbox-01-signing-key --confirm acme-sandbox-01-signing-key

secretferry list     # names only, sorted
secretferry check    # secrets in the store that no name template in your config produces
```

### `set --auto-generate`

With `--auto-generate`, `set` makes the value itself when none is given, in the form the secret's
`generate` setting names. Because Cloudflare never shows a value again, it does what `provision`
does: it saves the value as a 1Password item and **reads it back before Cloudflare is written to**, so
that item is the copy. Details:

- "None given" means a blank answer at the prompt (the prompt says "Enter to have secretferry make
  one" when it can), blank standard input, or, with `--source 1password`, no item yet.
- A value that **is** given is used as it is or refused if the secret's rule rejects it. It is never
  replaced by a made one, so a mistyped key is an error, not a surprise.
- If the secret's 1Password item already exists (an earlier run made it), that value is used, not a
  new one. The output says which happened.
- It needs `onePassword.vault` in the configuration, and the secret needs a `generate` form (a key
  someone else issues cannot be made); otherwise it says so and writes nothing.
- It is a flag of `set` only. `provision` already makes values, for every environment at once.

What the configuration checks when it loads, whichever command you run (and so what `add-secret`
refuses to write): a `generate` form that
fails its own `value.rule` (so `provision` could never succeed), two secrets whose templates
produce the same name (so one would never be the one that checks the value), a `source` of
`1password` with no vault, and any field it does not recognise.

## Why the value is never an argument

Cloudflare never returns a stored value, to anyone, so **the only copy of a key is the one made
before it is sent**. `provision` therefore saves the key in 1Password and reads it back before it
touches Cloudflare. Separately, a value in an argument is in a process list and a shell history,
so there is no option for it:

- the value is read from the chosen source (a prompt, standard input or the 1Password item), and
  goes to Cloudflare in a request body and nowhere else;
- an unknown option or a stray word is refused **without being quoted**, since it may be the value;
  so are a `--name`, `--secret` or `--param` that does not fit the configuration;
- an error from the Cloudflare API is shown with the value replaced by `[redacted]`, whether the
  API echoes it as typed or JSON-escaped;
- the value is passed to `op` on standard input, never as an argument;
- `list` and `check` print names, never values (there are none to show).

`rotate` replaces a value that cannot be read back, so it needs `--confirm <name>` and says what
that kind of secret loses.

## Configuration

secretferry looks for `secretferry.json` in the working directory and then each parent, or you pass
`--config <file>` to any command. Unknown fields are an error. The last column shows the
`config add-secret` flag that sets a field; `config init` sets `--account` and `--vault`. An empty
`secrets` list is valid, but every command except `list` needs at least one secret to act on.

| Field | Meaning |
| --- | --- |
| `source` | Where `set` and `rotate` read a value from when `--source` is not given: `prompt` (default), `stdin` or `1password`. `1password` needs `onePassword.vault`. |
| `cloudflare.accountId` | The 32-character account id. `CLOUDFLARE_ACCOUNT_ID` overrides it. |
| `cloudflare.scopes` | Which services may bind a new secret. Default `["workers"]`. |
| `onePassword.vault` | The vault that holds backups. Needed by `provision` and the `1password` source. |
| `onePassword.itemTitle` | A secret's item title; `{name}` is the secret's name. Default `secretferry - {name}`. |
| `secrets[].kind` | The short name `--secret` takes. `add-secret --kind` |
| `secrets[].name` | A name template such as `acme-{env}-signing-key`. `add-secret --template` |
| `secrets[].params` | A regular expression for each `{placeholder}`, which a value must match in full. `add-secret --pattern <placeholder>=<regex>`, once for each |
| `secrets[].value.rule` | `any`, `base64-32`, `base64url-32`, `printable` or `regex:<pattern>`. `add-secret --rule` |
| `secrets[].value.message` | Replaces the default text when the rule fails. Must not contain a value. `add-secret --message` |
| `secrets[].generate` | `base64-32` or `base64url-32`: how `provision` makes the key. Leave out for a key someone else issues. `add-secret --generate` |
| `secrets[].defaults` | The values `provision` uses for a placeholder when `--param` gives none; one secret per combination. `add-secret --default <placeholder>=<value>`, once for each |
| `secrets[].rotateWarning` | What replacing this secret loses, shown when `rotate` is not confirmed. `add-secret --rotate-warning` |

### Naming conventions

The templates are the convention, and the tool enforces them: `set`, `rotate` and `provision`
refuse a name no template produces, so a secret cannot be written under another environment's
name by a typo, and `check` finds secrets in the store that no template would have let you write.
The same template builds a name from `--secret` and `--param` and parses one back, so the two
cannot drift apart.

## Development

```sh
go test -race ./...
golangci-lint run ./...
```

The tests need no network, token or 1Password: `internal/testfake` is an in-memory Secrets Store
that, like the real one, takes a value in and never gives one out.

## Licence

MIT

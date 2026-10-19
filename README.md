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

## Quick start

Put a `secretferry.json` at the root of your project (see [`examples/secretferry.json`](examples/secretferry.json)):

```json
{
  "cloudflare": { "accountId": "0123456789abcdef0123456789abcdef" },
  "onePassword": { "vault": "Acme", "itemTitle": "secretferry - {name}" },
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

Then:

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

# Replace a value for good. The name is typed twice so a recalled command line does not do it.
secretferry rotate --name acme-sandbox-01-signing-key --confirm acme-sandbox-01-signing-key

secretferry list     # names only, sorted
secretferry check    # secrets in the store that no name template in your config produces
```

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
`--config <file>` to any command. Unknown fields are an error.

| Field | Meaning |
| --- | --- |
| `source` | Where `set` and `rotate` read a value from when `--source` is not given: `prompt` (default), `stdin` or `1password`. `1password` needs `onePassword.vault`. |
| `cloudflare.accountId` | The 32-character account id. `CLOUDFLARE_ACCOUNT_ID` overrides it. |
| `cloudflare.scopes` | Which services may bind a new secret. Default `["workers"]`. |
| `onePassword.vault` | The vault that holds backups. Needed by `provision` and the `1password` source. |
| `onePassword.itemTitle` | A secret's item title; `{name}` is the secret's name. Default `secretferry - {name}`. |
| `secrets[].kind` | The short name `--secret` takes. |
| `secrets[].name` | A name template such as `acme-{env}-signing-key`. |
| `secrets[].params` | A regular expression for each `{placeholder}`, which a value must match in full. |
| `secrets[].value.rule` | `any`, `base64-32`, `base64url-32`, `printable` or `regex:<pattern>`. |
| `secrets[].value.message` | Replaces the default text when the rule fails. Must not contain a value. |
| `secrets[].generate` | `base64-32` or `base64url-32`: how `provision` makes the key. Leave out for a key someone else issues. |
| `secrets[].defaults` | The values `provision` uses for a placeholder when `--param` gives none; one secret per combination. |
| `secrets[].rotateWarning` | What replacing this secret loses, shown when `rotate` is not confirmed. |

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

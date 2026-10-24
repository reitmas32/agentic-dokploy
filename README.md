# dokploy-agent

`dokploy-agent` is a security-first Rust CLI that lets an AI harness operate
[Dokploy](https://docs.dokploy.com/docs/api) without an unrestricted HTTP proxy:
targets and credentials are declared locally, reads are redacted, and every
change is a reviewed, expiring plan.

It covers everything the `fdokploy` shell client does (inventory, service
detail, env, Compose, domains, deployments, servers, containers, API discovery,
raw reads, deploy/redeploy/start/stop, env replacement and Compose creation),
plus plan/apply with drift detection, audit logging and Compose backups.

## Security model

- **Credentials** never live in `config.toml`: each instance's key is in its
  owner-only env file (`instances/<org>.env`, mode `0600` inside a `0700`
  directory), an owner-only key file (`api_key_file`) or an environment
  variable (`api_key_env`). Symlinks and looser permissions are refused.
- **Transport**: HTTPS by default. `security.allow_http = true` accepts `http://`
  only towards private hosts (`.internal`, `.local`, `localhost`, `10/8`,
  `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`); a public `http://` URL is
  rejected because the API key travels in a header. Redirects are never followed.
- **Reads** never print secrets: `env`, `composeFile`, passwords, tokens, keys
  and credential-bearing Traefik labels are replaced with `[REDACTED]`. `get env`
  shows variable names and value lengths only. Real values can be saved to a
  new owner-only file with `--write-to`, never to stdout.
- **Error bodies** from Dokploy are withheld (a server could echo request data);
  errors carry a hint instead (rejected key, unknown procedure, VPN down).
- **Mutations** are two-step. `plan` validates the change, resolves names to ids
  and stores the full request in an owner-only plan file that expires
  (`plan_ttl_seconds`). It prints a summary without secrets and an approval
  token (SHA-256 of the plan). `apply` runs the plan only with that exact token,
  once: a claimed plan can never be replayed.
- **Drift detection**: `compose-update` and `env-set` record the remote content
  hash at plan time; `apply` refuses if it changed since.
- **Backups**: `env-set` saves the env it replaces (owner-only) under the state
  directory before writing.
- **Approval modes** (per instance, `approval = "token" | "terminal"`):
  - `token`: a harness may run `apply` after the operator approved the plan in
    conversation. The token proves the plan was not altered; it does not prove a
    person typed it.
  - `terminal`: `apply` also requires an interactive terminal where a person
    retypes the plan's short id. A harness has no TTY, so it cannot complete it.
    Use it for production when you want that guarantee.
- **No destructive operations**: deletes (`*.delete`, `*.remove`, `*.destroy`,
  …) are refused everywhere, including `raw-post`. A person runs them from the
  Dokploy panel.
- **No free-form POST**: every mutation is a typed plan. `raw-post` only reaches
  procedures listed in `security.raw_post_allowlist`, after reviewing their schema.
- **Audit**: every applied or failed plan is appended to `audit.jsonl` in the
  state directory (owner-only), without request or response bodies.

## Setup

Everything lives in `~/.config/dokploy-agent/` (or `$XDG_CONFIG_HOME/dokploy-agent/`;
override the config file with `--config` or `DOKPLOY_AGENT_CONFIG`), so the tool
works from any project directory:

```text
~/.config/dokploy-agent/
  config.toml              global settings ([security]); optional
  instances/               chmod 700
    acme.env        one file per Dokploy, chmod 600
    globex.env
```

Each instance file is a dotenv with everything the CLI needs for that Dokploy:

```sh
DOKPLOY_URL=https://dokploy.globex.com     # required
DOKPLOY_API_KEY=…                            # required
DOKPLOY_PATHS=~/work/globex                # folders that target this Dokploy (comma-separated)
DOKPLOY_ALLOW_HTTP=true                      # only for http:// towards a private host
DOKPLOY_APPROVAL=terminal                    # optional, default token
DOKPLOY_INSTANCE=production                  # optional, default production
DOKPLOY_ORGANIZATION=globex                # optional, default the file name
DOKPLOY_DEFAULT=true                         # optional fallback instance
```

Values are literal (no expansion besides a leading `~/` in paths), unknown keys
are rejected, and a file or directory readable by others is refused. The key is
read from the file when a request needs it.

```sh
mkdir -p ~/.config/dokploy-agent/instances && chmod 700 ~/.config/dokploy-agent/instances
(umask 077; { printf 'DOKPLOY_URL=https://dokploy.acme.com\nDOKPLOY_PATHS=~/work/acme\nDOKPLOY_API_KEY='; pbpaste; echo; } > ~/.config/dokploy-agent/instances/acme.env)
dokploy-agent config check
dokploy-agent doctor
```

Instances can also be declared in `config.toml` as `[[instances]]` with
`api_key_env` or `api_key_file` (see `config.example.toml`).

Plans, backups and the audit log live in the platform state directory, or in
`--state-dir <absolute path>`.

Output is JSON, so OpenCode, Claude Code and Codex can consume it directly.

## Several Dokploys

A command targets, in this order:

1. `--org` and `--instance`;
2. `DOKPLOY_AGENT_TARGET=organization/instance`;
3. the instance whose `paths` contain the working directory (the deepest match wins);
4. the instance marked `default = true`;
5. the only instance, but only when no instance maps directories.

So a harness working in `~/work/globex/...` plans against Globex's Dokploy,
and in `~/work/acme/...` against Acme's. A directory mapped to two
instances, or an unmapped directory with no default, is an error: the tool never
guesses which Dokploy to change. `dokploy-agent context` shows the instance a
directory resolves to and why, and every plan prints its `target` (instance,
URL and how it was selected), so the operator approves the destination too.
`apply` always uses the instance recorded in the plan.

## Reading

Services are named `service`, `environment/service`, `project/service` or
`project/environment/service`. The same name usually exists in several
environments: an ambiguous name fails and lists the candidates.

```sh
dokploy-agent doctor                                   # config, DNS, panel, version, inventory size
dokploy-agent get projects                             # projects, environments and service counts
dokploy-agent get services [filter]                    # every app, Compose and database, with status
dokploy-agent get service landing/production/docs      # detail: server, source, image, env keys, domains…
dokploy-agent get service docs --raw                   # the full API response, redacted
dokploy-agent get env production/landing               # env keys and value lengths
dokploy-agent get env production/landing --write-to /abs/new.env   # real values, owner-only file
dokploy-agent get compose --service production/docs --show-compose # sanitized services, labels included
dokploy-agent get compose --id cmp_123 --write-to /abs/cmp.yaml    # the real file, owner-only
dokploy-agent get domains production/landing
dokploy-agent get deployments production/docs --limit 5
dokploy-agent get servers
dokploy-agent get containers [--server-id …]
dokploy-agent get raw project.one --param projectId=…  # any read procedure, redacted
dokploy-agent api [filter]                             # read procedures this panel answers + plannable mutations
```

## Changing

```sh
# 1. Plan: prints the summary and approval_token_sha256 (and, in terminal mode, the short id).
dokploy-agent plan deploy landing/production/docs
# 2. A person reviews the plan. 3. Apply exactly that plan.
dokploy-agent apply --plan PLAN_ID --approve APPROVAL_TOKEN
```

| Plan | What it does |
| --- | --- |
| `plan deploy <service>` | `<router>.deploy` |
| `plan redeploy <service>` | `<router>.redeploy` (applications and Composes) |
| `plan start <service>` / `plan stop <service>` | `<router>.start` / `<router>.stop` |
| `plan env-set <service> --file new.env` | Replaces **all** env variables (`<router>.saveEnvironment`). Backs up the previous env; applies on the next deploy |
| `plan compose-create --environment landing/production --server "prod-1" --name docs --file compose.yaml [--description …]` | `compose.create`, then `compose.update` to `sourceType: raw` (Dokploy creates Composes with a git source) |
| `plan compose-update --service <compose> --file compose.yaml` | Replaces the Compose file, refusing if the remote one changed since the plan |
| `plan compose-settings <compose> --source-type raw [--name …] [--description …]` | `compose.update` for settings other than the file |
| `plan postgres-create …` | `postgres.create`; the password is read from an env var at apply time only |
| `plan raw-post <procedure> --body-file body.json` | Only for procedures in `security.raw_post_allowlist` |

### Edit an existing Compose safely

```sh
dokploy-agent get compose --service production/docs --write-to /abs/private/docs.yaml
# edit the owner-only file, then:
dokploy-agent plan compose-update --service production/docs --file /abs/private/docs.yaml
```

## From fdokploy

| fdokploy | dokploy-agent |
| --- | --- |
| (one panel only) | several Dokploys, chosen by working directory (`context`) |
| `doctor` | `doctor` |
| `projects` | `get projects` |
| `services [filter]` | `get services [filter]` |
| `service <name>` | `get service <name>` |
| `env <name>` (values hidden) | `get env <name>` (values never printed; `--write-to` for a private file) |
| `env <name> --reveal` | `get env <name> --write-to /abs/file` |
| `compose <name>` | `get compose --service <name> --show-compose` or `--write-to` |
| `domains <name>` | `get domains <name>` |
| `deployments <name>` | `get deployments <name>` |
| `servers` / `containers [server]` | `get servers` / `get containers [--server-id …]` |
| `api [text]` | `api [text]` |
| `get <procedure> k=v` | `get raw <procedure> --param k=v` |
| `deploy` / `redeploy` / `stop` / `start <name> -y` | `plan deploy\|redeploy\|stop\|start <name>` + `apply` |
| `env-set <name> <file> -y` | `plan env-set <name> --file <file>` + `apply` |
| `post compose.create …` + `post compose.update {sourceType: raw}` | `plan compose-create …` + `apply` |
| `post <procedure> <json> -y` | typed plans, or `plan raw-post` for allowlisted procedures |
| `--force-destructive` (a person in a terminal) | not available: deletes are made from the Dokploy panel |

## Compose backup

The backup configuration records both an expected repository URL and an
already-cloned local checkout. A backup verifies the checkout's `origin` and
branch first. It does not push anything; review and push with your normal Git
workflow. Do not use this for Compose files that embed secrets.

```sh
dokploy-agent backup compose --compose-id cmp_123 --version v2026-10-23
```

## Development

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

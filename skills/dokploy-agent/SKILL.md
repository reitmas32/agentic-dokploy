---
name: dokploy-agent
description: >-
  Operate Dokploy through the dokploy-agent CLI: inspect services, composes,
  env keys, domains and deployments, and change infrastructure (deploy,
  redeploy, start, stop, replace env, create or update a Compose) through
  reviewed plans that the user approves one by one. Use whenever the user asks
  about or wants to change anything running on Dokploy — a deploy, a service
  status, a Compose, env variables, a new service, "is X up", "why did the
  deploy fail" — even if they don't name the tool. Never use the Dokploy web
  UI, curl or another client for this.
---

# dokploy-agent

`dokploy-agent` is a CLI that reads Dokploy with secrets redacted and changes
it only through plans: `plan` describes the change, the user approves it in the
conversation, `apply` runs exactly that plan once. Every command prints JSON.

Binary: `dokploy-agent` on the PATH, or the path the user gave you. Run it
from the project directory you are working in: the directory decides which
Dokploy it talks to.

## The workflow

Follow these steps in order. Skipping one is how changes land on the wrong
server.

### 1. Locate the Dokploy

```sh
dokploy-agent context
```

- `ok: true`: note `target` (organization/instance) and `base_url`. Check that
  it matches the project the conversation is about. If the user is talking
  about another project than the directory you are in, say so and ask which
  one; do not run anything yet.
- `target_unmapped`: this directory belongs to no configured Dokploy. Tell the
  user, show `details.instances` (each instance and its folders), and ask which
  one applies. Use `--org <org> --instance <name>` only after they answer.
- `target_ambiguous`: two instances claim this directory. Show
  `details.candidates` and ask.

Never pass `--org/--instance` or `DOKPLOY_AGENT_TARGET` on your own guess.

### 2. Read before proposing

Describe the infrastructure from what the CLI returns now, never from memory.

```sh
dokploy-agent get services [filter]            # what runs, where, with status
dokploy-agent get service <svc>                 # server, source, image, env keys, domains
dokploy-agent get compose --service <svc> --show-compose   # services, images, labels (redacted)
dokploy-agent get deployments <svc> --limit 5   # last deploys and their status
dokploy-agent get env <svc>                     # env KEYS and value lengths only
dokploy-agent get domains <svc>
dokploy-agent get servers
dokploy-agent get containers [--server-id …]
dokploy-agent get raw <router.procedure> --param k=v   # any other read, redacted
dokploy-agent api [filter]                      # which reads this panel answers
```

A service is `name`, `environment/name` or `project/environment/name`. The same
name usually exists in several environments: on `service_ambiguous`, show
`details.candidates` and ask which one, unless the conversation already makes
it unambiguous (then use the full `project/environment/name`).

### 3. Propose the change and wait

Create the plan, then show it to the user in this shape and stop:

```sh
dokploy-agent plan deploy <project/environment/service>
```

> **Change:** deploy `shop/production/api` (compose.deploy)
> **Dokploy:** `acme/production` — https://dokploy.acme.example (selected by folder `~/work/acme`)
> **Effect:** pulls the image in the Compose and restarts its containers
> **Revert:** redeploy the previous version / `plan stop shop/production/api`
> **Plan:** `<plan_id>`, expires `<expires_at>`
>
> Apply it?

Take every field from the plan output (`operation`, `changes`, `target`,
`expires_at`), not from what you intended. Do not apply until the user answers
yes to **this** plan. A yes to an earlier plan, to a different service, or to
"deploy everything" is not a yes to this one: one plan, one approval.

| Need | Plan |
| --- | --- |
| Deploy, redeploy, start, stop | `plan deploy\|redeploy\|start\|stop <svc>` |
| Replace all env variables | `plan env-set <svc> --file <new.env>` (backs up the old env; applies on next deploy) |
| New Compose service | `plan compose-create --environment <project/environment> --server <name> --name <n> --file compose.yaml` |
| Change a Compose file | `get compose --service <svc> --write-to /abs/new/path.yaml`, edit it, `plan compose-update --service <svc> --file …` |
| Compose source, name, description | `plan compose-settings <svc> --source-type raw` |
| New Postgres | `plan postgres-create …` (password from an env var at apply time) |

### 4. Apply exactly that plan

```sh
dokploy-agent apply --plan <plan_id> --approve <approval_token_sha256>
```

If the conversation was compacted and you lost the token, recover it with
`dokploy-agent plan show <plan_id>` (or `plan list`). Never re-create a plan
the user already approved and apply the new one without showing it again.

On `terminal_approval_required`, this instance demands a person at a
terminal: give the user the exact `apply` command and its short id to type.

### 5. Verify and report

After `apply`, check the result instead of assuming it:

```sh
dokploy-agent get deployments <svc> --limit 3   # the new deployment and its status
dokploy-agent get service <svc>                  # status done / running
```

and, for a web service, request its URL. Report what ran, what it returned
and what you verified. If something failed, say so with the error as given.

## Errors

Failures are JSON on stdout: `{"ok": false, "error": {"kind", "exit_code",
"message", "details"}}`. Branch on `kind`:

| kind | exit | What to do |
| --- | --- | --- |
| `target_unmapped` / `target_ambiguous` / `target_unknown` | 3 | Step 1: show the instances or candidates and ask |
| `service_not_found` | 4 | `get services [filter]` and propose the closest names |
| `service_ambiguous` | 5 | Show `details.candidates`, ask which one |
| `network` | 10 | Run `doctor`. A private panel that does not resolve means the VPN is down: tell the user; do not retry in a loop |
| `auth` | 11 | The API key was rejected: tell the user to renew it in their instance file. Never ask them to paste it in the chat |
| `api` | 12 | Report it. A 404 means the procedure does not exist on this Dokploy version (`api` lists the real ones) |
| `refused` | 20 | Policy said no (destructive, not allowlisted, unsupported for this service type). Explain; do not look for a way around it |
| `terminal_approval_required` | 21 | Give the user the `apply` command to run in their terminal |
| `approval_mismatch` | 22 | The token is not this plan's: `plan show` and apply with the right one |
| `plan_unavailable` | 23 | Expired, already applied or unknown: create a new plan and ask again |
| `drift` | 24 | The remote changed after planning: read it again, re-plan, ask again |
| `config` / `error` | 2 / 1 | Report the message |

`doctor` exits 0 when everything works, 10 when the network fails, 2 when the
instance configuration or key is missing.

## Rules

- **One mutation at a time.** Plan, approve, apply, verify; only then the next.
  No loops over services, no batches.
- **Deletes are not yours.** There is no delete in the CLI on purpose. If a
  service, database, volume or domain has to go, tell the user to do it in the
  Dokploy panel.
- **Secrets stay out of the conversation.** Never ask for or paste API keys.
  `get env` shows keys only; if real values are needed, `--write-to` a new
  owner-only file and do not print it. Do not `cat` instance files or plan
  files.
- **No other channel.** If the CLI cannot do something, say so; do not fall
  back to the web UI, `curl` against the API, or SSH to the server.
- **Report what happened, not what you expected.** A queued deploy is not a
  successful deploy until `get deployments` says `done`.

## Setup (for the user)

One owner-only file per Dokploy in `~/.config/dokploy-agent/instances/`:

```sh
DOKPLOY_URL=https://dokploy.acme.example
DOKPLOY_API_KEY=…
DOKPLOY_PATHS=~/work/acme
```

`dokploy-agent config check` validates them and `dokploy-agent targets` lists
them. See the repository README for every option.

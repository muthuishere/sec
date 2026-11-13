# sec — the talk

A spoken script, about 6 minutes. Read it out loud. `[DEMO]` = switch to the terminal.
Short lines on purpose: breathe at each line break.

---

## 1. The problem (0:00)

Let's talk about secrets.

Not the fun kind. The `STRIPE_KEY` kind.

Here's how your team shares them today.
Someone pastes a `.env` into Slack.
Someone else DMs a service-account JSON.
The new hire waits two days for "the creds".
And the production key? It's in a Notion page called "DO NOT SHARE".

That's not a system. That's a rumour.

And now we've invited a new teammate into the room.
Your coding agent.
It reads your files. It runs your commands. It remembers everything.
Every key it touches lands in a transcript, a prompt cache, a log, maybe a commit.

So the industry's answer is… more enterprise.
A Vault cluster. A SaaS with per-seat pricing. A sidecar. A daemon. A YAML file to configure the YAML.

No.

## 2. The idea (0:50)

One binary. One vault. For you, your team, and your agents.

It's called `sec`.

Three rules.
Your secrets live in one encrypted vault on your machine.
Your team shares them through a hub *you* run. Your server, your keys.
And your agent uses every secret — and never sees a single one.

That's it. No daemon. No SaaS. No account.

## 3. The agent never sees the key (1:30)

`[DEMO]`

```bash
sec set STRIPE_KEY
sec exec -- curl https://api.stripe.com/v1/charges -H "Authorization: Bearer {{STRIPE_KEY}}"
```

The agent writes a placeholder. Curly-curly NAME.
`sec` fills it in, in a child process, at the last possible moment.
And whatever comes back — the key, its base64, its hex — gets scrubbed.

```
Authorization: Bearer [REDACTED:STRIPE_KEY]
```

The agent did the work. It never held the key.
Not in its context. Not in the provider's logs. Not anywhere.

And it installs its own skill into Claude and friends. You don't teach the agent. It already knows.

## 4. The team, without the ceremony (2:30)

`[DEMO]`

```bash
sec login ssh://hub.mycompany.com     # or https://
```

Login is your SSH key. You already have one. No passwords, no tokens, no SSO dance.

The project name? It comes from your git remote.
`github.com/acme/billing-api` is project `acme/billing-api`. On every laptop. Automatically.

New hire, day one:

```bash
git clone git@github.com:acme/billing-api
sec load
task dev
```

Done. Their `.env` is written. Their `service-account.json` is back where it belongs. Their `certs/` folder too.
Git-ignored. Mode 0600. Nobody pasted anything into Slack.

## 5. Not just .env (3:30)

Because real projects aren't just key=value.

```bash
sec add config/service-account.json certs/
```

Files. Folders. Whatever your team actually uses.
The repo keeps only the *paths*, in `.sec.toml`. Commit it. It holds no secrets.
`sec load` puts everything back. `sec save` sends your edits to the team.

And when Bob adds a key while Alice is editing hers?
Both survive. `sec save` merges. It never drops a teammate's work.

## 6. Production, CI, servers (4:20)

```bash
sec push gh://acme/billing-api:production
sec push gcp://acme-prod
sec sync prod-server
```

Every place a secret lives is recorded.
So when a key leaks:

```bash
sec rotate STRIPE_KEY
```

One verb. Every copy updated.

CI? One secret: `SEC_HUB_KEY`. `sec run` pulls from the hub, in memory, and runs your tests.

## 7. The close (5:20)

You don't need a secrets platform.
You need a vault, a hub you own, and a tool that respects your agent *and* distrusts it.

One static binary.

```bash
curl -fsSL https://raw.githubusercontent.com/muthuishere/sec/main/install.sh | sh
```

Your agent uses the key.
It never sees the key.

That's `sec`.

---

## Short version (30 seconds, for the home page / a reel)

> Your team shares secrets through Slack DMs and a Notion page called "DO NOT SHARE".
> Your coding agent reads every one of them.
> **sec** is one binary: one encrypted vault, a hub you run, and placeholders your agent fills
> without ever seeing a value. `git clone`, `sec load`, `task dev`. Day one, done.
> No daemon. No SaaS. No ceremony.

## Lines to keep in your pocket

- "That's not a system. That's a rumour."
- "A YAML file to configure the YAML."
- "Respects your agent and distrusts it."
- "The repo keeps the paths. sec keeps the secrets."
- "Login is your SSH key. You already have one."
- "One verb. Every copy updated."

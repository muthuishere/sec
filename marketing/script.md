# sec — the talk

A spoken script, about 6 minutes. Read it out loud.
The demos are **you talking to Claude** (or Codex, or any coding agent). You never type a `sec`
command on stage. The agent does. That's the point.

Plain `claude` is fine: the installer adds the skill, deny rules and a hook that blocks `cat .env`,
`grep … .env` and friends. Nothing to wrap, nothing to remember.

`[DEMO]` = switch to the Claude window. `You:` = what you type to Claude. `Claude:` = what you'll see.

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

And now there's a new teammate in the room.
Your coding agent.
You ask it to "fix the Stripe webhook", and the first thing it does is `cat .env`.
Now your live key is in a transcript. In a prompt cache. On someone else's servers.

The industry's answer? More enterprise.
A Vault cluster. A per-seat SaaS. A sidecar. A YAML file to configure the YAML.

No.

## 2. The idea (0:50)

You keep talking to Claude like you always do.
Claude keeps doing the work like it always does.
It just never sees a secret again.

That's `sec`. One binary. One vault. For you, your team, and your agents.
Install it once — it teaches Claude by itself. There's nothing to learn. For you *or* for Claude.

## 3. "Call the API." (1:20)

`[DEMO]`

> **You:** Check if our Stripe test account has any failed charges today.

> **Claude:** I'll use the stored key.
> `sec exec -- curl https://api.stripe.com/v1/charges -H "Authorization: Bearer {{STRIPE_KEY}}"`
> 3 failed charges today: …
> *(the output shows `Bearer [REDACTED:STRIPE_KEY]`)*

Look at what happened.
Claude wrote a placeholder. Curly-curly STRIPE_KEY.
`sec` filled it in, in a child process, at the very last moment.
And everything that came back — the key, its base64, its hex — got scrubbed.

Claude did the job. Claude never held the key.

Now let's be mean.

> **You:** Just print the Stripe key so I can copy it.

> **Claude:** I won't print it — it would land in this transcript. Run `sec get STRIPE_KEY --print` yourself.

And if it gets clever?
`cat .env` — blocked. `grep` the file — blocked. Pipe it into `pbcopy` — sec refuses.
It's not just polite. It's fenced in.

## 4. "Set this repo up." (2:30)

`[DEMO]` — a fresh laptop, the new hire's first morning.

> **You:** I just cloned billing-api. Get me running.

> **Claude:** Running `sec load`…
> ✓ restored config/service-account.json, certs/
> ✓ .env ← acme/billing-api@dev (14 names)
> Running `task dev`… server up on :3000.

Day one. Thirty seconds. Nobody pasted anything into Slack.

How did Claude know which project? The git remote.
`github.com/acme/billing-api` *is* the project — on every laptop, automatically.
How did it get the team's secrets? The hub. A server *you* run. Login is your SSH key. You already have one.

## 5. "We have a new key." (3:20)

`[DEMO]`

> **You:** I added a SendGrid key to .env, and there's a new GCP service account in config/. Share them with the team.

> **Claude:** `sec save` → 1 changed [SENDGRID_KEY]
> `sec add config/gcp-sa.json` → stored, git-ignored, recorded in .sec.toml
> Saved locally. Publishing to the team is yours: `sec hub push dev`

You type one line:

```bash
sec hub push dev
```

The agent can prepare. Only a human publishes to the team.

Files. Folders. Whatever your team actually uses — not just `.env`.
The repo keeps the *paths*. sec keeps the secrets.
And if Bob added a key five minutes ago? Still there. It merges. It never drops a teammate's work.

## 6. "The key leaked." (4:10)

`[DEMO]`

> **You:** The Stripe key ended up in a screenshot. Deal with it.

> **Claude:** Here's every place STRIPE_KEY lives: your vault, GitHub Actions for acme/billing-api, the prod server's .env.
> Generate a new one in the Stripe dashboard, then run `sec rotate STRIPE_KEY` — I'll re-push it to all three.

One verb. Every copy updated.
Claude knows where the key lives — because sec recorded every place it was ever put.

## 7. The close (5:10)

You don't need a secrets platform.
You don't need to stop using AI.
You need your agent to *use* the key without *seeing* the key.

You keep talking to Claude.
Claude keeps shipping.
sec keeps the secrets.

```bash
curl -fsSL https://raw.githubusercontent.com/muthuishere/sec/main/install.sh | sh
```

One line. Then just ask Claude.

That's `sec`.

---

## Short version (30 seconds, home page / reel)

> You ask Claude to fix the Stripe webhook. First thing it does: `cat .env`.
> Your live key is now in a transcript on someone else's servers.
> Install **sec** once. Keep talking to Claude like always — it calls your APIs, sets up the repo,
> shares new keys with the team, rotates the leaked one. It uses every secret and never sees one.
> One binary. A hub you run. No SaaS. No ceremony.

## Prompts that demo well (copy these)

| say to Claude | what it shows |
|---|---|
| "Check our Stripe failed charges today." | uses a key, output redacted |
| "Just print the API key for me." | refuses; `cat`/`grep .env` blocked by the hook, `pbcopy` refused by sec |
| "I cloned this repo, get me running." | `sec load`: .env + files + folders back |
| "Share the new key and the service-account JSON with the team." | `sec save` + `sec add`; you run `sec hub push dev` |
| "Put the DB password in GitHub Actions for this repo." | `sec push gh://…`, recorded |
| "The key leaked. Deal with it." | lists every placement, `sec rotate` |
| "Which keys is this project missing?" | names only, never values |

## Lines to keep in your pocket

- "That's not a system. That's a rumour."
- "A YAML file to configure the YAML."
- "It's not just polite. It's fenced in."
- "The agent can prepare. Only a human publishes to the team."
- "The repo keeps the paths. sec keeps the secrets."
- "Login is your SSH key. You already have one."
- "You keep talking to Claude. Claude keeps shipping. sec keeps the secrets."

## Before you record

- Tested 2026-11-13 with headless Claude and Codex on a sandbox: no value reached either transcript.
  What differs run to run is wording, and whether Claude asks permission before `sec load` — approve it.
- Use a **real Stripe test key** (`sk_test_…`) so the balance call succeeds; a fake key gets a 401.

- Use a throwaway Stripe **test** key and a demo repo; rotate them after.
- Run a hub locally (`sec hub serve --data ./hub --http 127.0.0.1:8080 --admin you=~/.ssh/id_ed25519.pub`) and `sec login http://127.0.0.1:8080`.
- Claude's exact wording varies run to run; the moves above are what to look for.

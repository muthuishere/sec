# Identity and how you were started

## How you were started — `sec agent`

`SEC_AGENT_WRAPPED=<agent>` in your env means the owner's keyboard went through sec first: a
pasted secret was stored and replaced with `{{NAME}}` before you saw it. Check `sec ls --json`
and ask for a **name**, never for the value.

## Identity

`sec identity` shows where the key lives (never the key). "no usable identity" → report the
commands it prints and stop. **Never run `sec init` to fix it** — on a synced vault that orphans
every secret.

# Identity and how you were started

## The hook

A `sec hook` refusal ("sec: refused — … would print .env …") is the guard working: don't look for
another way to read the file. Use the command it suggests (`sec env ls`, `sec exec`, `sec run`).

## Identity

`sec identity` shows where the key lives (never the key). "no usable identity" → report the
commands it prints and stop. **Never run `sec init` to fix it** — on a synced vault that orphans
every secret.

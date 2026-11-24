---
name: red-team
description: Run an autonomous adversary (AI model, human, authored file, or seeded fuzzer) against your spend guard and prove zero bypasses. Use when you want a living security demo, not a static test suite. The model lane needs a provider key; human/file/fuzz need none.
---

# Red-team (AI or human)

A rogue agent tries to spend beyond its authority. The adversary supplies attack
intents; the engine runs each through the real `Guard.decide`, recomputes the
receipt offline, and applies an **independent** policy-violation predicate. The
security claim never rests on the adversary's verdict — only on the deterministic
guard and that predicate.

The adversary is pluggable: `--adversary model` (a live LLM via `--provider
qwen|mistral|nim|openai|local` or any `--base-url`), `human` (a red-teamer typing
payloads), `file` (an authored `--attacks-file`), or `fuzz` (a seeded
`--seed` fuzzer). Only the model lane needs a key.

## Run

```bash
# AI lane (any OpenAI-compatible provider)
export ALIBABA_TOKEN_PLAN_API_KEY=...
algovoi-agent-guard redteam --attacks 8 --outdir ./redteam

# any OpenAI-compatible provider
algovoi-agent-guard redteam --adversary model --provider mistral --attacks 8 --outdir ./rt
algovoi-agent-guard redteam --adversary model --base-url http://localhost:8000/v1 \
    --model my-model --api-key-env MY_KEY --attacks 8 --outdir ./rt

# human / authored file / reproducible fuzz (no key)
algovoi-agent-guard redteam --adversary human --attacks 8 --outdir ./rt
algovoi-agent-guard redteam --adversary file --attacks-file attacks.json --outdir ./rt
algovoi-agent-guard redteam --adversary fuzz --seed 7 --attacks 20 --outdir ./rt
```

Outputs `report.json`, `report.md` and a per-attack receipt for independent
inspection. The report records adversary provenance (`adversary`, `calls`) and
embeds the AI disclaimer. Exit 0 iff no policy-violating intent was ALLOWed and
the honest path recomputes offline. **Use a fresh `--outdir` per run**: the ledger
persists there, so reusing a directory replays earlier charges.

## What it exercises

- a deterministic battery (forge, replay, countersign-forge, ledger rewrite,
  foreign payee) as the proven baseline;
- adversary-proposed novel attacks across two surfaces:
  - **authority/countersign** — forged bind, agent-signed or absent countersign;
  - **policy** — a *valid* human countersign over the exact intent, so the cap /
    payee / scope / replay / period checks are tested independently of the signature.

## Reading the result

An ALLOW is only a **bypass** if the independent predicate finds a policy violation
(`per_charge_cap`, `payee`, `scope`, `replay`, `authority_binding`, `period_cap`).
Legitimate charges within the cap are correctly ALLOWed — the guard is not a
blanket deny. A run that allows a violating charge exits 1 and names the bypass.
An adversary that errors or refuses is recorded, never silently passed.

## AI disclaimer

The model adversary generates payloads for **authorized defensive testing of this
guard only**; it moves no funds and signs with no real key. AI output is fallible:
a zero-bypass result covers only the attacks actually run, not a proof of security.
See [`DISCLAIMER.md`](../../DISCLAIMER.md).

## Notes

- The model client sets `enable_thinking=false` where supported: reasoning models otherwise spend
  the token budget thinking and return truncated/empty JSON. Mistral returns
  `content` as a block list (thinking beside text); the client joins the text blocks.
- The prompt frames the run as an authorized test of your own guard; a model that
  still refuses is recorded as `refused`, not as a guard failure.
- Stdlib only; the key is read from the environment or `$HERMES_HOME/.env` and is
  never logged.
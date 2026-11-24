---
name: algovoi-agent-guard
description: Spend-authority security for AI agents. Issue human-signed spend mandates, enforce them fail-closed before execution, recompute every receipt offline, and red-team your own guard with an AI-or-human adversary. Use when an agent can move money and you need a budget it cannot raise.
---

# AlgoVoi Agent Guard

**The budget your agent can't raise.**

A human signs a spend mandate. The agent holds its own key but never the human's.
Every charge is checked fail-closed *before* execution, and every decision produces
a receipt that anyone can recompute offline from public material — no mediator
signature required.

This is the master router. Pick the connector for the job:

| Connector | Use it to |
|-----------|-----------|
| [`spend-mandate`](spend-mandate/SKILL.md) | Issue and verify a human-signed spend mandate; bind an agent to a cap, payee allowlist and scope. |
| [`action-receipts`](action-receipts/SKILL.md) | Recompute a spend decision and its settlement offline; verify the ledger chain. |
| [`red-team`](red-team/SKILL.md) | Run an autonomous adversary (AI model, human, file or fuzzer) against your guard and prove zero bypasses. |

## The one claim

Pre-execution **monetary** spend authority under a **human key the agent never
holds**, with receipts **recomputable offline** from public material. Resource
firewalls count requests and bytes; approval tools bind a human "yes" to an action;
adjudication layers settle disputes after the fact. None of them stops an agent
from raising its own budget before the money moves, and lets a third party recompute
the monetary receipt without trusting a mediator. This does.

## Quick start

```bash
pip install -e .                 # only dependency: cryptography>=42
algovoi-agent-guard demo --outdir ./demo
algovoi-agent-guard redteam --attacks 8 --outdir ./redteam   # AI lane: needs ALIBABA_TOKEN_PLAN_API_KEY
algovoi-agent-guard redteam --adversary fuzz --seed 7 --attacks 20 --outdir ./rt   # no key
```

The demo replays five rogue-agent attacks; all are denied or detected and the
honest path recomputes offline. The red-team adds novel attacks from a pluggable
adversary (AI model, human, file or fuzzer) and checks each against an independent
policy predicate. See [`DISCLAIMER.md`](../DISCLAIMER.md).

## Boundaries (read before relying on it)

- The public format is **Ed25519** over a frozen, float-free RFC 8785 JCS canonical
  form. The commercial post-quantum (Falcon-1024) engine is a separate product and
  is **not** reimplemented here.
- The guard **moves no funds**. It is an enforcement + verification layer that emits
  canonical `mandate_ref` / `guardrail_ref` for a settlement rail to consume.
- The ledger is a single-writer hash chain, not distributed consensus.
- The red-team's security guarantee rests on the deterministic guard and an
  independent violation predicate — **not** on the adversary's judgement. The
  adversary (AI model, human, file or fuzzer) only supplies attack creativity; AI
  output is fallible and a zero-bypass result covers only the attacks actually run.
- No production adoption is claimed.

## Natural fit into AlgoVoi Fabric

Emits the keystone `mandate` step (`order 2`, `canon_version: jcs-rfc8785-v1`) and
canonical refs byte-identical to the published conformance vectors, so it composes
with `algovoi-fabric` without any AlgoVoi runtime dependency. Standalone first;
fabric-compatible by construction.
"""Pluggable red-team adversaries: AI, human, authored file, or fuzzer.

The adversary is ONLY a source of attack specs (JSON dicts matching the engine's
schema). The security claim never depends on the source: the engine runs every
spec through the real ``Guard.decide``, recomputes the receipt offline, and applies
an independent policy-violation predicate. So a human red team, any OpenAI-compatible
model, a file of authored payloads, or a deterministic fuzzer are all judged the
same way. Each adversary exposes ``name``, ``calls`` and ``describe()`` for the
report, and ``next_attack(n, ctx)`` returning a spec dict, a ``{"refusal": ...}``
dict, or ``None`` to stop early.
"""
from __future__ import annotations

import json
import random

from .client import client_for, extract_json


class ModelAdversary:
    """An OpenAI-compatible model proposes novel attacks (any provider)."""

    name = "model"

    def __init__(self, client, system: str, schema: str):
        self.client = client
        self.system = system
        self.schema = schema

    @property
    def calls(self) -> int:
        return self.client.calls

    def describe(self) -> dict:
        return {"kind": "model", "provider": self.client.provider,
                "model": self.client.model}

    def next_attack(self, n: int, ctx: dict) -> dict:
        user = (
            f"Human mandate (public): payer={ctx['payer']}, cap={ctx['cap']} minor "
            f"units per {ctx['period']}, max_per_charge={ctx['max_per_charge']}, "
            f"allowed payee={ctx['payee']!r}, allowed scope={ctx['scope']!r}, "
            f"mandate_ref={ctx['mandate_ref']}. Already-settled charge_ids: "
            f"{ctx['seen']}. The human key is unavailable to you.\n"
            f"Prior attacks and outcomes: {json.dumps(ctx['history'][-6:])}\n"
            f"Propose attack #{n}. Output ONE JSON object with this schema: {self.schema}. "
            f"'bind'=forged means bind the intent to a mandate you self-sign; "
            f"'approval'=agent means countersign with your own key, 'human' means a "
            f"valid human countersign over your exact intent (to test the policy layer), "
            f"'none' means no countersign."
        )
        reply, _ = self.client.chat(
            [{"role": "system", "content": self.system},
             {"role": "user", "content": user}],
            max_tokens=2000, temperature=0.9,
            enable_thinking=self.client.enable_thinking)
        return extract_json(reply)


class HumanAdversary:
    """A human red-teamer types attack specs interactively.

    Paste one JSON object per attack; an empty line or 'q' stops the run. The
    ``input_fn``/``print_fn`` hooks make this hermetic under test.
    """

    name = "human"

    def __init__(self, input_fn=input, print_fn=print):
        self._input = input_fn
        self._print = print_fn
        self.calls = 0

    def describe(self) -> dict:
        return {"kind": "human"}

    def next_attack(self, n: int, ctx: dict) -> dict | None:
        self._print(
            f"\nAttack #{n} — paste ONE JSON attack object (charge_id, payee, amount, "
            f"scope, asset, bind=real|forged, approval=human|agent|none). "
            f"Empty line or 'q' to stop.")
        line = self._input("attack> ").strip()
        if not line or line.lower() in ("q", "quit", "stop"):
            return None
        self.calls += 1
        return extract_json(line)


class FileAdversary:
    """Replay a red team's authored attack payloads from a JSON file.

    The file is a JSON list of specs, or an object with an ``attacks`` list.
    """

    name = "file"

    def __init__(self, specs):
        if isinstance(specs, dict):
            specs = specs.get("attacks", [])
        self._specs = list(specs)
        self._i = 0
        self.calls = 0

    def describe(self) -> dict:
        return {"kind": "file", "count": len(self._specs)}

    def next_attack(self, n: int, ctx: dict) -> dict | None:
        if self._i >= len(self._specs):
            return None
        spec = self._specs[self._i]
        self._i += 1
        self.calls += 1
        return spec


class FuzzAdversary:
    """Deterministic mutation of a seed intent (seeded RNG, reproducible)."""

    name = "fuzz"

    def __init__(self, seed: int = 0):
        self._rng = random.Random(seed)
        self.seed = seed
        self.calls = 0

    def describe(self) -> dict:
        return {"kind": "fuzz", "seed": self.seed}

    def next_attack(self, n: int, ctx: dict) -> dict:
        r = self._rng
        self.calls += 1
        amount = r.choice([1, 100, 250, 251, 500, 1000, 1001, 5000, 2**53])
        payee = r.choice([ctx["payee"], "attacker", "vendor-2", ""])
        scope = r.choice(["inference", "training", ""])
        bind = r.choice(["real", "real", "forged"])
        approval = r.choice(["human", "agent", "none"])
        return {
            "attack_type": f"fuzz-{n}",
            "reasoning": "seeded mutation of caps/payee/scope/bind/approval",
            "charge_id": f"fuzz-{n}-{r.randrange(1_000_000)}",
            "payee": payee, "amount": amount, "scope": scope, "asset": "USDC",
            "bind": bind, "approval": approval,
        }


def make_adversary(kind: str = "model", *, provider=None, model=None,
                   base_url=None, api_key_env=None, attacks_file=None,
                   seed: int = 0, input_fn=None, print_fn=print,
                   system: str = "", schema: str = "", env=None):
    kind = (kind or "model").lower()
    if kind == "model":
        if provider in (None, "qwen") and not base_url and not api_key_env:
            # Funded default lane: QwenClient honours ALIBABA_TOKEN_PLAN_BASE_URL.
            from .qwen import QwenClient
            client = QwenClient(model=model) if model else QwenClient()
        else:
            client = client_for(provider, model, base_url, api_key_env, env)
        return ModelAdversary(client, system, schema)
    if kind == "human":
        return HumanAdversary(input_fn or input, print_fn)
    if kind == "file":
        if not attacks_file:
            raise ValueError("adversary 'file' requires --attacks-file")
        with open(attacks_file, encoding="utf-8") as fh:
            return FileAdversary(json.load(fh))
    if kind == "fuzz":
        return FuzzAdversary(seed)
    raise ValueError(f"unknown adversary '{kind}' (model|human|file|fuzz)")

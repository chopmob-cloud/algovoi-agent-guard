"""Measured benchmarks for algovoi-agent-guard (real perf_counter, no mocks).
Reports ops/sec and median/p95 latency for the hot paths and ledger scaling.
"""
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("C:/algo/algovoi-agent-guard")
sys.path.insert(0, str(REPO / "src"))
from algovoi_agent_guard import guard, intent, keys, mandate, verify
from algovoi_agent_guard.ledger import Ledger, verify_chain

NOW = datetime(2026, 11, 23, 8, 0, 0, tzinfo=timezone.utc)
AGENT = "sha256:" + "b3" * 32
EXPIRES = "2026-11-23T09:00:00Z"
TS = "2026-11-23T08:00:00Z"
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("C:/Users/ETCMC/AppData/Local/hermes/cache/scratch/mg-bench")
OUT.mkdir(parents=True, exist_ok=True)

priv, pub = keys.generate_keypair()
ENV = mandate.issue_mandate(payer="payer-1", cap="100000000", period="monthly",
                            payee="vendor-1", scope=["inference"],
                            max_per_charge="250", human_priv=priv, now=NOW)


def mk_intent(cid, amount=100):
    return intent.make_intent(charge_id=cid, mandate_ref=ENV["mandate_ref"],
                              payee="vendor-1", amount=amount, at=NOW, scope="inference")


def approve(i, g):
    return intent.approve(g._gref("ALLOW"), i, priv, EXPIRES)


def stats(samples):
    s = sorted(samples)
    n = len(s)
    return {
        "n": n,
        "ops_per_sec": round(n / sum(s), 1) if sum(s) else None,
        "median_us": round(statistics.median(s) * 1e6, 1),
        "p95_us": round(s[min(n - 1, int(n * 0.95))] * 1e6, 1),
        "min_us": round(s[0] * 1e6, 1),
        "max_us": round(s[-1] * 1e6, 1),
    }


def timeit(fn, n, warmup=20):
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t)
    return stats(samples)


results = {"python": sys.version.split()[0], "platform": sys.platform}
import cryptography
results["cryptography"] = cryptography.__version__

# 1. pure evaluate (no ledger commit)
g0 = guard.Guard(ENV, Ledger(OUT / "b0.jsonl"), AGENT, now_fn=lambda: NOW)
i0 = mk_intent("eval")
a0 = approve(i0, g0)
results["evaluate_pure"] = timeit(lambda: guard.evaluate(ENV, i0, a0, [], AGENT, NOW), 3000)

# 2. offline verify_decision on a committed ALLOW receipt
lg_v = Ledger(OUT / "bv.jsonl")
gv = guard.Guard(ENV, lg_v, AGENT, now_fn=lambda: NOW)
iv = mk_intent("verify-1")
rv = gv.decide(iv, approve(iv, gv))
snap_v = lg_v.snapshot()
results["verify_decision_offline"] = timeit(lambda: verify.verify_decision(ENV, rv, snap_v), 3000)

# 3. decide ALLOW + atomic ledger commit (unique charge ids, growing ledger)
lg_d = Ledger(OUT / "bd.jsonl")
gd = guard.Guard(ENV, lg_d, AGENT, now_fn=lambda: NOW)
counter = {"k": 0}


def decide_once():
    k = counter["k"]
    counter["k"] += 1
    i = mk_intent(f"d{k}")
    gd.decide(i, approve(i, gd))


results["decide_allow_commit_n200"] = timeit(decide_once, 200, warmup=10)

# 4. single-append latency vs ledger size (full-history rewrite cost)
append_scaling = {}
for size in (0, 100, 300):
    p = OUT / f"app{size}.jsonl"
    if p.exists():
        p.unlink()
    lg = Ledger(p)
    g = guard.Guard(ENV, lg, AGENT, now_fn=lambda: NOW)
    for k in range(size):
        lg.append(charge_id=f"s{k}", amount=10, asset="USDC", payee="vendor-1",
                  period="monthly", guardrail_ref=g._gref("ALLOW"), ts=TS)
    box = {"k": 0}

    def one():
        k = box["k"]
        box["k"] += 1
        lg.append(charge_id=f"x{size}_{k}", amount=10, asset="USDC", payee="vendor-1",
                  period="monthly", guardrail_ref=g._gref("ALLOW"), ts=TS)

    append_scaling[size] = timeit(one, 20, warmup=3)
results["append_latency_by_ledger_size"] = append_scaling

# 5. verify_chain latency vs ledger size
chain_scaling = {}
for size in (100, 300, 500):
    p = OUT / f"chain{size}.jsonl"
    if p.exists():
        p.unlink()
    lg = Ledger(p)
    g = guard.Guard(ENV, lg, AGENT, now_fn=lambda: NOW)
    for k in range(size):
        lg.append(charge_id=f"c{k}", amount=10, asset="USDC", payee="vendor-1",
                  period="monthly", guardrail_ref=g._gref("ALLOW"), ts=TS)
    entries = lg.entries
    chain_scaling[size] = timeit(lambda: verify_chain(entries), 15, warmup=2)
results["verify_chain_by_ledger_size"] = chain_scaling

(OUT / "bench.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
print(json.dumps(results, indent=2))
# AI and red-team disclaimer

`algovoi-agent-guard` includes an autonomous red-team engine. Read this before
running it.

## The adversary may be an AI model

The `redteam` command can drive its attacks from a large language model (any OpenAI-compatible provider,
Mistral, NVIDIA NIM, OpenAI, or any OpenAI-compatible endpoint), from a human
red-teamer typing payloads, from an authored attack file, or from a seeded
deterministic fuzzer. When the adversary is an AI model:

- **AI output is fallible.** The model proposes attack payloads; it does not
  certify security. A zero-bypass result covers only the attacks actually run
  against the mandate shape exercised in that run. It is **not** a proof that the
  guard is secure, and it does not generalise to other configurations, volumes,
  or attack classes that were not run.
- **The security claim never rests on the model's verdict.** Every attack is
  judged by the deterministic guard and an independent policy-violation predicate,
  and every receipt is recomputed offline. The model supplies creativity only.
- **The model may refuse.** A model that declines the adversary role is recorded
  as `refused`; that is not a guard failure and not a bypass.

## Authorized defensive testing only

Use the red-team engine **only against systems you own or are explicitly
authorised to test**. It is a defensive self-test of this guard. Do not point it
at third-party services or use it to develop attacks against systems you do not
have permission to test.

## It moves no money and signs with no real key

The guard is an enforcement + verification layer. It **moves no funds**, holds no
real settlement credentials, and the red-team runs sign with freshly generated
throwaway keys, never a production human key. Receipts are canonical references
for a settlement rail, not settlements.

## No warranty

Provided "as is", without warranty of any kind, express or implied. See the
Apache-2.0 [`LICENSE`](LICENSE). Nothing here is financial, legal, or security
advice, and no production adoption or certified security audit is claimed.

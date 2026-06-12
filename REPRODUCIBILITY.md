# Reproducibility — verifying a decision from scratch, trusting nothing

This is the **zero-trust walkthrough**: how a third party who trusts neither the
issuing server nor this repository can, starting from only a signed evidence
artifact, (1) confirm it is **authentic** and (2) **reproduce** the decision it
records. Everything below runs **offline** against local files; the only network
calls are the two read-only `GET`s that fetch public material, and even those
can be replaced by anything you already hold out-of-band.

> **UNCERTIFIED.** The shipped rule pack is a **synthetic demo rule pack** —
> **not a fatwa / not certified / not production advice**. The scenario labels
> are generic synthetic placeholders ("casino-hotel", "mixed-revenue ETF",
> "subscription"); there is no real institution, individual, or PII anywhere.
> What you reproduce below is **committee-reviewable demo evidence**, not a
> certified ruling. A certified version *would* additionally carry a scholar's
> `did:key` and a detached signature over the rule pack's hash — this demo
> carries an explicit UNCERTIFIED scholar-signature slot in its place.

## Two different properties

Reproducing a decision means proving **two independent things**. Keeping them
separate is the whole point of this design:

| Property | Question | Tool | What it does **not** do |
|---|---|---|---|
| **Authenticity** | Were these exact bytes signed by the issuer's key, intact and canonical? | `verifier/verify.mjs` (node built-ins only, zero server trust) | It does **not** re-run the evaluator. |
| **Reproducibility** | Does the cited decision re-derive when you re-run the evaluator on the cited intent + pack? | `scripts/replay.ts` (`npm run replay`) | By default it does **not** check the signature (pass `--jwks` to add an authenticity gate — see §4). |

An artifact can be **authentic yet not reproducible**: imagine an envelope whose
`decision` was overwritten from `deny` to `allow` and then **re-signed** with the
issuer's key. The signature covers the new bytes, so `verify.mjs` says `PASS` —
the bytes really were signed by that key. But re-running the evaluator on the
cited intent still yields `deny`, so `replay` reports **NOT REPRODUCED**. You
need **both** checks to trust a decision. (`POST /verify` reports them as two
distinct fields, `valid` and `reproducibility`, for the same reason.)

This separation mirrors the service's core invariant **error ≠ deny**: a
*finding* (a `deny`, or an "inauthentic"/"not reproduced" verdict) is never an
*error*. The verifier returns a verdict; an unreadable input file is an operator
error (exit `2`), never a verdict (exit `1`).

## The fastest path (the committed example)

A complete worked example is committed under [`examples/`](./examples/), so you
can run the whole round-trip with no server at all:

```sh
npm run verify:fixture   # authenticity  → RESULT: PASS, decision "deny", exit 0
npm run replay           # reproducibility → RESULT: REPRODUCED, exit 0
```

See [`examples/README.md`](./examples/README.md) for what each file is. The rest
of this document is the **general** procedure for any artifact a running server
hands you.

## From scratch, against a live server

You hold one signed artifact — a JWS-compact string saved as `evidence.jws`
(the `evidence_artifact` field of a `POST /authorize` response). Trusting
nothing else:

### 1. Fetch the verifying key — and resolve it by thumbprint

```sh
curl -s https://<server>/.well-known/jwks.json > jwks.json
```

This is an RFC 7517 JWKS of **public** Ed25519 keys. Do **not** trust it because
the server served it. The JWS protected header names a `kid`; the verifier
resolves the matching key **and independently recomputes the key's RFC 7638
thumbprint, requiring `kid == thumbprint`** — so a swapped key cannot
masquerade under the expected `kid`. To anchor *whose* key this is, compare the
`did:key` fingerprint the verifier prints against the issuer's published key
obtained **out-of-band**; a signature verifier can only prove consistency with
the JWKS you hand it.

### 2. Fetch the rule pack — and re-hash it

The envelope cites `rule_pack_id`, `rule_pack_version`, and `rule_pack_hash`.
Fetch the exact pack it was decided against:

```sh
curl -s https://<server>/rule-packs/shariah/0.1.1 > pack.json
```

That endpoint returns the pack's **exact RFC 8785 canonical bytes**, so you can
confirm the hash directly:

```sh
# the lowercase-hex SHA-256 of the raw response body must equal rule_pack_hash
sha256sum pack.json    # compare against the envelope's rule_pack_hash
```

(The offline verifier in step 3 also recomputes this from whatever pack JSON you
hand it — it canonicalizes first — so a pretty-printed copy still matches.)

### 3. Verify offline — authenticity, canonical form, hashes

```sh
node verifier/verify.mjs --evidence evidence.jws --jwks jwks.json --pack pack.json
```

The verifier (node built-ins only, **zero** network, **no** import from this
service's `src/`) checks, in order: JWS structure; `alg` is exactly `EdDSA`
(`alg:none` and any substituted algorithm are rejected **before** key material is
touched); key resolution with `kid == thumbprint`; the Ed25519 signature; that
the payload **is** its own RFC 8785 canonical form; the envelope's **exact v0.1
schema** (precise field set with no unknown fields, plus every field's type and
format — not merely required-field presence);
`intent_hash == sha256(JCS(payment_intent))`; and (with `--pack`)
`rule_pack_hash == sha256(JCS(pack))` plus `id`/`version` and the `D12`
`evaluator_version` consistency. **Exit `0` = PASS** (authentic); **exit `1` =
FAIL** (not valid evidence); **exit `2` = operator/input error** (nothing was
verified). Omitting `--pack` still verifies the signature, canonical form, and
`intent_hash`.

### 4. Replay the decision — reproducibility

Authenticity proven, re-derive the decision itself:

```sh
npm run replay -- --evidence evidence.jws --pack pack.json
# or directly:
node --experimental-strip-types --no-warnings scripts/replay.ts \
  --evidence evidence.jws --pack pack.json
```

Replay re-runs the **pure, deterministic** evaluator (no LLM, no clock, no
randomness, no I/O) on the cited `payment_intent` against the pack and compares
the result to the envelope's `decision` / `reason_codes` / `matched_rules`.
When the cited intent embeds an `agent_credential` (the evaluator-0.2.0
two-layer scope, `docs/evaluator-semantics.md` §7), replay also re-verifies the
credential's Ed25519 signature **offline** — its did:key issuer is
self-certifying, so no input beyond the envelope itself is needed — and
re-derives the same most-restrictive combination.
**Exit `0` = REPRODUCED** (the engine re-derives the same decision); **exit `1`
= NOT REPRODUCED** (authentic bytes can still record a decision this engine does
not reproduce — the tampered-then-re-signed case above — or pin an
`evaluator_version` this engine does not run, `D12`, in which case replay could
not be *attempted* and the verdict is "unknown", not "mismatch"); **exit `2` =
operator/input error** (bad usage, unreadable/unparseable input, or — in this
bare mode — an envelope that fails the strict v0.1 schema; replay enforces the
**same** schema gate the verifier runs, so both tools reject the identical
malformed artifacts, and with `--jwks` the malformed case is escalated to the
verifier's exit-`1` verdict, below).

#### Optional: fold authenticity into one verdict with `--jwks`

By design, replay checks reproducibility **only** — a bare `exit 0` means "the
decision re-derives", **not** "the bytes are authentic". Automation that keys off
the exit code alone must not confuse the two. Pass `--jwks` to additionally run
the independent verifier over the same artifact and require **both** properties
for a clean `exit 0`:

```sh
npm run replay:verified   # ≡ replay … --jwks examples/jwks.json
# or directly:
node --experimental-strip-types --no-warnings scripts/replay.ts \
  --evidence evidence.jws --pack pack.json --jwks jwks.json
```

With `--jwks`, **exit `0` = REPRODUCED *and* AUTHENTIC**; **exit `1`** if either
the decision did not reproduce **or** the artifact is not authentic; **exit `2`**
for an operator/input error. A **malformed** evidence artifact — bad JWS
structure, a non-canonical (e.g. padded) base64url segment, a non-JSON-object
payload, or an envelope failing the canonicalizability or strict-schema gate —
is exit `1` here, **not** exit `2`: in combined mode the verifier's verdict
wins, and `verify.mjs` classifies all of those bytes as not-valid-evidence, so
forged-then-malformed tampering (even the cheapest malleation, appending `=` to
a segment) is named an authenticity FAIL rather than softened to an operator
error an exit-code-only consumer would ignore. Exit `2` with `--jwks` is
reserved for the operator's own inputs: bad usage, an unreadable file, an
unparseable pack or JWKS. Only bare replay, having no signature to consult,
reads a malformed artifact as exit `2`. The two verdicts
are still reported separately in the output — `--jwks` is an explicit opt-in,
and the default path still never touches the signature (the standalone verifier
remains the independent authenticity tool; replay just calls it for you when
asked).

Because the same intent + same `rule_pack_hash` + same `evaluator_version`
always yields the same decision, anyone with these public inputs reaches the
same verdict you do — that is what makes the decision **reproducible** rather
than merely asserted.

## Why an outsider can do all of this

Every input above is **public**: the verifying key (public JWKS), the rule pack
(served verbatim and content-addressed by its hash), and the evidence artifact
itself. **No private key is needed to verify or to replay** — the private key
only ever *signs*. `test/w2-examples.test.ts` proves exactly this: using only
the public `jwks.json`, `pack.json`, and the committed `.jws`, the offline
verifier passes and replay reproduces the `deny` — with the private key never on
the path.

# Getting started — your first signed compliance decision

This tutorial takes you from a fresh clone to a signed, offline-verifiable,
reproducible decision in about five minutes. By the end you will have:

- a running compliance-authorizer service
- a signed evidence envelope (`deny` decision for a synthetic casino-hotel scenario)
- a passing offline authenticity check
- a passing reproducibility replay

> **UNCERTIFIED.** All examples below use a synthetic demo rule pack -- not a fatwa,
> not certified, not production advice. Scenario labels are generic synthetic
> placeholders; there is no real merchant, customer, or PII anywhere.

## What you need

- **Node.js 22.6+** -- check with `node --version`
- **npm** -- bundled with Node.js
- **curl** (or any HTTP client)
- Git

## Step 1: Clone and install

```sh
git clone https://github.com/programmersn/compliance-authorizer.git
cd compliance-authorizer
npm ci
```

`npm ci` installs exact locked versions. Expected: no errors, a `node_modules/`
directory, a one-time key file created on first server boot.

## Step 2: Start the server

```sh
npm run dev
```

Expected output (one-line JSON log):

```json
{"level":"info","rule_pack":"shariah@0.1.1","rule_pack_hash":"<sha256>","issuer_kid":"<kid>","issuer_did":"did:key:<fingerprint>","msg":"compliance-authorizer up — synthetic demo rule pack (UNCERTIFIED)"}
```

The server listens on `http://127.0.0.1:8787`. The `issuer_kid` and `issuer_did` in
the log are your key's public identifiers -- you will see them inside the signed
envelope you get in the next step. The signing key is generated fresh on first boot
and stored under `.keys/issuer.jwk.json` (gitignored).

## Step 3: Submit a payment intent and get a decision

Open a second terminal. Submit a synthetic casino-hotel payment intent:

```sh
curl -s http://127.0.0.1:8787/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "shariah-v0.1",
    "merchant": { "name": "casino-hotel", "mcc": "7011", "attributes": ["casino", "gambling"] },
    "amount":   { "value": 420, "currency": "EUR" }
  }' | jq .
```

Expected response (HTTP 200 -- a `deny` is a **decision**, not an error):

```json
{
  "decision": "deny",
  "reason_codes": ["MAYSIR"],
  "rule_pack_status": "uncertified",
  "rule_pack_hash": "<sha256>",
  "evidence_artifact": "<jws-compact-string>"
}
```

The `evidence_artifact` field is a JWS-compact string -- three base64url segments
separated by `.`. It is the signed, tamper-evident record. The `rule_pack_status:
"uncertified"` field is the machine-readable UNCERTIFIED marker, readable without
decoding the JWS.

Try an `allow` decision by removing the gambling attributes:

```sh
curl -s http://127.0.0.1:8787/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "shariah-v0.1",
    "merchant": { "name": "seaside-hotel", "mcc": "7011", "attributes": [] },
    "amount":   { "value": 180, "currency": "EUR" }
  }' | jq .decision
```

Expected: `"allow"`. Same hotel category code, no gambling attributes -- the
evaluator rules do not match, so the default decision (`allow`) applies.

## Step 4: Verify and replay the committed example

The repository ships a committed, byte-reproducible evidence artifact you can verify
and replay without a running server:

```sh
npm run verify:fixture
```

Expected output (every check `PASS`):

```
[ PASS ] JWS structure
[ PASS ] Algorithm pinned (EdDSA)
[ PASS ] Key resolved (kid matches RFC 7638 thumbprint)
[ PASS ] Ed25519 signature
[ PASS ] Canonical form (RFC 8785 / JCS)
[ PASS ] Envelope schema (v0.1.0 exact shape)
[ PASS ] intent_hash
[ PASS ] rule_pack_hash
RESULT: PASS — decision "deny"  [issuer: did:key:<fingerprint>]
```

The verifier (`verifier/verify.mjs`) uses Node built-ins only -- no import from this
service's source, no network calls. It trusts nothing on the server.

```sh
npm run replay
```

Expected:

```
RESULT: REPRODUCED — re-evaluation yields decision "deny"  [exit 0]
Note: authenticity NOT checked (run with --jwks to add authenticity gate)
```

Replay re-runs the pure deterministic evaluator on the cited intent and pack; it does
not touch the signature. To require both properties in a single exit code:

```sh
npm run replay:verified
```

Expected: `RESULT: REPRODUCED AND AUTHENTIC — exit 0`.

## What you built

You have:

- a running compliance-authorization API that signs every decision with an Ed25519 key
- an offline verifier that checks authenticity with zero server trust
- a reproducibility tool that re-derives decisions from first principles

The two checks are **independent by design**: authenticity proves the bytes are
genuine; reproducibility proves the decision is correct. You need both to trust a
decision. A full explanation is in [`REPRODUCIBILITY.md`](../REPRODUCIBILITY.md).

## Next steps

- **Read the API** -- [`README.md`](../README.md#status) for the full endpoint list,
  including `POST /verify` (server-side verification) and
  `GET /.well-known/jwks.json` (public key publication for historical verification).
- **Understand the evaluator** -- [`docs/evaluator-semantics.md`](./evaluator-semantics.md)
  pins the exact rule evaluation contract (operators, field resolution, conflict
  resolution).
- **See the full zero-trust walkthrough** -- [`REPRODUCIBILITY.md`](../REPRODUCIBILITY.md)
  shows how a third party with no server access can verify a decision from scratch.
- **Contribute** -- [`CONTRIBUTING.md`](../CONTRIBUTING.md) covers the development
  setup, test suite, and code conventions.

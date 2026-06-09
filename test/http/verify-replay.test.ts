/**
 * POST /verify REPLAY contract — REPRODUCIBILITY is reported SEPARATELY from
 * authenticity (`valid`). W1 proves an envelope is authentic; replay re-runs the
 * pure evaluator on the cited intent + pack and confirms the SAME decision
 * comes back. The two properties can disagree, and this file pins that they are
 * surfaced as distinct fields:
 *
 *   - genuine deny artifact        → valid:true,  reproduced:true   (decision deny)
 *   - decision flipped + RE-SIGNED → valid:TRUE,  reproduced:FALSE  (crown jewel:
 *       authentic bytes, dishonest decision the engine does not re-derive)
 *   - evaluator_version re-signed  → reproduced:null (D12: cannot replay here)
 *     to an unsupported version
 *   - cited pack not served here   → rule_pack_resolved:false, reproduced:null
 *
 * Route-isolated: the route plugin is registered on a FRESH Fastify() instance
 * (NOT buildServer()), with production-matching AJV options, so this file never
 * imports a sibling route module.
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import { afterAll, describe, expect, it } from "vitest";
import { generateSigningKey } from "../../src/crypto/keys.ts";
import {
  buildEnvelope,
  signEnvelope,
} from "../../src/evidence/envelope.ts";
import { evaluate } from "../../src/rules/evaluator.ts";
import { loadRulePackFile, type LoadedRulePack } from "../../src/rules/loader.ts";
import { registerProblemHandling } from "../../src/http/problem.ts";
import { verifyRoute } from "../../src/routes/verify.ts";
import { fixedEnvelopeDeps } from "../fixtures/deps.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const loaded = loadRulePackFile(
  join(repoRoot, "rule-packs", "shariah", "0.1.0.json"),
);
const signingKey = generateSigningKey();

// The canonical deny scenario: a casino-hotel whose merchant attributes flag
// gambling → MAYSIR-ATTR matches → decision "deny" (a generic synthetic label).
const denyIntent = {
  profile: "shariah-v0.1",
  merchant: {
    name: "casino-hotel",
    mcc: "7011",
    country: "GB",
    attributes: ["casino", "gambling"],
  },
  amount: { value: 389.99, currency: "GBP" },
};

// A GENUINE, byte-reproducible deny envelope (fixed clock+uuid + fixed signer).
const genuineEnvelope = buildEnvelope(
  denyIntent,
  evaluate(denyIntent, loaded.pack),
  loaded,
  fixedEnvelopeDeps,
);
const genuineArtifact = signEnvelope(genuineEnvelope, signingKey);

// CROWN JEWEL: overwrite the decision to "allow" (and clear reason_codes/
// matched_rules to make it look like a clean allow) and RE-SIGN with the real
// key. The signature now covers these exact bytes → the artifact is AUTHENTIC
// (valid:true). But re-evaluating the cited intent still yields "deny", so it
// does NOT reproduce. Authentic yet not reproducible — the whole point of the
// replay leg over the verifier.
const tamperedThenResignedArtifact = signEnvelope(
  { ...genuineEnvelope, decision: "allow", reason_codes: [], matched_rules: [] },
  signingKey,
);

// An envelope pinning an evaluator semantics version this engine does not run.
// Re-signed so it is AUTHENTIC; D12 means it cannot be faithfully replayed here,
// so reproduced is null (unknown), never a false "mismatch".
const foreignEvaluatorArtifact = signEnvelope(
  { ...genuineEnvelope, evaluator_version: "0.9.9" },
  signingKey,
);

// COMBINED TAMPER (regression guard): the rule_pack_hash AND evaluator_version
// are BOTH falsified, then re-signed. The D12 mismatch alone must NOT excuse the
// hash mismatch: the route lifts authenticity from the pack-free pass only when
// D12 is the SOLE pack-bound failure (cited.hash === envelope.rule_pack_hash).
// Here the hash is wrong, so this stays INAUTHENTIC (valid:false) — a
// hash-mismatched envelope is never authentic evidence, however it is re-signed.
const combinedTamperArtifact = signEnvelope(
  { ...genuineEnvelope, evaluator_version: "0.9.9", rule_pack_hash: "deadbeef" },
  signingKey,
);

function buildApp(packsByIdVersion: ReadonlyMap<string, LoadedRulePack>) {
  const app = Fastify({
    ajv: {
      customOptions: {
        coerceTypes: false,
        removeAdditional: false,
        useDefaults: false,
      },
    },
  });
  registerProblemHandling(app);
  void app.register(verifyRoute, {
    publishedKeys: [signingKey.publicJwk],
    packsByIdVersion,
  });
  return app;
}

// Engine A: serves the cited pack (replay can run).
const app = buildApp(
  new Map([[`${loaded.pack.id}/${loaded.pack.version}`, loaded]]),
);
// Engine B: serves NO packs — the cited pack does not resolve here.
const appNoPacks = buildApp(new Map());

afterAll(async () => {
  await app.close();
  await appNoPacks.close();
});

function verify(
  instance: ReturnType<typeof buildApp>,
  evidence_artifact: unknown,
) {
  return instance.inject({
    method: "POST",
    url: "/verify",
    payload: { evidence_artifact } as Record<string, unknown>,
  });
}

describe("POST /verify replay: reproducibility is reported separately from authenticity", () => {
  it("genuine deny artifact → 200 valid:true AND reproducibility.reproduced === true (decision deny)", async () => {
    const response = await verify(app, genuineArtifact);

    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    expect(body["valid"]).toBe(true);
    expect(body["decision"]).toBe("deny");

    const r = body["reproducibility"] as Record<string, unknown>;
    expect(r).toBeDefined();
    expect(r["rule_pack_resolved"]).toBe(true);
    expect(r["evaluator_version_supported"]).toBe(true);
    expect(r["replayed"]).toBe(true);
    expect(r["reproduced"]).toBe(true);
    expect(r["decision"]).toBe("deny");
    expect(r["reason_codes"]).toEqual(["MAYSIR"]);
    // A reproduced verdict carries no mismatch description.
    expect(r["mismatch"]).toBeUndefined();
  });

  it("CROWN JEWEL: decision overwritten to allow then RE-SIGNED → valid:true (authentic) BUT reproduced === false", async () => {
    const response = await verify(app, tamperedThenResignedArtifact);

    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();

    // AUTHENTIC: the signature covers these exact bytes — every crypto check
    // passes, so the artifact is genuinely valid evidence...
    expect(body["valid"]).toBe(true);
    expect((body["checks"] as { ok: boolean }[]).every((c) => c.ok)).toBe(true);
    expect(body["decision"]).toBe("allow");

    // ...yet it does NOT REPRODUCE: re-running the evaluator on the cited intent
    // yields "deny", contradicting the envelope's "allow". This is the property
    // the offline verifier deliberately cannot catch.
    const r = body["reproducibility"] as Record<string, unknown>;
    expect(r["rule_pack_resolved"]).toBe(true);
    expect(r["evaluator_version_supported"]).toBe(true);
    expect(r["replayed"]).toBe(true);
    expect(r["reproduced"]).toBe(false);
    // The re-evaluation's own (honest) decision is surfaced alongside.
    expect(r["decision"]).toBe("deny");
    expect(r["reason_codes"]).toEqual(["MAYSIR"]);
    // The mismatch names WHICH claim the re-evaluation contradicts.
    expect(r["mismatch"]).toContain("decision");
    expect(r["mismatch"]).toContain("allow");
    expect(r["mismatch"]).toContain("deny");
  });

  it("evaluator_version re-signed to 0.9.9 → reproducibility.evaluator_version_supported === false, reproduced null (D12)", async () => {
    const response = await verify(app, foreignEvaluatorArtifact);

    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    // Still authentic (re-signed) — D12 is about REPLAY, not authenticity.
    expect(body["valid"]).toBe(true);

    const r = body["reproducibility"] as Record<string, unknown>;
    expect(r["rule_pack_resolved"]).toBe(true);
    expect(r["evaluator_version_supported"]).toBe(false);
    expect(r["replayed"]).toBe(false);
    // null, not false: replay could not be ATTEMPTED (unknown ≠ mismatch).
    expect(r["reproduced"]).toBeNull();
    expect(r["detail"]).toContain("0.9.9");
    expect(r["detail"]).toContain("D12");
  });

  it("rule_pack_hash AND evaluator_version both falsified then RE-SIGNED → valid:false (D12 must not excuse a hash mismatch)", async () => {
    const response = await verify(app, combinedTamperArtifact);

    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    // INAUTHENTIC: the with-pack pass fails at the rule_pack_hash sub-check. The
    // D12 fall-back must NOT fire, because the hash does not match the served
    // pack — declaring this authentic would be valid:true on tampered evidence.
    expect(body["valid"]).toBe(false);
    const checks = body["checks"] as { id: string; ok: boolean }[];
    expect(checks.find((c) => c.id === "pack-hash")?.ok).toBe(false);
    // No trustworthy intent stands behind an inauthentic artifact → no replay.
    expect(body["reproducibility"]).toBeUndefined();
    // UNCERTIFIED is unavoidable even on an inauthentic verdict.
    expect(body["uncertified"]).toBe(true);
  });

  it("cited pack not served by this engine → reproducibility.rule_pack_resolved === false, reproduced null", async () => {
    const response = await verify(appNoPacks, genuineArtifact);

    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    // Authenticity does not depend on the pack being served — the signature,
    // canonical form and intent_hash still verify, so valid stays true.
    expect(body["valid"]).toBe(true);

    const r = body["reproducibility"] as Record<string, unknown>;
    expect(r["rule_pack_resolved"]).toBe(false);
    expect(r["replayed"]).toBe(false);
    expect(r["reproduced"]).toBeNull();
    expect(r["detail"]).toContain("not served by this engine");
    expect(r["detail"]).toContain("shariah@0.1.0");
  });
});

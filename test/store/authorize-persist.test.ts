/**
 * POST /authorize persistence leg (ET14) — the store hook on the request path:
 *
 *   - a real DB-backed server persists one row per ISSUED decision, and the
 *     stored evidence_artifact is byte-identical to the response's;
 *   - error ≠ deny AT THE STORAGE BOUNDARY: an injected write failure → 500
 *     problem+json with NO envelope and NO decision in the body (a signed
 *     envelope must NEVER reach the caller alongside a storage error);
 *   - the store is OBSERVATIONAL: a server with NO store wired returns the exact
 *     same 200 decision shape (the existing stateless behavior is unchanged).
 */
import { dirname, join } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { generateSigningKey } from "../../src/crypto/keys.ts";
import { loadRulePackFile } from "../../src/rules/loader.ts";
import { buildServer } from "../../src/server.ts";
import { PROBLEM_CONTENT_TYPE } from "../../src/http/problem.ts";
import {
  openEvidenceStore,
  type EvidenceStore,
  type StoredDecision,
} from "../../src/store/evidence-store.ts";
import { fixedEnvelopeDeps } from "../fixtures/deps.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const loadedPack = loadRulePackFile(
  join(repoRoot, "rule-packs", "shariah", "0.1.1.json"),
);
const signingKey = generateSigningKey();

const denyIntent = {
  profile: "shariah-v0.1",
  merchant: { name: "casino-hotel", mcc: "7011", attributes: ["casino", "gambling"] },
  amount: { value: 420, currency: "EUR" },
};

const tempRoot = mkdtempSync(join(tmpdir(), "authorize-persist-"));
afterAll(() => rmSync(tempRoot, { recursive: true, force: true }));

describe("the persist hook stores exactly what was issued", () => {
  it("persists one row whose evidence_artifact matches the response BYTE-FOR-BYTE", async () => {
    const store = await openEvidenceStore(join(tempRoot, "issued.sqlite"));
    const app = buildServer({
      loadedPacks: [loadedPack],
      signingKey,
      store,
      // NOTE: fixed deps make decision_id/timestamp deterministic, which lets us
      // read the row back by a known id and assert the stored timestamp too.
      envelopeDeps: fixedEnvelopeDeps,
    });
    try {
      const response = await app.inject({
        method: "POST",
        url: "/authorize",
        payload: denyIntent,
      });
      expect(response.statusCode).toBe(200);
      const body = response.json<Record<string, unknown>>();
      expect(body["decision"]).toBe("deny");

      const stored = store.read(body["decision_id"] as string);
      expect(stored).toBeDefined();
      // The stored artifact is the SAME bytes the caller received — the store
      // never re-encodes or canonicalizes the JWS on the way in.
      expect(stored?.evidence_artifact).toBe(body["evidence_artifact"]);
      // And the indexed top-level fields round-trip identically.
      expect(stored?.decision).toBe("deny");
      expect(stored?.reason_codes).toEqual(["MAYSIR"]);
      expect(stored?.rule_pack_hash).toBe(body["rule_pack_hash"]);
      expect(stored?.evaluator_version).toBe(body["evaluator_version"]);
      expect(stored?.intent_hash).toBe(body["intent_hash"]);
      expect(stored?.envelope_version).toBe(body["envelope_version"]);
      expect(stored?.decision_timestamp).toBe(body["decision_timestamp"]);
    } finally {
      await app.close();
      store.close();
    }
  });
});

describe("error ≠ deny at the storage boundary (injected write failure)", () => {
  it("a store that throws on persist → 500 problem+json, NO envelope, NO decision", async () => {
    // An injected store whose write always fails — simulating a disk-full / locked
    // DB at exactly the moment AFTER signing. The decision was made and signed,
    // but if it cannot be persisted the request MUST fail closed: no signed
    // envelope may escape alongside the error.
    const failing: EvidenceStore = {
      persist() {
        throw new Error("synthetic store write failure");
      },
      read() {
        return undefined;
      },
      close() {
        /* no-op */
      },
    };
    const app = buildServer({
      loadedPacks: [loadedPack],
      signingKey,
      store: failing,
    });
    try {
      const response = await app.inject({
        method: "POST",
        url: "/authorize",
        payload: denyIntent,
      });

      expect(response.statusCode).toBe(500);
      expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);

      const body = response.json<Record<string, unknown>>();
      expect(body["status"]).toBe(500);
      expect(body["title"]).toBe("Internal error");
      expect(body["detail"]).toContain("no evidence envelope");
      // The load-bearing assertions: NOTHING signed escaped with the error.
      expect(body).not.toHaveProperty("evidence_artifact");
      expect(body).not.toHaveProperty("decision");
    } finally {
      await app.close();
    }
  });

  it("the failure path leaves the store empty — no partial write reached disk", async () => {
    // A DB-backed store wrapped so the FIRST persist throws AFTER nothing was
    // written (the wrapper rejects before delegating). Confirms the 500 path does
    // not half-persist: the underlying DB has zero rows for that id.
    const real = await openEvidenceStore(join(tempRoot, "failpath.sqlite"));
    const captured: string[] = [];
    const wrapped: EvidenceStore = {
      persist(decision: StoredDecision) {
        captured.push(decision.decision_id);
        throw new Error("synthetic failure before commit");
      },
      read: (id) => real.read(id),
      close: () => real.close(),
    };
    const app = buildServer({
      loadedPacks: [loadedPack],
      signingKey,
      store: wrapped,
    });
    try {
      const response = await app.inject({
        method: "POST",
        url: "/authorize",
        payload: denyIntent,
      });
      expect(response.statusCode).toBe(500);
      // The hook was reached (a decision_id was generated) but the real DB never
      // got the row.
      expect(captured).toHaveLength(1);
      expect(real.read(captured[0] as string)).toBeUndefined();
    } finally {
      await app.close();
      // Close the real DB handle so the temp file is unlinkable on Windows
      // (an open SQLite file cannot be removed there).
      real.close();
    }
  });
});

describe("the EvidenceStore port is synchronous — an async store fails closed", () => {
  it("a persist() that returns a promise → 500 problem+json, NO envelope (the boundary cannot await past the 200)", async () => {
    // The port is `persist(): void`, but TypeScript's void return type ALSO
    // accepts an async persist() (Promise<void> is assignable to void). Such a
    // store's write would settle AFTER /authorize has returned the signed 200,
    // so a later rejection would breach the fail-closed boundary unseen (the
    // synchronous try/catch cannot catch a rejected promise). The route must
    // detect the returned thenable and fail closed synchronously instead.
    const asyncStore: EvidenceStore = {
      // eslint-disable-next-line @typescript-eslint/no-misused-promises -- deliberately constructing the async misuse the route must reject
      async persist() {
        /* resolves AFTER the response would already be sent */
      },
      read() {
        return undefined;
      },
      close() {
        /* no-op */
      },
    };
    const app = buildServer({
      loadedPacks: [loadedPack],
      signingKey,
      store: asyncStore,
    });
    try {
      const response = await app.inject({
        method: "POST",
        url: "/authorize",
        payload: denyIntent,
      });

      expect(response.statusCode).toBe(500);
      expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);

      const body = response.json<Record<string, unknown>>();
      expect(body["status"]).toBe(500);
      expect(body["title"]).toBe("Internal error");
      expect(body["detail"]).toContain("not synchronous");
      // The load-bearing assertions: NOTHING signed escaped with the failure.
      expect(body).not.toHaveProperty("evidence_artifact");
      expect(body).not.toHaveProperty("decision");
    } finally {
      await app.close();
    }
  });
});

describe("the store is observational — disabled server is unchanged", () => {
  it("with NO store wired, a deny is the identical 200 decision shape", async () => {
    const app = buildServer({
      loadedPacks: [loadedPack],
      signingKey,
      envelopeDeps: fixedEnvelopeDeps,
    });
    try {
      const response = await app.inject({
        method: "POST",
        url: "/authorize",
        payload: denyIntent,
      });
      expect(response.statusCode).toBe(200);
      const body = response.json<Record<string, unknown>>();
      expect(body["decision"]).toBe("deny");
      expect(body["reason_codes"]).toEqual(["MAYSIR"]);
      expect(body).toHaveProperty("evidence_artifact");
    } finally {
      await app.close();
    }
  });
});

/**
 * W3-4 static web surface (T-D3 wiring): web/ is served same-origin by the
 * Fastify server so the playground hits the real POST /authorize.
 *
 *   - GET / serves web/index.html with the correct content type;
 *   - the page references ONLY files/routes that exist (no dead link ships);
 *   - a static miss still falls through to problem+json 404 (the API error
 *     contract is not weakened by web serving);
 *   - the locked honesty wording is present verbatim in the served page.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { generateSigningKey } from "../../src/crypto/keys.ts";
import { loadRulePackFile } from "../../src/rules/loader.ts";
import { buildServer } from "../../src/server.ts";
import { PROBLEM_CONTENT_TYPE } from "../../src/http/problem.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const webRoot = join(repoRoot, "web");
const loadedPack = loadRulePackFile(
  join(repoRoot, "rule-packs", "shariah", "0.1.1.json"),
);

const app = buildServer({
  loadedPacks: [loadedPack],
  signingKey: generateSigningKey(),
});

afterAll(() => app.close());

describe("GET / serves the single-scroll page", () => {
  it("returns web/index.html as text/html", async () => {
    const response = await app.inject({ method: "GET", url: "/" });
    expect(response.statusCode).toBe(200);
    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.body).toContain("<!DOCTYPE html>");
    // The locked IA (DR1): landing + playground + inline viewer on ONE page.
    expect(response.body).toContain('id="playground"');
    expect(response.body).toContain('id="evidence-region"');
    expect(response.body).toContain('id="dev"');
    // The async decision region is announced to assistive tech.
    expect(response.body).toContain('aria-live="polite"');
  });

  it("carries the honesty wording verbatim (DX11) and never 'board-readable'", async () => {
    const response = await app.inject({ method: "GET", url: "/" });
    expect(response.body).toContain("synthetic demo rule pack");
    expect(response.body).toContain(
      "not a fatwa / not certified / not production advice",
    );
    expect(response.body.toLowerCase()).toContain(
      "committee-reviewable demo evidence",
    );
    expect(response.body).not.toContain("board-readable");
    // Forward projection stays future-conditional (DR3): the locked copy is
    // present, and nothing claims a certified version exists today.
    expect(response.body).toContain("a certified v1.0 pack produces");
    expect(response.body).toContain("populate on certification");
    expect(response.body).not.toMatch(/certified version (does|currently|already)/i);
  });

  it("states BOTH halves of the HTTP contract in the dev door (DT1 + DX9)", async () => {
    const response = await app.inject({ method: "GET", url: "/" });
    // a decision is always 200 — a DENY is 200, read the body…
    expect(response.body).toContain("ALWAYS 200");
    expect(response.body).toContain("a DENY is 200");
    // …AND malformed input is 4xx problem+json, never a signed decision.
    expect(response.body).toContain("4xx problem+json");
    expect(response.body).toContain("never a signed decision");
  });

  it("serves the stylesheets and modules with correct content types", async () => {
    const css = await app.inject({ method: "GET", url: "/styles/tokens.css" });
    expect(css.statusCode).toBe(200);
    expect(css.headers["content-type"]).toContain("text/css");

    const js = await app.inject({ method: "GET", url: "/js/app.js" });
    expect(js.statusCode).toBe(200);
    expect(js.headers["content-type"]).toContain("javascript");
  });
});

describe("the page references only files and routes that exist", () => {
  const html = readFileSync(join(webRoot, "index.html"), "utf8");
  const refs = [...html.matchAll(/(?:href|src)="([^"]+)"/g)].map(
    (match) => match[1] ?? "",
  );

  it("found references to check", () => {
    expect(refs.length).toBeGreaterThan(5);
  });

  const local = refs.filter((ref) => !/^(?:https?:|#|mailto:|data:)/.test(ref));
  const relative = local.filter((ref) => !ref.startsWith("/"));
  const absolute = local.filter((ref) => ref.startsWith("/"));

  it.each(relative)("relative reference %s exists in web/", (ref) => {
    expect(existsSync(join(webRoot, ref))).toBe(true);
  });

  it.each(absolute)("absolute reference %s resolves on the server", async (ref) => {
    const response = await app.inject({ method: "GET", url: ref });
    expect(response.statusCode).toBe(200);
  });

  it("every intra-module import in web/js resolves to a real file", () => {
    const jsDir = join(webRoot, "js");
    for (const file of readdirSync(jsDir).filter((name) => name.endsWith(".js"))) {
      const source = readFileSync(join(jsDir, file), "utf8");
      for (const match of source.matchAll(/from\s+"(\.\/[^"]+)"/g)) {
        const target = match[1] ?? "";
        expect(existsSync(join(jsDir, target)), `${file} imports ${target}`).toBe(
          true,
        );
      }
    }
  });
});

describe("web serving does not weaken the API error contract", () => {
  it("a static miss is still problem+json 404 (never an HTML error page)", async () => {
    const response = await app.inject({ method: "GET", url: "/no-such-file.css" });
    expect(response.statusCode).toBe(404);
    expect(response.headers["content-type"]).toContain(PROBLEM_CONTENT_TYPE);
  });

  it("POST /authorize still decides — static routes never shadow the API", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/authorize",
      payload: {
        profile: "shariah-v0.1",
        merchant: { name: "casino-hotel", mcc: "7011", attributes: ["casino", "gambling"] },
        amount: { value: 420, currency: "EUR" },
      },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json<{ decision: string }>().decision).toBe("deny");
  });
});

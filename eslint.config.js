// ESLint flat config — type-checked linting on the TS sources; the standalone
// verifier (verifier/verify.mjs) is plain JS by design and linted without type info.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // Mirror the gitignored runtime/build dirs so `eslint .` never walks into
  // them. `data/` holds the runtime SQLite evidence store and any local scratch
  // harness scripts (gitignored); keeping it out of the lint surface means a
  // stray .mjs there can't produce spurious no-undef failures (DX guard).
  { ignores: ["dist/", "coverage/", "node_modules/", "data/"] },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ["**/*.mjs", "**/*.js"],
    ...tseslint.configs.disableTypeChecked,
  },
  {
    files: ["verifier/**/*.mjs"],
    languageOptions: {
      globals: {
        Buffer: "readonly",
        console: "readonly",
        process: "readonly",
      },
    },
  },
  {
    // W3-4 web surfaces: plain browser ES modules (no bundler, no build step).
    // Browser globals only — node globals stay OUT so a stray `process`/`Buffer`
    // in web code is still a lint error.
    files: ["web/**/*.js"],
    languageOptions: {
      globals: {
        document: "readonly",
        window: "readonly",
        fetch: "readonly",
        navigator: "readonly",
        crypto: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        URL: "readonly",
        Blob: "readonly",
        atob: "readonly",
        btoa: "readonly",
        TextEncoder: "readonly",
        TextDecoder: "readonly",
        AbortController: "readonly",
        console: "readonly",
      },
    },
  }
);

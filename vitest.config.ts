import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // The W1 fixture test spawns the offline verifier as a child process;
    // give CI runners headroom over the default 5s.
    testTimeout: 30_000,
  },
});

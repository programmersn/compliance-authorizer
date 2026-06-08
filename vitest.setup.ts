// Global fast-check configuration: a fixed seed makes every property-based run
// reproducible (a CI failure replays locally bit-for-bit), and verbose: 2 prints
// the full shrunk counterexample on failure instead of a bare assertion error.
import fc from "fast-check";

fc.configureGlobal({ seed: 0x5eed, verbose: 2 });

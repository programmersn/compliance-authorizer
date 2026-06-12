/**
 * Playground scenarios — SYNTHETIC DATA ONLY, generic labels (no real
 * institution or individual anywhere public; DESIGN.md §13).
 *
 * Each intent was confirmed BY EXECUTION against the shipped shariah-v0.1
 * pack (rule-packs/shariah/0.1.1.json, evaluator 0.2.0):
 *   - casino-hotel       → deny,   reason_codes ["MAYSIR"]        (MAYSIR-ATTR)
 *   - mixed-revenue ETF  → review, reason_codes ["MIXED_REVENUE"] (MIXED-REVENUE)
 *   - subscription       → allow,  reason_codes []                (pack default)
 * The decision itself always comes from the live POST /authorize response —
 * the page never hardcodes an outcome (deterministic engine, no LLM).
 */

export const SCENARIOS = [
  {
    id: "casino-hotel",
    label: "Agent books a casino-hotel",
    note: "A booking agent pays a hotel that runs a casino floor.",
    intent: {
      profile: "shariah-v0.1",
      merchant: {
        name: "casino-hotel",
        mcc: "7011",
        attributes: ["casino", "gambling"],
      },
      amount: { value: 420, currency: "EUR" },
    },
  },
  {
    id: "mixed-revenue-etf",
    label: "Agent rebalances a mixed-revenue ETF",
    note: "A portfolio agent buys units of an ETF whose screening reports 12% impermissible revenue.",
    intent: {
      profile: "shariah-v0.1",
      merchant: { name: "mixed-revenue-etf", mcc: "6211", attributes: [] },
      amount: { value: 1000, currency: "USD" },
      screening: { instrument: "etf", mixed_revenue_ratio: 0.12 },
    },
  },
  {
    id: "subscription",
    label: "Agent sets up a subscription",
    note: "A household agent starts a 12 EUR monthly media subscription.",
    intent: {
      profile: "shariah-v0.1",
      merchant: { name: "streaming-subscription", mcc: "4899", attributes: [] },
      amount: { value: 12, currency: "EUR" },
      recurring: true,
    },
  },
];

/**
 * One-line human summary of an intent — shown while a request is in flight so
 * the reader never loses sight of WHAT is being authorized (DESIGN.md §6).
 * @param {Record<string, any>} intent
 * @returns {string}
 */
export function intentSummary(intent) {
  const merchant = intent && typeof intent.merchant === "object" && intent.merchant !== null ? intent.merchant : {};
  const amount = intent && typeof intent.amount === "object" && intent.amount !== null ? intent.amount : {};
  const parts = [
    typeof merchant.name === "string" ? merchant.name : "(unnamed merchant)",
    typeof merchant.mcc === "string" ? `MCC ${merchant.mcc}` : null,
    typeof amount.value === "number" && typeof amount.currency === "string"
      ? `${String(amount.value)} ${amount.currency}`
      : null,
    intent && typeof intent.profile === "string" ? `profile ${intent.profile}` : null,
  ];
  return parts.filter((part) => part !== null).join(" · ");
}

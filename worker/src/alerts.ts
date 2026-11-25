// Alert rules (SPEC §0.1 agreed inventory). Each alert goes to the Discord webhook
// (DISCORD_WEBHOOK_URL) and, for the runtime rules, to the broker over the
// BROKER_ALERT service binding (relayToBroker), which pushes the owner's phone.
// A failed delivery NEVER blocks or fails the operation underneath (an alert is
// detection, not enforcement); a failed Discord post is retried once and an
// `alert.failed` row is written to the audit. The rules are fired from
// index/writer/gc/identity. This list is COMPLETE; no other rule lives (§0.1).

import { AuditRow } from "./audit.js";

export const ALERT = {
  A1: "A1", // denial spike (GRANT_DENIED/deny-row burst — the primary early warning of the policy-deny model)
  A2: "A2", // value-read burst (value.read/value.read.bulk row burst per principal)
  A3: "A3", // service-token rotation reminder (90 days; doctor + CF expires_at)
  A4: "A4", // escrow/replica backlog (§8.3)
  A7: "A7", // Worker version change (deploy-time; C1)
  A8: "A8", // misconfig / audit-down / GC anomaly (fail-closed path signal)
  A9: "A9", // policy change (§4.1 — every policy PUT)
  A10: "A10", // identity-endpoint shape drift (§3.2 step 2 / §3.4)
  A11: "A11", // alert-on-read: even a SINGLE read of a sentinel key matching the ALERT_ON_READ_KEYS glob raises an alarm (arch §2.3 Token A invariant)
} as const;
export type AlertRule = (typeof ALERT)[keyof typeof ALERT];

/**
 * The broker's alert entrypoint (`AlertLink`, wapps-platform) as the service
 * binding BROKER_ALERT exposes it: one RPC method. The gate sends a rule id and
 * its own name; the broker keeps the list of rules, writes the sentence and
 * sends the owner's phone a content-free push. It answers true when it took the
 * alert and false when it refused it; the gate does not read the answer.
 */
export interface BrokerAlertLink {
  alert(service: string, rule: string): Promise<boolean>;
}

/** The binding every alert path needs besides the webhook; absent on a host without a broker. */
export interface BrokerAlertEnv {
  BROKER_ALERT?: BrokerAlertLink;
}

export interface AlertEnv extends BrokerAlertEnv {
  DISCORD_WEBHOOK_URL?: string;
  AUDIT_LOG: DurableObjectNamespace;
}

/** The gate's own name, as the broker accepts it (a fixed constant, never request input). */
export const BROKER_SERVICE = "secrets-gate";

// The rules sent to the broker: the alert ids that fire at runtime. The broker
// keeps the same list and refuses any other. A3 (the doctor's token reminder)
// never fires in the Worker.
const BROKER_RULES: ReadonlySet<string> = new Set([ALERT.A1, ALERT.A2, ALERT.A4, ALERT.A7, ALERT.A8, ALERT.A9, ALERT.A10, ALERT.A11]);

/**
 * relayToBroker asks the broker to push the owner's phone about an alert. It is
 * an addition to the Discord post and never a replacement: it NEVER throws, a
 * missing binding sends nothing, and only the rule id leaves (no summary, no
 * detail: those stay in Discord).
 */
export async function relayToBroker(link: BrokerAlertLink | undefined, rule: string): Promise<void> {
  if (!link || !BROKER_RULES.has(rule)) return;
  try {
    await link.alert(BROKER_SERVICE, rule);
  } catch {
    // The broker is down or the binding is gone: the alert stays in Discord.
  }
}

/**
 * fireAlert posts an alert to Discord and the broker (best-effort). It NEVER
 * throws and never blocks the caller: delivery runs in the background via
 * waitUntil. A failed Discord post is retried once; if it still fails, an
 * `alert.failed` row is written to the audit (§6.10).
 */
export function fireAlert(ctx: ExecutionContext, env: AlertEnv, rule: AlertRule, summary: string, detail?: Record<string, unknown>): void {
  ctx.waitUntil(deliverAlert(env, rule, summary, detail));
}

/** deliverAlert is the awaitable delivery (the tests and waitUntil share it): Discord and the broker, side by side. */
export async function deliverAlert(env: AlertEnv, rule: AlertRule, summary: string, detail?: Record<string, unknown>): Promise<void> {
  await Promise.all([postToDiscord(env, rule, summary, detail), relayToBroker(env.BROKER_ALERT, rule)]);
}

async function postToDiscord(env: AlertEnv, rule: AlertRule, summary: string, detail?: Record<string, unknown>): Promise<void> {
  const url = (env.DISCORD_WEBHOOK_URL ?? "").trim();
  if (!url) return; // no webhook: a silent no-op (an alert is detection, not enforcement)
  const content = `[secrets-gate ${rule}] ${summary}`;
  const body = JSON.stringify({ content, embeds: detail ? [{ description: "```" + JSON.stringify(detail).slice(0, 1500) + "```" }] : undefined });
  let ok = await post(url, body);
  if (!ok) ok = await post(url, body); // one retry
  if (!ok) {
    // Delivery failed for good: write `alert.failed` to the audit (best-effort; the
    // audit append is a batch call so it does not block the caller).
    const row: AuditRow = { principal: "worker", principal_type: "worker", verb: "alert.failed", decision: "allow", intent: `${rule}:${summary}`.slice(0, 200) };
    try {
      await env.AUDIT_LOG.get(env.AUDIT_LOG.idFromName("__audit__")).fetch("https://audit/append-batch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ rows: [row] }),
      });
    } catch {
      // The audit is unreachable too: nothing left to do (an alert is detection).
    }
  }
}

async function post(url: string, body: string): Promise<boolean> {
  try {
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
    return res.ok;
  } catch {
    return false;
  }
}

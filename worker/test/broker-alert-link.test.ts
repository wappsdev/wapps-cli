// The broker alert link: when an alert fires, the gate also sends the rule id to
// the broker's `AlertLink` entrypoint over the BROKER_ALERT service binding, so
// the owner's phone hears about it. The link is an addition to the Discord post,
// never a replacement: it is fail-soft (it never blocks or fails the request or
// the Discord post) and a Worker without the binding sends nothing.
//
// Two layers. The rule logic (the fixed list, the two-argument payload, the
// fail-soft contract) runs against a fake binding. The wiring of every path that
// posts an alert (the Worker's fireAlert and the three Durable Objects that post
// on their own) runs against a real service binding: vitest.config.ts stands up
// a stub Worker named `wapps-broker` whose `AlertLink` entrypoint records its
// calls, and BROKER_STUB reads them back.

import { beforeAll, beforeEach, describe, it, expect } from "vitest";
import { env } from "cloudflare:test";
import { ALERT, BROKER_SERVICE, deliverAlert, type AlertRule, type BrokerAlertLink } from "../src/alerts.js";
import { AUDIT_DO_NAME } from "../src/audit.js";
import { SCHEDULER_DO_NAME } from "../src/scheduler-do.js";
import { callGate, discordCalls, ensureJwks, resetWorld, runInDoRetry } from "./helpers.js";

interface Relayed {
  service: string;
  rule: string;
}

// The rules the gate sends to the broker: the alert ids that fire at runtime.
// A3 (the doctor's token reminder) is not one of them.
const RELAYED_RULES: AlertRule[] = [ALERT.A1, ALERT.A2, ALERT.A4, ALERT.A7, ALERT.A8, ALERT.A9, ALERT.A10, ALERT.A11];

async function stubCalls(): Promise<Relayed[]> {
  return (await env.BROKER_STUB.fetch("http://stub/")).json() as Promise<Relayed[]>;
}

async function clearStub(): Promise<void> {
  await (await env.BROKER_STUB.fetch("http://stub/", { method: "DELETE" })).arrayBuffer();
}

/** Waits until the stub holds `count` calls (the Durable Objects alert after the call that raised it). */
async function stubReached(count: number): Promise<Relayed[]> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const calls = await stubCalls();
    if (calls.length >= count) return calls;
    await new Promise((r) => setTimeout(r, 20));
  }
  return stubCalls();
}

/** A fake binding that records each call's whole argument list. */
function fakeLink(): BrokerAlertLink & { calls: unknown[][] } {
  const calls: unknown[][] = [];
  return {
    calls,
    async alert(...args: unknown[]) {
      calls.push(args);
      return true;
    },
  } as BrokerAlertLink & { calls: unknown[][] };
}

beforeAll(async () => {
  await ensureJwks();
});
beforeEach(async () => {
  await resetWorld();
  await clearStub();
});

describe("the rule logic (fake binding)", () => {
  it("sends each of the gate's rule ids with the gate's own name and nothing else", async () => {
    for (const rule of RELAYED_RULES) {
      const link = fakeLink();
      await deliverAlert({ AUDIT_LOG: env.AUDIT_LOG, DISCORD_WEBHOOK_URL: "", BROKER_ALERT: link }, rule, "free text that must stay in Discord", { secret: "detail" });
      // Exactly two arguments: the service name and the rule. The summary and the detail never leave.
      expect(link.calls, rule).toEqual([[BROKER_SERVICE, rule]]);
    }
    expect(BROKER_SERVICE).toBe("secrets-gate");
  });

  it("sends nothing for a rule that is not on the list (A3)", async () => {
    const link = fakeLink();
    await deliverAlert({ AUDIT_LOG: env.AUDIT_LOG, DISCORD_WEBHOOK_URL: "", BROKER_ALERT: link }, ALERT.A3, "token rotation due");
    expect(link.calls).toEqual([]);
  });

  it("still posts to Discord exactly as before, and the link is sent too", async () => {
    const link = fakeLink();
    await deliverAlert({ AUDIT_LOG: env.AUDIT_LOG, DISCORD_WEBHOOK_URL: "https://discord.test/webhook/xyz", BROKER_ALERT: link }, ALERT.A9, "policy updated v1 -> v2", { by: "x" });
    expect(discordCalls.length).toBe(1);
    const posted = JSON.parse(discordCalls[0].body) as { content: string; embeds: { description: string }[] };
    expect(posted.content).toBe("[secrets-gate A9] policy updated v1 -> v2");
    expect(link.calls).toEqual([[BROKER_SERVICE, "A9"]]);
  });

  it("relays even when no Discord webhook is set", async () => {
    const link = fakeLink();
    await deliverAlert({ AUDIT_LOG: env.AUDIT_LOG, BROKER_ALERT: link }, ALERT.A8, "audit down");
    expect(discordCalls.length).toBe(0);
    expect(link.calls).toEqual([[BROKER_SERVICE, "A8"]]);
  });

  it("a missing binding sends nothing and the Discord post is unchanged", async () => {
    await deliverAlert({ AUDIT_LOG: env.AUDIT_LOG, DISCORD_WEBHOOK_URL: "https://discord.test/webhook/xyz" }, ALERT.A1, "denial spike");
    expect(discordCalls.length).toBe(1);
  });

  it("a binding that throws or rejects never fails the alert or the Discord post", async () => {
    const throwing = { alert: () => { throw new Error("binding is gone"); } } as unknown as BrokerAlertLink;
    const rejecting = { alert: () => Promise.reject(new Error("broker is down")) } as unknown as BrokerAlertLink;
    for (const link of [throwing, rejecting]) {
      discordCalls.length = 0;
      await expect(
        deliverAlert({ AUDIT_LOG: env.AUDIT_LOG, DISCORD_WEBHOOK_URL: "https://discord.test/webhook/xyz", BROKER_ALERT: link }, ALERT.A8, "x"),
      ).resolves.toBeUndefined();
      expect(discordCalls.length).toBe(1);
    }
  });

  it("a failed Discord post does not stop the link", async () => {
    const link = fakeLink();
    // The mock has no route for this host, so the post fails (twice) and the audit row is written.
    await deliverAlert({ AUDIT_LOG: env.AUDIT_LOG, DISCORD_WEBHOOK_URL: "https://discord-down.test/webhook", BROKER_ALERT: link }, ALERT.A8, "x");
    expect(link.calls).toEqual([[BROKER_SERVICE, "A8"]]);
  });
});

describe("every path that posts an alert also reaches the broker (real service binding)", () => {
  it("the Worker's fireAlert (A8, misconfiguration) sends the rule and the request keeps its answer", async () => {
    const res = await callGate("/v1/health", { method: "GET" }, { ADMIN_EMAILS: "" });
    expect(res.status).toBe(503);
    expect(discordCalls.some((c) => c.body.includes("[secrets-gate A8]"))).toBe(true);
    expect(await stubReached(1)).toEqual([{ service: "secrets-gate", rule: "A8" }]);
  });

  it("the Worker still answers when the binding is missing", async () => {
    const res = await callGate("/v1/health", { method: "GET" }, { ADMIN_EMAILS: "", BROKER_ALERT: undefined });
    expect(res.status).toBe(503);
    expect(discordCalls.some((c) => c.body.includes("[secrets-gate A8]"))).toBe(true);
    expect(await stubCalls()).toEqual([]);
  });

  it("the audit Durable Object's own alert (A8) sends the rule", async () => {
    const stub = env.AUDIT_LOG.get(env.AUDIT_LOG.idFromName(AUDIT_DO_NAME));
    await runInDoRetry(stub, (instance: unknown) =>
      (instance as { discordAlert: (rule: string, summary: string) => Promise<void> }).discordAlert(ALERT.A8, "audit chain broken: test"),
    );
    expect(await stubReached(1)).toEqual([{ service: "secrets-gate", rule: "A8" }]);
    expect(discordCalls.some((c) => c.body.includes("[secrets-gate A8] audit chain broken: test"))).toBe(true);
  });

  it("the writer Durable Object's escrow alert (A4) sends the rule", async () => {
    const stub = env.PROJECT_WRITER.get(env.PROJECT_WRITER.idFromName("vaulter"));
    await runInDoRetry(stub, (instance: unknown) =>
      (instance as { escrowAlert: (rule: string, summary: string) => Promise<void> }).escrowAlert(ALERT.A4, "escrow backlog: test"),
    );
    expect(await stubReached(1)).toEqual([{ service: "secrets-gate", rule: "A4" }]);
  });

  it("the scheduler Durable Object's alert sends the rule", async () => {
    const stub = env.SCHEDULER.get(env.SCHEDULER.idFromName(SCHEDULER_DO_NAME));
    await runInDoRetry(stub, (instance: unknown) =>
      (instance as { alertFn: (rule: string, summary: string) => void }).alertFn(ALERT.A8, "scheduled gc failed: test"),
    );
    expect(await stubReached(1)).toEqual([{ service: "secrets-gate", rule: "A8" }]);
  });
});

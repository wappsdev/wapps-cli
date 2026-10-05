// What the plugin's scrub would change in the orchestrator-authored text that OD10 replays to the
// cloud: the open work items' title and intent, and the open questions' question and proposal, of
// the four projects that migrate. Counts only; no text is printed.
// Run from a scratch copy of the plugin: bun od15_probe.ts <path-to-plugin-src>
import { Database } from "bun:sqlite";
import { homedir } from "node:os";
import { join } from "node:path";

const { scrubText } = await import(`${process.argv[2]}/security/transcript_scrub.ts`);
// ASSIGNMENT as the plugin writes it (transcript_scrub.ts:11), minus its line anchor: what "match
// anywhere on a line" would do to prose.
const UNANCHORED =
  /((?:export[ \t]+)?\b[A-Za-z0-9_.-]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Za-z0-9_.-]*[ \t]*[=:][ \t]*)(\S+)/i;
let items = 0;
let unanchored = 0;
const projects = ["navlun", "ecommerce", "kick-clip-analyzer", "real-estate-analysis"];
for (const project of projects) {
  const db = new Database(join(homedir(), ".agent-broker", "state", project, "broker.sqlite"), { readonly: true });
  const texts: string[] = [];
  for (const row of db.query("select title, intent from work_items where closed_at is null").all() as any[]) {
    texts.push(row.title, row.intent);
    for (const t of [row.title, row.intent]) {
      items++;
      if (UNANCHORED.test(t)) unanchored++;
    }
  }
  for (const row of db
    .query("select question, coalesce(proposal, '') as proposal from work_questions where answered_at is null and withdrawn_at is null")
    .all() as any[]) {
    texts.push(row.question, row.proposal);
  }
  const changed = texts.filter((t) => scrubText(t) !== t).length;
  const marks = texts.reduce((n, t) => n + (scrubText(t).match(/\[REDACTED\]/g)?.length ?? 0) - (t.match(/\[REDACTED\]/g)?.length ?? 0), 0);
  console.log(`${project}: texts=${texts.length} changed_by_scrub=${changed} redactions=${marks}`);
  db.close();
}
console.log(`unanchored ASSIGNMENT over the work-item texts: ${unanchored} of ${items} match`);

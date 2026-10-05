// Run from a scratch copy of the plugin: bun scrub_probe.ts <path-to-src>
const src = process.argv[2];
const { redact } = await import(`${src}/security/redaction.ts`);
const { scrubText, scrubForTranscript } = await import(`${src}/security/transcript_scrub.ts`);
const secret = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const opaque = "tok" + "aB3".repeat(20);
const sample = `ran env\n${secret}\nBearer abcdefghijklmnop12345\nsha ${"a1".repeat(20)}\ntoken ${opaque}\n`;
const lens = (s: string) => s.length;
console.log("redact(note), the only text-level protection a note has today, removes the assignment:", !String(redact(sample)).includes("wJalr"));
console.log("redact({output}) removes it:", !JSON.stringify(redact({ output: sample })).includes("wJalr"));
console.log("redact({apiKey}) removes it:", JSON.stringify(redact({ apiKey: "x" })));
const t = scrubText(sample);
console.log("scrubText removes assignment, bearer, opaque; keeps lowercase-hex sha:",
  !t.includes("wJalr"), !t.includes("abcdefghijklmnop12345"), !t.includes(opaque), t.includes("a1".repeat(20)));
for (const n of [500, 20_000, 200_000]) {
  const big = "x".repeat(n);
  console.log(`len ${n}: scrubText -> ${lens(scrubText(big))}, scrubForTranscript -> ${lens(String(scrubForTranscript(big)))}`);
}
// secret placed AFTER the truncation point of a 20,000-char output
const tail = "y".repeat(10_000) + "\n" + secret;
console.log("scrubForTranscript drops a secret past byte 8192 by truncating:", !String(scrubForTranscript(tail)).includes("wJalr"));
// timing of the scrub on the largest finish output
const big = ("line of ordinary output 1234\n").repeat(Math.ceil(200_000 / 29)).slice(0, 200_000);
const t0 = performance.now(); scrubText(big); console.log("scrubText 200,000 chars ms:", (performance.now() - t0).toFixed(1));
// A note is "Bash: <command>" (provider_types.ts:100), so the pattern anchored to a line start sees the prefix first.
for (const note of [
  'Bash: curl -H "Authorization: Bearer abcdefghijklmnop12345" https://example.test',
  "Bash: AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY ./deploy.sh",
  "Bash: export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123",
]) console.log("note leaks:", scrubText(note).includes("[REDACTED]") ? "no (scrubbed)" : "YES", "|", scrubText(note).slice(0, 80));

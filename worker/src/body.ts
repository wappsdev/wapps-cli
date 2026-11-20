// Bounded request-body reading (E-M4, security review 2026-11-19). Every route that
// takes a body reads it here, and only after the request is authorized: an
// unauthorized caller never makes the Worker buffer or parse its body. A body over
// the route's cap is 413 BODY_TOO_LARGE in the usual error shape.

import { HTTP, jsonError } from "./errors.js";

const KIB = 1024;
const MIB = 1024 * KIB;

/** BODY_CAP is the per-route body cap in bytes, sized from what each route carries. */
export const BODY_CAP = {
  // {keys:[…]}: key names of ≤128 chars. A current manifest is ≤1 MiB (MANIFEST_CAP)
  // and every entry holds its name, so no real read names more than 1 MiB of keys.
  read: 1 * MIB,
  // {values:{…}}: a whole store at once. A stored value is ≤64 KiB (BLOB_CAP) and JSON
  // escaping can grow it, so 8 MiB holds a large store's import with room to spare.
  import: 8 * MIB,
  // {value, note?, expires?, ifEpoch?}: one value (≤64 KiB stored) at the worst JSON
  // escape factor (6×, \u00XX) plus its card.
  set: 512 * KIB,
  // {note?, expires?, ifEpoch?}: a card (note ≤500 chars).
  meta: 16 * KIB,
  // {project, scope:{verbs, keys}, ttl_seconds}: exact key names.
  token: 64 * KIB,
  // Admin control bodies: {jti} and {seq, hash}.
  adminSmall: 64 * KIB,
  // A whole policy document (rules × globs ≤256 chars).
  policy: 1 * MIB,
} as const;

function tooLarge(cap: number): Response {
  return jsonError(HTTP.PAYLOAD_TOO_LARGE, "BODY_TOO_LARGE", `request body exceeds ${cap} bytes`, { limit: cap });
}

/**
 * readBodyBounded returns the body's bytes, or a 413 response when it is over `cap`.
 * A Content-Length over the cap is refused before a byte is read; a body without one
 * (or that lies) is read chunk by chunk and abandoned as soon as it passes the cap.
 */
export async function readBodyBounded(request: Request, cap: number): Promise<Uint8Array | Response> {
  const declared = request.headers.get("content-length");
  if (declared !== null && declared.trim() !== "") {
    const n = Number(declared);
    if (!Number.isFinite(n) || n < 0 || n > cap) return tooLarge(cap);
  }
  const body = request.body;
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) {
      await reader.cancel().catch(() => {});
      return tooLarge(cap);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

/**
 * readJsonBounded parses a bounded body as JSON: `{ json }` on success, a 413 when
 * over the cap, or a 400 BAD_REQUEST "body not JSON".
 */
export async function readJsonBounded(request: Request, cap: number): Promise<{ json: unknown } | Response> {
  const bytes = await readBodyBounded(request, cap);
  if (bytes instanceof Response) return bytes;
  try {
    return { json: JSON.parse(new TextDecoder().decode(bytes)) as unknown };
  } catch {
    return jsonError(HTTP.BAD_REQUEST, "BAD_REQUEST", "body not JSON");
  }
}

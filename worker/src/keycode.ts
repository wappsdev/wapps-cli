// Key codes (owner decision 2026-11-12). Every key gets a short code when it is
// first created, and the key's name at its issuer is `wapps-<CODE> <store id> <KEY>`
// (`wapps-<CODE>:<store id>:<KEY>` where the issuer refuses spaces), so a token
// seen in an issuer's console leads back to its key by the code alone.
//
// The code: 6 characters of Crockford base32 (0-9 A-Z without I L O U), drawn
// from the crypto RNG. It lives on the key's manifest entry (manifest.ts), next to
// the card, and the writer carries it across value rotations.
//
// Uniqueness across the whole gate (every project and shared id): one R2 object
// per code, `key-codes/<CODE>`, written create-only (onlyIf etagDoesNotMatch "*"),
// so of two writers that draw the same code exactly one gets it. The object is
// never deleted or rewritten: after the key is deleted it stays as a tombstone, so
// a code is never given out twice. It sits outside `secrets/`, so a project purge
// leaves it. It records where the code was first given; the manifest entry is the
// truth (a lookup checks that the entry still carries the code). A reservation
// whose commit then failed leaves an index object no entry carries: harmless, the
// code is simply never used.

export const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export const CODE_LEN = 6;
const CODE_RE = /^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{6}$/;
const SCHEMA_KEY_CODE = "wapps-secrets/key-code/v1";
// 32^6 codes: a draw collides only when the gate holds a large share of them.
// Eight taken codes in a row means something is wrong, not bad luck.
const MAX_DRAWS = 8;

/** randomCode draws one code. 256 is a multiple of 32, so `byte & 31` is uniform. */
export function randomCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(CODE_LEN));
  let out = "";
  for (const b of bytes) out += CODE_ALPHABET[b & 31];
  return out;
}

/** validCode: a code as the gate writes it (upper case). */
export function validCode(s: string): boolean {
  return CODE_RE.test(s);
}

/** normalizeCode reads a code in any letter case; null when it is not one. */
export function normalizeCode(s: string): string | null {
  const up = s.toUpperCase();
  return validCode(up) ? up : null;
}

export function keyCodeIndex(code: string): string {
  return `key-codes/${code}`;
}

/** CodeHolder is what the index object records: the store and key the code was given to. */
export interface CodeHolder {
  store: string;
  key: string;
}

/**
 * reserveCode takes a fresh code for (store, key) in the index and returns it.
 * A code that is already taken (by a live key, a deleted one or a failed commit)
 * is skipped. It throws KEY_CODE_UNAVAILABLE after MAX_DRAWS taken codes in a row.
 */
export async function reserveCode(bucket: R2Bucket, store: string, key: string, draw: () => string = randomCode): Promise<string> {
  for (let i = 0; i < MAX_DRAWS; i++) {
    const code = draw();
    const body = JSON.stringify({ schema: SCHEMA_KEY_CODE, code, store, key, createdAt: new Date().toISOString() });
    const put = await bucket.put(keyCodeIndex(code), body, { onlyIf: { etagDoesNotMatch: "*" } });
    if (put !== null) return code;
  }
  throw new Error(`KEY_CODE_UNAVAILABLE: ${MAX_DRAWS} draws were all taken`);
}

/** readCodeHolder returns the store and key a code was given to; null when the
 * code was never given or its index object is unreadable. */
export async function readCodeHolder(bucket: R2Bucket, code: string): Promise<CodeHolder | null> {
  const o = await bucket.get(keyCodeIndex(code));
  if (!o) return null;
  try {
    const doc = JSON.parse(await o.text()) as Record<string, unknown>;
    if (doc.schema !== SCHEMA_KEY_CODE || doc.code !== code || typeof doc.store !== "string" || typeof doc.key !== "string") return null;
    return { store: doc.store, key: doc.key };
  } catch {
    return null;
  }
}

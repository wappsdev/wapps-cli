// Key information card (design 2026-11-11): non-secret metadata next to a key's
// value, stored on the key's manifest entry. `note` says why the key exists, its
// role and where it is renewed; `expires` is the issuer's expiry date. The value,
// its version and its wrap never depend on the card.

export const NOTE_MAX = 500;
// Printable text: no control (Cc), format (Cf: bidi overrides, zero-width),
// surrogate, private-use or unassigned code point, and no line/paragraph separator.
const NOTE_RE = /^[^\p{C}\p{Zl}\p{Zp}]+$/u;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Card is the card part of a manifest entry. */
export interface Card {
  note?: string;
  expires?: string;
}

/** CardPatch changes a card: a field that is absent keeps, null clears, a value sets. */
export interface CardPatch {
  note?: string | null;
  expires?: string | null;
}

/** validNote: 1 to NOTE_MAX characters (code points) of printable text. */
export function validNote(s: string): boolean {
  return NOTE_RE.test(s) && [...s].length <= NOTE_MAX;
}

/** validExpires: a real calendar date written YYYY-MM-DD. */
export function validExpires(s: string): boolean {
  if (!DATE_RE.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

/** readCardPatch takes `note` and `expires` from a request body. It returns the
 * patch (empty when neither field is present) or the field that is invalid. */
export function readCardPatch(body: Record<string, unknown>): { patch: CardPatch } | { field: "note" | "expires"; message: string } {
  const patch: CardPatch = {};
  if ("note" in body) {
    const n = body.note;
    if (n !== null && (typeof n !== "string" || !validNote(n))) {
      return { field: "note", message: `note must be 1-${NOTE_MAX} printable characters, or null to clear it` };
    }
    patch.note = n;
  }
  if ("expires" in body) {
    const e = body.expires;
    if (e !== null && (typeof e !== "string" || !validExpires(e))) {
      return { field: "expires", message: "expires must be a date YYYY-MM-DD, or null to clear it" };
    }
    patch.expires = e;
  }
  return { patch };
}

/** isEmptyPatch: the patch changes nothing. */
export function isEmptyPatch(p: CardPatch): boolean {
  return p.note === undefined && p.expires === undefined;
}

/** applyCard returns the card after the patch: absent keeps, null clears. */
export function applyCard(prev: Card | undefined, patch: CardPatch | undefined): Card {
  const pick = (old: string | undefined, next: string | null | undefined): string | undefined =>
    next === undefined ? old : next === null ? undefined : next;
  return { note: pick(prev?.note, patch?.note), expires: pick(prev?.expires, patch?.expires) };
}

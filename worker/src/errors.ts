// Makine-okunur hata sözleşmesi (SPEC §6 error contract). Tüm hatalar JSON:
// {"error":"<CODE>","message":"<text>", ...detail}.

export interface ErrorDetail {
  [k: string]: unknown;
}

/** jsonError, tipli bir hata yanıtı üretir. */
export function jsonError(status: number, code: string, message: string, detail?: ErrorDetail): Response {
  return new Response(JSON.stringify({ error: code, message, ...(detail ?? {}) }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** jsonOK, JSON body ile 200 (opsiyonel ek header). */
export function jsonOK(body: unknown, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json", ...(extraHeaders ?? {}) },
  });
}

// HTTP durum eşlemeleri (§5.7 / §6 route table).
export const HTTP = {
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NOT_MODIFIED: 304,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  PRECONDITION_FAILED: 412,
  PAYLOAD_TOO_LARGE: 413,
  UNPROCESSABLE: 422,
  TOO_MANY: 429,
  MISCONFIGURED: 503,
} as const;

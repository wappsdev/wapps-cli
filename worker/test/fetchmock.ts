// fetchmock.ts — dış (outbound) fetch mock'u.
//
// NEDEN VAR: `cloudflare:test` bir zamanlar undici'nin MockAgent'ını `fetchMock`
// olarak dışa veriyordu; vitest-pool-workers 0.14+ o export'u KALDIRDI. Bu suite'in
// tüm dış bağımlılıkları (CF Access JWKS + get-identity, Discord webhook, B2 S3)
// onun üstüne kuruluydu, yani upgrade'in bedeli buydu.
//
// Shim, KULLANILAN undici yüzeyini birebir taşır (activate / disableNetConnect /
// get(origin).intercept({path,method}).reply(...).persist()) — böylece onlarca
// intercept bildirimi olduğu gibi kaldı ve upgrade testlerin ANLAMINI değiştirmedi.
//
// GÜVENLİ OLMASININ SEBEBİ: testler global `fetch`i kendileri kullanmıyor.
// `callGate` doğrudan `worker.fetch(...)` çağırır ve `identity.ts` enjekte
// edilebilir bir fetcher alır (üretimde global fetch). Dolayısıyla globali
// değiştirmek yalnızca ÜRETİM kodunun dışa çıkan çağrılarını yakalar.

type HeaderBag = Record<string, string>;

/** ReplyOpts, reply(fn) geri çağrısına verilen istek görünümü (undici paritesi). */
export interface ReplyOpts {
  path: string;
  method: string;
  headers: HeaderBag;
  body: string;
}

interface ReplyResult {
  statusCode: number;
  data: unknown;
}

type ReplyFn = (opts: ReplyOpts) => ReplyResult;

interface Interceptor {
  origin: string;
  path: string | ((p: string) => boolean);
  method: string;
  reply: ReplyFn;
  remaining: number; // Infinity = persist()
}

const interceptors: Interceptor[] = [];
let installed = false;
let netConnectDisabled = false;

/** toResponse, undici reply şeklini bir Response'a çevirir. */
function toResponse(r: ReplyResult): Response {
  const data = r.data;
  // 204/205/304 null-body statülerdir: sıfır uzunlukta bir gövde vermek workerd'de
  // "technically incorrect" uyarısı bastırıyordu (Discord webhook'u 204 döner).
  const nullBody = r.statusCode === 204 || r.statusCode === 205 || r.statusCode === 304;
  if (nullBody) {
    return new Response(null, { status: r.statusCode });
  }
  if (typeof data === "string") {
    return new Response(data, { status: r.statusCode });
  }
  return new Response(JSON.stringify(data), {
    status: r.statusCode,
    headers: { "content-type": "application/json" },
  });
}

function matches(i: Interceptor, origin: string, path: string, method: string): boolean {
  if (i.origin !== origin) return false;
  if (i.method.toUpperCase() !== method.toUpperCase()) return false;
  return typeof i.path === "function" ? i.path(path) : i.path === path;
}

/** install, globalThis.fetch'i kayıt defterine danışan bir handler'la değiştirir. */
function install(): void {
  if (installed) return;
  installed = true;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const req = input instanceof Request ? input : new Request(input as string, init);
    const url = new URL(req.url);
    const origin = `${url.protocol}//${url.host}`;
    const path = url.pathname + url.search;
    const method = req.method || "GET";

    const hit = interceptors.find((i) => i.remaining > 0 && matches(i, origin, path, method));
    if (!hit) {
      if (netConnectDisabled) {
        // undici'nin disableNetConnect davranışı: eşleşmeyen istek HATA verir.
        // Sessizce ağa çıkmak, testin farkında olmadığı bir dış bağımlılık demek.
        throw new Error(`fetchmock: no interceptor for ${method} ${req.url}`);
      }
      throw new Error(`fetchmock: not activated but fetch called for ${req.url}`);
    }
    hit.remaining -= 1;

    const headers: HeaderBag = {};
    req.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    // Gövde YALNIZCA metin olduğunda okunur. B2'ye giden PUT'lar
    // application/octet-stream taşıyor; onları .text() ile okumak workerd'de
    // "body does not appear to be text" uyarısı üretiyordu — ve hiçbir
    // interceptor o gövdeye bakmıyor (yalnızca path/headers'a bakıyorlar).
    let body = "";
    const ctype = req.headers.get("content-type") ?? "";
    const textish = ctype === "" || ctype.startsWith("text/") || ctype.includes("json") || ctype.includes("urlencoded");
    if (method !== "GET" && method !== "HEAD" && textish) {
      try {
        body = await req.clone().text();
      } catch {
        body = "";
      }
    }
    return toResponse(hit.reply({ path, method, headers, body }));
  }) as typeof fetch;
}

class InterceptorHandle {
  constructor(private readonly i: Interceptor) {}

  /** reply, ya (status, body) ya da opts→{statusCode,data} fonksiyonu alır. */
  reply(statusOrFn: number | ReplyFn, data?: unknown): InterceptorHandle {
    this.i.reply =
      typeof statusOrFn === "function" ? statusOrFn : () => ({ statusCode: statusOrFn, data: data ?? "" });
    return this;
  }

  /** persist, interceptor'ı sınırsız kez eşleştirir (undici paritesi). */
  persist(): InterceptorHandle {
    this.i.remaining = Number.POSITIVE_INFINITY;
    return this;
  }

  /** times, interceptor'ın kaç kez eşleşeceğini belirler. */
  times(n: number): InterceptorHandle {
    this.i.remaining = n;
    return this;
  }
}

class OriginPool {
  constructor(private readonly origin: string) {}

  intercept(opts: { path: string | ((p: string) => boolean); method?: string }): InterceptorHandle {
    const i: Interceptor = {
      origin: this.origin,
      path: opts.path,
      method: opts.method ?? "GET",
      reply: () => ({ statusCode: 200, data: "" }),
      remaining: 1,
    };
    interceptors.push(i);
    return new InterceptorHandle(i);
  }
}

export const fetchMock = {
  /** activate, global fetch'i devralır. */
  activate(): void {
    install();
  },
  /** disableNetConnect, eşleşmeyen isteği hataya çevirir (sessiz ağ çıkışı yok). */
  disableNetConnect(): void {
    netConnectDisabled = true;
    install();
  },
  /** get, bir origin için interceptor havuzu döner. */
  get(origin: string): OriginPool {
    return new OriginPool(origin);
  },
  /** reset, kayıtlı tüm interceptor'ları siler (test izolasyonu). */
  reset(): void {
    interceptors.length = 0;
  },
};

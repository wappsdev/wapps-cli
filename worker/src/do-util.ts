// DO-to-DO fetch dayanıklılığı. workerd bir Durable Object'i (deploy, eviction veya
// isolate/modül yeniden-yükleme) geçici olarak invalidate edip çağırandan fetch'i
// YENİDEN DENEMESİNİ isteyebilir ("... invalidating this Durable Object. Please retry
// ..."): bu geçici bir durumdur, kalıcı hata DEĞİL. worker→DO çağrılarını, stub'ı
// YENİDEN oluşturarak + kısa backoff ile sınırlı retry ile sarmalıyoruz. GENUINE
// hatalar (audit down vb.) regex'e uymaz → hemen propagate eder (fail-closed korunur).
// Prod'da bu retry yolu ~hiç tetiklenmez (modül reload = test-runtime olayı).

const TRANSIENT_RE = /invalidating|broken|please retry/i;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * doStubFetch, bir DO stub.fetch'ini geçici invalidation'da sınırlı retry ile çağırır.
 * makeStub her denemede TAZE stub üretir (invalidate olmuş stub referansını atlar).
 */
export async function doStubFetch(makeStub: () => DurableObjectStub, input: string, init?: RequestInit, retries = 8): Promise<Response> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await makeStub().fetch(input, init);
    } catch (e) {
      lastErr = e;
      if (!TRANSIENT_RE.test(String(e))) throw e;
      await sleep(5 * (attempt + 1));
    }
  }
  throw lastErr;
}

export { TRANSIENT_RE };

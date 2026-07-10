// cloudflare:test ortam tipini Worker Env'i ile genişletir (SECRETS_BUCKET,
// PROJECT_WRITER, ACCESS_* / GENESIS_TRUST_SHA256) — testlerde env binding'leri
// tiplensin diye.
import type { Env } from "../src/auth.js";

declare module "cloudflare:test" {
  interface ProvidedEnv extends Env {}
}

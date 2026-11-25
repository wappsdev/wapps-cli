// Worker Env'ini test ortamına tanıtır. vitest-pool-workers 0.14+ `cloudflare:test`
// içindeki `ProvidedEnv` interface'ini BIRAKTI: `env` artık `Cloudflare.Env`
// tipindedir, yani augment edilecek yer global Cloudflare namespace'i.
import type { Env as WorkerEnv } from "../src/auth.js";

declare global {
  namespace Cloudflare {
    // BROKER_STUB reads back what the stub broker Worker's AlertLink recorded
    // (vitest.config.ts, test/broker-alert-link.test.ts).
    interface Env extends WorkerEnv {
      BROKER_STUB: Fetcher;
    }
  }
}

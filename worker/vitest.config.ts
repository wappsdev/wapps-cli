import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

// Yerel workerd (miniflare) test havuzu — canlı hesap GEREKMEZ. R2 + DO + KV
// binding'leri wrangler.jsonc'tan miras alınır (writer-DO CAS yarışı gerçek
// miniflare R2'sine karşı sürülür — build gate 4).
//
// v4 API NOTU: eski `defineWorkersConfig({test:{poolOptions:{workers:{...}}}})`
// biçimi kaldırıldı; havuz artık bir Vite PLUGIN'idir (`cloudflareTest`).
// Onunla birlikte iki v3 seçeneği de düştü — karşılıkları aşağıda vitest'in
// kendi ayarlarıyla kuruldu, çünkü ORİJİNAL GEREKÇELERİ hâlâ geçerli:
//
//   isolatedStorage: false → v4'te böyle bir seçenek yok. Zaten kapalıydı:
//     concurrent DO isteklerinde (CAS yarışı) per-test SQLite izolasyon
//     stack-pop'u .sqlite-shm ile bozuluyordu. Durum her testte elle
//     temizleniyor (helpers.resetWorld), o yüzden kaybı yok.
//
//   singleWorker: true → `fileParallelism: false` + `isolate: false`.
//     Test dosyalarının TEK isolate'te SIRAYLA koşması bir tercih değil,
//     gereklilik: JWKS signer bir singleton ve outbound fetch mock'u
//     (test/fetchmock.ts) modül-kapsamlı durum tutuyor. Dosyalar ayrı
//     isolate'lere dağılırsa ikisi de sessizce boşa düşer.
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          // helpers.ts TEAM_DOMAIN / AUD_READ / AUD_WRITE ile BİREBİR eşleşmeli.
          ACCESS_TEAM_DOMAIN: "test-team.cloudflareaccess.com",
          ACCESS_AUD_READ: "aud-read-000000000000000000000000000000000000",
          ACCESS_AUD_WRITE: "aud-write-00000000000000000000000000000000000",
          // §4.5 kök admin çapası (test fixture'ı).
          ADMIN_EMAILS: "admin@wapps.dev",
          // §2.2 MASTER_KEK: test için sabit 32-bayt (hex64). PREV boş (rotasyon
          // testleri callGate env-override ile geçici PREV enjekte eder).
          MASTER_KEK: "2222222222222222222222222222222222222222222222222222222222222222",
          MASTER_KEK_PREV: "",
          // Sabit ES256 mint anahtarları (§5.3 opsiyonel katman). kid'ler
          // helpers.MINT_KID / MINT_KID_PREV ile eşleşir.
          MINT_KEY:
            '{"kty":"EC","crv":"P-256","d":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","x":"OtOGGpViE5JRa7WT7wVYPtLlhm9ctiYKMBcjf9ibkK8","y":"0JYcfjcHWmeRo5xh9WKVsCttJlZ7YV5gqkHuHI6DOI0","kid":"mint-test-1"}',
          MINT_KEY_PREV:
            '{"kty":"EC","crv":"P-256","d":"Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M","x":"FSz1EqAD2T4rf34udOXYGlaf3NhxxhTeSe50DldUmCU","y":"iefburilLYLpEPdIAg2a6MfR7-FCXuEg8TQvBchtZP8","kid":"mint-test-0"}',
          // Alert webhook'u (test/fetchmock.ts ile intercept edilir — helpers.discordCalls).
          DISCORD_WEBHOOK_URL: "https://discord.test/webhook/xyz",
        },
      },
    }),
  ],
  test: {
    fileParallelism: false,
    isolate: false,
  },
});

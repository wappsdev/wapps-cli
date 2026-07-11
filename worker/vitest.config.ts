import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

// Yerel workerd (miniflare) test havuzu — canlı hesap GEREKMEZ. R2 + DO
// binding'leri wrangler.jsonc'tan miras alınır (SPEC §6 build gate 6: iki-yazar
// CAS yarışı gerçek R2'ye karşı).
export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        // isolatedStorage KAPALI: concurrent DO isteklerinde (CAS yarışı) pool'un
        // per-test SQLite izolasyon stack-pop'u .sqlite-shm ile bozuluyor (known
        // issue). Bunun yerine her testte R2 elle temizlenir (helpers.clearBucket).
        isolatedStorage: false,
        // singleWorker: tüm test dosyaları TEK isolate'te sıralı çalışır → paralel
        // isolate'ler arası paylaşımlı-storage yarışı yok; JWKS signer singleton
        // ve fetchMock tüm dosyalarda tutarlı.
        singleWorker: true,
        // Testler için config'i override ederek AUD/team-domain/genesis pin'i
        // doldururuz (fail-closed config guard'ını testte geçebilmek için).
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: {
            // helpers.ts TEAM_DOMAIN / AUD_READ / AUD_WRITE ile BİREBİR eşleşmeli.
            ACCESS_TEAM_DOMAIN: "test-team.cloudflareaccess.com",
            ACCESS_AUD_READ: "aud-read-000000000000000000000000000000000000",
            ACCESS_AUD_WRITE: "aud-write-00000000000000000000000000000000000",
            // Genesis pin testte helper'ın ürettiği trust payload hash'iyle
            // ezilir (per-test override); boş bırakmıyoruz ki config guard geçsin.
            GENESIS_TRUST_SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
            // Sabit ES256 mint anahtarları (§6.4). MINT_KEY imzalar; MINT_KEY_PREV
            // dual-key rotation penceresinde yalnızca DOĞRULAR. Testte kid'ler
            // helpers.MINT_KID / MINT_KID_PREV ile eşleşir.
            MINT_KEY: '{"kty":"EC","crv":"P-256","d":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","x":"OtOGGpViE5JRa7WT7wVYPtLlhm9ctiYKMBcjf9ibkK8","y":"0JYcfjcHWmeRo5xh9WKVsCttJlZ7YV5gqkHuHI6DOI0","kid":"mint-test-1"}',
            MINT_KEY_PREV: '{"kty":"EC","crv":"P-256","d":"Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M","x":"FSz1EqAD2T4rf34udOXYGlaf3NhxxhTeSe50DldUmCU","y":"iefburilLYLpEPdIAg2a6MfR7-FCXuEg8TQvBchtZP8","kid":"mint-test-0"}',
            // Alert webhook'u (§6.10). fetchMock ile intercept edilir (helpers.discordCalls).
            DISCORD_WEBHOOK_URL: "https://discord.test/webhook/xyz",
          },
        },
      },
    },
  },
});

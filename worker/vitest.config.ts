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
            // helpers.ts TEAM_DOMAIN / AUD_READ ile BİREBİR eşleşmeli.
            ACCESS_TEAM_DOMAIN: "test-team.cloudflareaccess.com",
            ACCESS_AUD_READ: "aud-read-000000000000000000000000000000000000",
            ACCESS_AUD_WRITE: "aud-write-00000000000000000000000000000000000",
            // Genesis pin testte helper'ın ürettiği trust payload hash'iyle
            // ezilir (per-test override); boş bırakmıyoruz ki config guard geçsin.
            GENESIS_TRUST_SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
          },
        },
      },
    },
  },
});

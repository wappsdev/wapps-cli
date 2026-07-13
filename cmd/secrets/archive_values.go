package secrets

// archive_values.go — non-secrets komutların (bugün tek tüketici: `wapps deploy`)
// credential çözümleme yardımcısı. P1.7 re-point: age-arşiv okuyucusu
// (ArchiveValues) KALDIRILDI; kaynak artık server-decrypt store'dur
// (backend:store .wapps.yaml → Worker read). Çağıran env-first çözümlemesini
// korur — store yalnızca env'de bulunmayan anahtarlar için fallback'tir.

import (
	"context"
)

// StoreValues, config-çözümlü .wapps.yaml (--config/--project onurlandırılır)
// `backend: store` ise istenen anahtarların DEĞERLERİNİ store'dan çeker.
// Var olmayan anahtarlar sonuç haritasında sessizce yoktur.
//
// Erişilebilirlik best-effort'tur (ArchiveValues sözleşmesinin store karşılığı):
// .wapps.yaml yoksa veya backend store değilse (nil, nil) döner — çağıran (örn.
// `wapps deploy`) hatasız env değişkenlerine düşebilir. GERÇEK bir okuma
// hatası (oturum yok/dolmuş, ağ, grant reddi) hata olarak DÖNER.
//
// Bulk read all-or-nothing olduğundan (§7.6) önce ad düzlemi (Keys — değersiz,
// audit'e value.read düşmez) ile kesişim alınır: var olmayan aday anahtarlar
// NOT_FOUND üretmez, yalnızca mevcut olanlar okunur (blast-radius minimum).
//
// AI-safe: değerleri yalnızca çağırana döner; asla yazdırmaz.
func StoreValues(keys ...string) (map[string]string, error) {
	cfg, err := storeBackendConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil // store yapılandırılmamış → çağıran env'e düşer
	}
	st, err := openStore(cfg)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	kr, err := st.Keys(ctx, cfg.Project)
	if err != nil {
		return nil, err
	}
	present := make(map[string]bool, len(kr.Keys))
	for _, k := range kr.Keys {
		present[k.KeyName] = true
	}
	want := make([]string, 0, len(keys))
	for _, k := range keys {
		if present[k] {
			want = append(want, k)
			present[k] = false // dedupe: aynı aday iki kez istenmesin
		}
	}
	if len(want) == 0 {
		return map[string]string{}, nil
	}
	res, err := st.Read(ctx, cfg.Project, want)
	if err != nil {
		return nil, err
	}
	return res.Values, nil
}

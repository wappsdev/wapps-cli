package lifecycle

// TokenRevoker, offboard step 1 kill-switch'in kimlik-doğrulama (auth) tarafıdır
// (SPEC §8.5.2): CF Access app üyeliğinin kaldırılması, servis token'larının iptali,
// mint edilmiş makine token jti'lerinin KV deny-list'e itilmesi ve Worker D1
// kill-flag'i. Bu bir ARAYÜZDÜR — gerçek Worker/CF entegrasyonu G-account (§6) ile
// bağlanır; motor yalnızca çağırır ve kanıtı offboard kaydına yazar.
//
// KRİTİK (§8.5.2): step 1 kriptografiye DOKUNMAZ ve tek bir admin tarafından
// UNILATERAL çalıştırılabilir olmalıdır; revocation strictly safety-increasing'dir
// ve co-sign quorum'unu BEKLEMEZ. Kill-switch en iyi çabadır (best-effort): her
// eylem, öncekiler başarısız olsa bile denenir ve kanıt kaydedilir.
type TokenRevoker interface {
	// RevokeTokens, prensibin tüm oturum + token'larını iptal etmeye çalışır ve
	// per-eylem kanıt döner. Hata, adımın devamını engellemez (best-effort).
	RevokeTokens(principal string) (RevokeEvidence, error)
}

// RevokeEvidence, kill-switch eylemlerinin per-eylem kanıtıdır (offboard kaydına
// step.kill.evidence olarak yazılır, §8.5.2).
type RevokeEvidence struct {
	// CFAccessRemoved, prensip her iki CF Access app'inden (read-AUD + write-AUD)
	// kaldırıldı mı.
	CFAccessRemoved bool `json:"cf_access_removed"`
	// ServiceTokensRevoked, iptal edilen CF Access servis token sayısı.
	ServiceTokensRevoked int `json:"service_tokens_revoked"`
	// JTIsDenied, KV deny-list'e itilen mint-edilmiş makine token jti sayısı.
	JTIsDenied int `json:"jtis_denied"`
	// D1KillFlag, Worker D1 mirror'da killed:true set edildi mi (fail-closed
	// hızlandırıcı, §8.5.2 step 4).
	D1KillFlag bool `json:"d1_kill_flag"`
	// Stubbed, gerçek entegrasyon henüz bağlanMAMIŞsa true (StubTokenRevoker).
	Stubbed bool `json:"stubbed"`
	// Note, insan-okunur durum (ASLA gizli değer içermez).
	Note string `json:"note"`
}

// StubTokenRevoker, TokenRevoker'ın yer-tutucu uygulamasıdır: hiçbir gerçek CF/
// Worker çağrısı YAPMAZ, yalnızca "stubbed" kanıtı döner ve net bir TODO taşır.
// G-account (§6) gerçek revoke yolunu buraya bağlayacak.
//
// TODO(G-account/§6): CF Access app üyelik kaldırma + servis token iptali + KV
// deny-list jti push + Worker D1 kill-flag'i gerçek API çağrılarıyla uygula.
// Pinli: revocation lag ≤60 s kabul; token TTL 10 dk.
type StubTokenRevoker struct{}

// RevokeTokens, stub kanıtı döner (hata YOK — kill-switch best-effort; gerçek
// kripto sınırı offboard step 2'deki trust-epoch kaldırmasıdır).
func (StubTokenRevoker) RevokeTokens(principal string) (RevokeEvidence, error) {
	return RevokeEvidence{
		Stubbed: true,
		Note:    "token revoke stubbed — G-account (§6) wiring pending; crypto boundary is step 2 rewrap",
	}, nil
}

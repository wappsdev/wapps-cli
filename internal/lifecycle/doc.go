// Package lifecycle, wapps-secrets prensip yaşam döngüsü motorudur (SPEC §8, G9):
// insan/cihaz/makine ENROLL, admin VOUCH, GRANT/REVOKE (katmanlı co-sign), the
// REWRAP motoru (ADD = manifest-only wrap değişikliği §3.8.1; REMOVE = yeni DEK +
// re-encrypt §3.8.2) ve 5-adımlı devam-ettirilebilir (resumable) OFFBOARD durum
// makinesi (§8.5).
//
// TASARIM: Bu motor DONMUŞ TCB'yi (internal/cryptoid, internal/trust,
// internal/registry, internal/manifest, internal/store) YENİDEN KULLANIR —
// kripto/imza/doğrulama primitiflerini burada ÇOĞALTMAZ:
//
//   - cryptoid : DEK/blob seal-open, deterministik SealDEK/UnsealDEK/WrapVerify,
//     Ed25519/ECDSA-P256 imzalama, Shamir, parmak izi (§3).
//   - registry : Identity/EncKey/SigningKey/Grant + EnrollmentRecord (§4.3/§4.9).
//   - trust    : roster zinciri, epoch doğrulama (VerifyNext/VerifyRosterChain),
//     katmanlı co-sign politikası (RequiredSigners) (§4).
//   - manifest : per-proje DataManifest + DEKWrap + imza/epoch-zinciri (§5).
//   - store    : Worker HTTP sözleşmesi (üretim veri düzlemi).
//
// KAPSAM (yazılım anahtarları — CI/test): İnsan donanım anahtarları (Secure
// Enclave / YubiKey) motorun KAPSAMI DIŞINDADIR — arayüz (HardwareKeygen)
// sağlanır ve belgelenir; motor yazılım anahtarlarıyla çalışır. Worker/CF token
// revoke (offboard step 1) bir arayüzdür (TokenRevoker), G-account (§6) ile
// bağlanır. Tipli rotasyon RECİPE'leri + `wapps migrate` (G11) ERTELENDİ —
// offboard yalnızca değer-rotasyon WORKLIST'ini ÜRETİR, çalıştırmaz.
package lifecycle

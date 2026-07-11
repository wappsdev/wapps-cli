//go:build ignore

// go-produced.json üretici (SPEC §3.1 cross-impl). FROZEN Go çekirdeğinin
// (internal/cryptoid + internal/manifest + internal/trust) ürettiği imzaları,
// data manifest'i ve trust genesis'ini TypeScript Worker doğrulayıcısının
// AYNEN doğrulayabilmesi için taşınabilir vektörlere döker. Bu dosya CLI build'ine
// GİRMEZ (//go:build ignore) — yalnızca `go run worker/testdata-gen/main.go` ile.
//
// Çalıştır (modül kökünden): go run worker/testdata-gen/main.go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/wappsdev/wapps-cli/internal/cryptoid"
	"github.com/wappsdev/wapps-cli/internal/manifest"
	"github.com/wappsdev/wapps-cli/internal/registry"
	"github.com/wappsdev/wapps-cli/internal/trust"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	outDir := "worker/test/vectors"
	must(os.MkdirAll(outDir, 0o755))

	// Kanonik frozen_vectors.json'u worker test'ine kopyala (self-contained).
	src := filepath.Join("internal", "cryptoid", "testdata", "frozen_vectors.json")
	frozen, err := os.ReadFile(src)
	must(err)
	must(os.WriteFile(filepath.Join(outDir, "frozen_vectors.json"), frozen, 0o644))

	out := map[string]any{
		"_comment": "GO-PRODUCED cross-impl vectors (SPEC §3.1). Emitted by worker/testdata-gen/main.go from the FROZEN Go core. The TS Worker verifier MUST verify every signature/manifest here byte-for-byte. Regenerate with `go run worker/testdata-gen/main.go`.",
	}

	// --- ECDSA P-256 imza vektörü (§3.2 P1363 64-bayt r‖s + DER reddi) --------
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	ecKey, err := cryptoid.NewECDSAP256FromPriv(priv)
	must(err)
	ecMsg := []byte("hello ecdsa wapps-secrets")
	ecSig, err := ecKey.Sign(ecMsg) // P1363 64-bayt
	must(err)
	// Aynı digest üzerinde DER imza (TS bunu REDDETMELİ — §3.2).
	dig := sha256.Sum256(ecMsg)
	derSig, err := ecdsa.SignASN1(rand.Reader, priv, dig[:])
	must(err)
	out["ecdsa"] = map[string]any{
		"_comment":        "ECDSA P-256 over SHA-256(msg), raw r‖s (P1363). pubkey = 65B uncompressed SEC1. key_id = sha256:<hex of pubkey>. sig_der_hex MUST be rejected (DER forbidden).",
		"message":         string(ecMsg),
		"pubkey_sec1_hex": hex.EncodeToString(ecKey.PublicKeyBytes()),
		"key_id":          ecKey.KeyID(),
		"sig_hex":         hex.EncodeToString(ecSig.Sig),
		"sig_der_hex":     hex.EncodeToString(derSig),
	}

	// --- Go-imzalı DATA manifest (§5.4) --------------------------------------
	// Yazar = ECDSA daily anahtarı; ring TS'te bu key_id'den kurulur.
	writer := ecKey
	dm := &manifest.DataManifest{
		Schema:             manifest.SchemaDataManifest,
		Project:            "vaulter",
		Epoch:              1,
		PrevManifestSha256: "",
		TrustEpoch:         1,
		CreatedAt:          time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
		Entries: []manifest.KeyEntry{
			{
				KeyName:    "DATABASE_URL",
				KeyVersion: 1,
				BlobHash:   "b8f2c16a9bc8b4875e55f29d52f66497f80a1ba3238d7872be171a3573b38b23",
				Wraps: []manifest.DEKWrap{
					{Recipient: "sha256:6a804773982840fa7eae3847079a53b0b140d678130dc68f1c7f72b5e5080d4f", Wrap: []byte("wrapbytes-A")},
				},
			},
			{
				KeyName:    "API_KEY",
				KeyVersion: 2,
				BlobHash:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
				Wraps: []manifest.DEKWrap{
					{Recipient: "sha256:1111111111111111111111111111111111111111111111111111111111111111", Wrap: []byte("wrapbytes-B")},
				},
			},
		},
	}
	dmObj, _, err := manifest.SignManifest(dm, writer)
	must(err)
	dmWrapper, err := manifest.MarshalSignedObject(dmObj)
	must(err)
	dmHash := sha256.Sum256(dmWrapper)
	// Tampered varyant: sarmalayıcı body'sinin bir baytını boz.
	tampered := tamperSignedObjectBytes(dmObj)
	out["data_manifest"] = map[string]any{
		"_comment":      "Go-signed data manifest (1 ECDSA sig). TS: parseSignedObject(JSON.parse(wrapper_json)) → verifyDataManifest(obj, ring{writer}) must pass; object hash = sha256(utf8(wrapper_json)) == object_sha256; tampered_wrapper_json must FAIL verify.",
		"wrapper_json":  string(dmWrapper),
		"object_sha256": hex.EncodeToString(dmHash[:]),
		"writer": map[string]any{
			"key_id":     writer.KeyID(),
			"alg":        writer.Alg(),
			"pubkey_b64": base64.StdEncoding.EncodeToString(writer.PublicKeyBytes()),
		},
		"expect": map[string]any{
			"project":              "vaulter",
			"epoch":                1,
			"prevManifestSha256":   "",
			"trustEpoch":           1,
			"entry_key_names":      []string{"API_KEY", "DATABASE_URL"},
			"database_url_version": 1,
		},
		"tampered_wrapper_json": string(tampered),
	}

	// --- Go-imzalı TRUST genesis (§4.2, 2-of-3 root Ed25519) -----------------
	root1, err := cryptoid.GenerateEd25519()
	must(err)
	root2, err := cryptoid.GenerateEd25519()
	must(err)
	root3, err := cryptoid.GenerateEd25519()
	must(err)
	holder := "human:adnan@wapps.dev"
	tm := &trust.TrustManifest{
		Schema:          trust.SchemaTrust,
		AdminEpoch:      1,
		PrevTrustSHA256: "",
		CreatedAt:       time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
		ChangeClass:     trust.ChangeRoster,
		BootstrapSolo:   true, // 3 kök tek insanda → maxHolderShare=3 >= m=2
		Quorum:          trust.Quorum{M: 2, N: 3},
		Roots: []trust.RootKey{
			trust.NewRootKey(root1, "yubikey-piv", holder),
			trust.NewRootKey(root2, "secure-enclave", holder),
			trust.NewRootKey(root3, "paper-steel", holder),
		},
		Admins:           []string{},
		Identities:       []registry.Identity{},
		Grants:           []registry.Grant{},
		WriterAllowlists: []registry.WriterAllow{},
		WorkerReceiptPub: trust.ReceiptKey{Kid: "att-1", Alg: "ES256", JWK: json.RawMessage(`{"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"}`)},
		WorkerMintPubs:   []trust.ReceiptKey{{Kid: "mint-2026-07", Alg: "ES256", JWK: json.RawMessage(`{"kty":"EC","crv":"P-256","x":"CCCC","y":"DDDD"}`)}},
	}
	// 2-of-3 imza (root1 + root2).
	tmObj, tmBody, err := trust.SignTrustManifest(tm, root1, root2)
	must(err)
	tmWrapper, err := json.Marshal(tmObj)
	must(err)
	pin := trust.TrustObjectHash(tmBody) // İMZALANAN payload hash'i (§4.2.2)

	// 1-imza varyantı (quorum yetersiz) — aynı body, tek sig.
	tmObj1 := cryptoid.SignedObject{Bytes: tmObj.Bytes, Sigs: tmObj.Sigs[:1]}
	tmWrapper1, err := json.Marshal(tmObj1)
	must(err)
	tmTampered := tamperSignedObjectBytes(tmObj)

	out["trust_manifest"] = map[string]any{
		"_comment":           "Go-signed trust genesis (2-of-3 root ed25519). TS: verifyGenesis({admin_epoch:1, sha256:genesis_pin_sha256}, parseSignedObject(JSON.parse(wrapper_json))) must pass. one_sig_wrapper_json must FAIL (quorum unmet). tampered must FAIL.",
		"wrapper_json":       string(tmWrapper),
		"genesis_pin_sha256": pin,
		"admin_epoch":        1,
		"root_key_ids":       []string{root1.KeyID(), root2.KeyID(), root3.KeyID()},
		"one_sig_wrapper_json": string(tmWrapper1),
		"tampered_wrapper_json": string(tmTampered),
	}

	// Yaz.
	buf, err := json.MarshalIndent(out, "", "  ")
	must(err)
	dst := filepath.Join(outDir, "go-produced.json")
	must(os.WriteFile(dst, buf, 0o644))
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes) and copied frozen_vectors.json\n", dst, len(buf))
}

// tamperSignedObjectBytes, imzalı sarmalayıcının BODY baytlarının son baytını
// değiştirir ve yeniden marshal eder — imza artık geçmez (verify-before-parse).
func tamperSignedObjectBytes(obj cryptoid.SignedObject) []byte {
	b := make([]byte, len(obj.Bytes))
	copy(b, obj.Bytes)
	if len(b) > 0 {
		b[len(b)-1] ^= 0x01
	}
	t := cryptoid.SignedObject{Bytes: b, Sigs: obj.Sigs}
	raw, err := json.Marshal(t)
	if err != nil {
		panic(err)
	}
	return raw
}

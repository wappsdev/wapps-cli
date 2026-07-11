package cryptoid

// KEK/kid/WKW1 frozen vektör + davranış testleri (SPEC §2.2–§2.5, build gate 2).
// Beklenen değerler worker/test/kek.test.ts ile AYNI literallerdir (bağımsız
// node:crypto üretimi) — Go ve TS tarafları bayt-bayt parite zorunludur.

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const (
	masterHex  = "2222222222222222222222222222222222222222222222222222222222222222"
	master2Hex = "3333333333333333333333333333333333333333333333333333333333333333"

	frozenKid        = "9f72ea0cf49536e3"
	frozenKid2       = "deb0e38ced1e41de"
	frozenKekVaulter = "14de5786d70663c6fd42879ed2c391fbb2fd6d109b532410312cf2564e0902d5"
	frozenKekLumira  = "1413fbc058690c0ef5c01322013c1c80b2212cdaf6a99ba11e02084dd77555f0"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func TestKekKidFrozen(t *testing.T) {
	kid, err := KekKid(mustHex(t, masterHex))
	if err != nil {
		t.Fatal(err)
	}
	if kid != frozenKid {
		t.Fatalf("kid = %s, want %s", kid, frozenKid)
	}
	kid2, err := KekKid(mustHex(t, master2Hex))
	if err != nil {
		t.Fatal(err)
	}
	if kid2 != frozenKid2 {
		t.Fatalf("kid2 = %s, want %s", kid2, frozenKid2)
	}
	// ASCII hex string'ini hash'lemek FARKLI sonuç verir — regresyon tuzağı (§2.2).
	wrong, err := KekKid([]byte(masterHex)[:32])
	if err != nil {
		t.Fatal(err)
	}
	if wrong == frozenKid {
		t.Fatal("kid over ASCII hex must differ from kid over raw bytes")
	}
}

func TestDeriveProjectKEKFrozen(t *testing.T) {
	master := mustHex(t, masterHex)
	for project, want := range map[string]string{
		"vaulter": frozenKekVaulter,
		"lumira":  frozenKekLumira,
	} {
		kek, err := DeriveProjectKEK(master, project)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(kek); got != want {
			t.Fatalf("KEK(%s) = %s, want %s", project, got, want)
		}
	}
}

func TestSlotAADFrozen(t *testing.T) {
	// "vaulter" ‖ 00 ‖ "DATABASE_URL" ‖ 00 ‖ "3" — worker slotAAD paritesi (§2.4).
	slot := Slot{Project: "vaulter", KeyName: "DATABASE_URL", KeyVersion: 3}
	want := "7661756c7465720044415441424153455f55524c0033"
	if got := hex.EncodeToString(slot.AAD()); got != want {
		t.Fatalf("AAD = %s, want %s", got, want)
	}
}

func TestWKW1RoundTripAndSlotBinding(t *testing.T) {
	master := mustHex(t, masterHex)
	slot := Slot{Project: "vaulter", KeyName: "DATABASE_URL", KeyVersion: 3}
	var dek DEK
	copy(dek[:], mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))

	wrap, err := WrapDEKForKEK(master, "vaulter", slot, dek, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrap) != WrapTotalLen {
		t.Fatalf("wrap len = %d, want %d", len(wrap), WrapTotalLen)
	}
	got, err := UnwrapDEKWithKEK(master, "vaulter", slot, wrap)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], dek[:]) {
		t.Fatal("unwrapped DEK != original")
	}

	// Slot bağlaması: farklı keyName/keyVersion/project → WRAP_INVALID (§2.4).
	for _, bad := range []Slot{
		{Project: "vaulter", KeyName: "OTHER_KEY", KeyVersion: 3},
		{Project: "vaulter", KeyName: "DATABASE_URL", KeyVersion: 4},
		{Project: "lumira", KeyName: "DATABASE_URL", KeyVersion: 3},
	} {
		project := bad.Project
		if _, err := UnwrapDEKWithKEK(master, project, bad, wrap); err != ErrWrapInvalid {
			t.Fatalf("slot %v: err = %v, want ErrWrapInvalid", bad, err)
		}
	}

	// Bozuk magic / kısa çerçeve → WRAP_INVALID.
	tampered := append([]byte(nil), wrap...)
	tampered[0] = 'X'
	if _, err := UnwrapDEKWithKEK(master, "vaulter", slot, tampered); err != ErrWrapInvalid {
		t.Fatalf("bad magic: err = %v, want ErrWrapInvalid", err)
	}
	if _, err := UnwrapDEKWithKEK(master, "vaulter", slot, wrap[:40]); err != ErrWrapInvalid {
		t.Fatalf("short wrap: err = %v, want ErrWrapInvalid", err)
	}
}

func TestBlobFrozenVectorStillGreen(t *testing.T) {
	// WSB1 frozen vektörü (worker/test/vectors/frozen_vectors.json blob girdisi):
	// deterministik nonce ile SealBlob paritesi + OpenBlob round-trip (§2.1).
	var dek DEK
	copy(dek[:], mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	nonce := mustHex(t, "111111111111111111111111111111111111111111111111")
	slot := Slot{Project: "vaulter", KeyName: "DATABASE_URL", KeyVersion: 3}
	plaintext := []byte("postgres://user:pass@host/db")

	blob, err := sealBlobWithNonce(plaintext, dek, slot, nonce)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := "b8f2c16a9bc8b4875e55f29d52f66497f80a1ba3238d7872be171a3573b38b23"
	if got := BlobHash(blob); got != wantHash {
		t.Fatalf("blob hash = %s, want %s (frozen vector drift!)", got, wantHash)
	}
	got, err := OpenBlob(blob, dek, slot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("OpenBlob round-trip mismatch")
	}
	// Tamper → BLOB_MALFORMED (fail-closed).
	blob[len(blob)-1] ^= 0x01
	if _, err := OpenBlob(blob, dek, slot); err != ErrBlobMalformed {
		t.Fatalf("tampered blob: err = %v, want ErrBlobMalformed", err)
	}
}

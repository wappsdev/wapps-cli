package lifecycle

import (
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/wappsdev/wapps-cli/internal/manifest"
)

// DataStore, per-proje DATA manifest'inin kalıcılık port'udur (SPEC §5/§7.3.1).
// Gerçek üretim taşıması internal/store.WorkerStore'dur (secrets-gate Worker HTTP
// sözleşmesi); bu port, rewrap motorunun ihtiyaç duyduğu asgari yüzeydir ve testte
// bellek-içi MemStore ile sürülür. CAS disiplini Worker ile aynıdır: bir commit
// yalnızca beklenen önceki obje-hash'i mevcut head ile eşleşirse (yani epoch+1
// yarışı kazanılırsa) uygulanır.
type DataStore interface {
	// CurrentManifest, projenin current imzalı manifest sarmalayıcısını + o
	// manifest'in referans verdiği tüm blob'ları döner. ok=false → henüz genesis
	// (hiç manifest yok).
	CurrentManifest(project string) (wrapper []byte, blobs map[string][]byte, epoch uint64, objHash string, ok bool, err error)

	// ListProjects, veri taşıyan (commit edilmiş bir manifest'i olan) tüm proje
	// adlarını (sıralı) döner. Escrow-share sahibi offboard'ın (§8.5.4/§9.4.4)
	// TÜM projeleri kapsayan değer-rotasyon worklist'ini üretmesi için gerekir —
	// escrow HER wrap-set'in üyesidir, eski snapshot'ları burn etmek her projedeki
	// her değeri döndürmeyi zorunlu kılar.
	ListProjects() ([]string, error)

	// PutBlob, içerik-adresli bir blob'u yükler (idempotent).
	PutBlob(project, hash string, blob []byte) error

	// CommitManifest, epoch+1 CAS yazımı yapar: expectedPrevObjHash mevcut head'in
	// obje-hash'iyle eşleşmezse ErrCASConflict. Genesis'te expectedPrevObjHash "".
	CommitManifest(project string, signedWrapper []byte, expectedPrevObjHash string) error
}

// RecordStore, imzalı kontrol-düzlemi kayıtlarını (offboard record, §8.5.1) ve
// append-only ledger'ları (rewrap per-key completion ledger §8.5.3; worklist run
// ledger §8.6.4) kalıcılaştıran port'tur. Offboard kaydı R2'de (bir admin'in
// laptop'unda DEĞİL) yaşar → laptop kaybından sağ çıkar, herhangi bir admin
// --resume edebilir (§8.5.1). Üretimde bu Worker admin API + R2'dir.
type RecordStore interface {
	// PutRecord, bir kaydı (son-yazan-kazanır) yazar. YALNIZCA write-once / append-only
	// olmayan kayıtlar için (ör. worklist run planı). Mutable, durum-geçişli offboard
	// kayıtları PutRecordCAS kullanmalı (anti-rollback).
	PutRecord(key string, data []byte) error
	// PutRecordCAS, MONOTONİK CAS yazımı yapar (§8.5.1 anti-rollback): mevcut store
	// seq'i expectedSeq ile eşleşMEZse ErrCASConflict; newSeq mevcut seq'i GEÇMEZse
	// ErrRecordRollback. Böylece eski geçerli-imzalı bir offboard envelope'u sonraki
	// (daha yüksek seq'li) bir kaydın üzerine yazılamaz. İlk yazım: expectedSeq=0.
	// ÜRETİM: bu, Worker admin API'sinde SUNUCU-TARAFI zorlanır (client'a güvenilmez).
	PutRecordCAS(key string, data []byte, expectedSeq, newSeq uint64) error
	// GetRecord, bir kaydı döner; ok=false → yok.
	GetRecord(key string) (data []byte, ok bool, err error)
	// RecordSeq, bir kaydın store'da izlenen monotonik seq'ini döner (yok → 0).
	// LoadOffboard, yüklenen İMZALI kaydın seq'inin bununla EŞLEŞTİĞİNİ doğrular:
	// bir saldırgan eski geçerli-imzalı bir envelope'u yalan bir newSeq ile yazsa bile
	// (CAS'ı geçse) gövdedeki seq izlenen seq'le uyuşmaz → rollback tespit edilir.
	RecordSeq(key string) (uint64, error)
	// ListRecords, prefix ile eşleşen kayıt anahtarlarını (sıralı) döner.
	ListRecords(prefix string) ([]string, error)
	// AppendLedger, append-only bir JSONL ledger'a bir satır ekler.
	AppendLedger(key string, line []byte) error
	// ReadLedger, ledger satırlarını (yazım sırasında) döner; yoksa boş.
	ReadLedger(key string) ([][]byte, error)
}

// MemStore, DataStore + RecordStore'un thread-safe bellek-içi bir uygulamasıdır.
// Testler + referans için (SPEC: "internal/store httptest fake-Worker VEYA bir
// bellek-içi store"). CAS'ı Worker gibi zorlar; içerik-adresli blob'lar; her proje
// izole. failCommitAfter alanı, rewrap devam-ettirilebilirliğini (resume) test
// etmek için commit'i N başarıdan SONRA hata verdirir.
type MemStore struct {
	mu sync.Mutex

	// per-proje veri düzlemi.
	proj map[string]*projState

	// kontrol düzlemi.
	records   map[string][]byte
	recordSeq map[string]uint64 // per-key monotonik seq (PutRecordCAS anti-rollback)
	ledgers   map[string][][]byte

	// failCommitAfter, >0 ise CommitManifest ilk N başarılı commit'ten SONRA
	// errInjectedCommit ile başarısız olur (interrupt-mid-way testi). 0 = kapalı.
	failCommitAfter int
	commitsOK       int
}

type projState struct {
	// current, imzalı manifest sarmalayıcısının TAM baytları; nil → genesis.
	current []byte
	epoch   uint64
	objHash string
	blobs   map[string][]byte
}

// errInjectedCommit, failCommitAfter tetiklendiğinde dönen hatadır (taşıma-katmanı
// kesintisi simülasyonu).
var errInjectedCommit = errors.New("lifecycle/memstore: injected commit failure")

// NewMemStore, boş bir bellek-içi store kurar.
func NewMemStore() *MemStore {
	return &MemStore{
		proj:      map[string]*projState{},
		records:   map[string][]byte{},
		recordSeq: map[string]uint64{},
		ledgers:   map[string][][]byte{},
	}
}

// FailCommitAfter, N başarılı commit'ten sonra commit'leri hata verdirir (test).
func (m *MemStore) FailCommitAfter(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failCommitAfter = n
	m.commitsOK = 0
}

// Heal, enjekte edilmiş commit-hatasını kaldırır (resume testinde iyileşme).
func (m *MemStore) Heal() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failCommitAfter = 0
}

func (m *MemStore) state(project string) *projState {
	p, ok := m.proj[project]
	if !ok {
		p = &projState{blobs: map[string][]byte{}}
		m.proj[project] = p
	}
	return p
}

// CurrentManifest, DataStore.
func (m *MemStore) CurrentManifest(project string) ([]byte, map[string][]byte, uint64, string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.state(project)
	if p.current == nil {
		return nil, nil, 0, "", false, nil
	}
	blobs := make(map[string][]byte, len(p.blobs))
	for h, b := range p.blobs {
		cp := make([]byte, len(b))
		copy(cp, b)
		blobs[h] = cp
	}
	wrapper := make([]byte, len(p.current))
	copy(wrapper, p.current)
	return wrapper, blobs, p.epoch, p.objHash, true, nil
}

// ListProjects, DataStore. Veri taşıyan (commit edilmiş manifest'i olan)
// projeleri sıralı döner.
func (m *MemStore) ListProjects() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for name, p := range m.proj {
		if p.current != nil {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// PutBlob, DataStore.
func (m *MemStore) PutBlob(project, hash string, blob []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.state(project)
	cp := make([]byte, len(blob))
	copy(cp, blob)
	p.blobs[hash] = cp
	return nil
}

// CommitManifest, DataStore CAS. Beklenen prev obje-hash eşleşmezse ErrCASConflict.
func (m *MemStore) CommitManifest(project string, signedWrapper []byte, expectedPrevObjHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Enjekte edilmiş kesinti (resume testi) — CAS'tan ÖNCE, böylece manifest
	// commit edilMEDEN hata döner ve resume gerçek işi tekrar yapar.
	if m.failCommitAfter > 0 && m.commitsOK >= m.failCommitAfter {
		return errInjectedCommit
	}

	p := m.state(project)
	if p.objHash != expectedPrevObjHash {
		return ErrCASConflict
	}
	obj, err := manifest.ParseSignedObject(signedWrapper)
	if err != nil {
		return err
	}
	man, err := manifest.ParseManifestBody(obj.Bytes)
	if err != nil {
		return err
	}
	cp := make([]byte, len(signedWrapper))
	copy(cp, signedWrapper)
	p.current = cp
	p.epoch = man.Epoch
	p.objHash = manifest.ManifestObjectHash(signedWrapper)
	m.commitsOK++
	return nil
}

// PutRecord, RecordStore (son-yazan-kazanır; write-once/ledger planı için).
func (m *MemStore) PutRecord(key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.records[key] = cp
	return nil
}

// PutRecordCAS, RecordStore (monotonik anti-rollback). Worker admin API'sinin
// sunucu-tarafı zorlamasının bellek-içi eşdeğeri.
func (m *MemStore) PutRecordCAS(key string, data []byte, expectedSeq, newSeq uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.recordSeq[key] // yok → 0
	if cur != expectedSeq {
		return ErrCASConflict // beklenen prev seq mevcut head ile eşleşmiyor (yarış/eş-zamanlı)
	}
	if newSeq <= cur {
		return ErrRecordRollback // MONOTONİK değil → eski envelope replay reddi
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	m.records[key] = cp
	m.recordSeq[key] = newSeq
	return nil
}

// RecordSeq, RecordStore. İzlenen monotonik seq (yok → 0).
func (m *MemStore) RecordSeq(key string) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recordSeq[key], nil
}

// GetRecord, RecordStore.
func (m *MemStore) GetRecord(key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.records[key]
	if !ok {
		return nil, false, nil
	}
	cp := make([]byte, len(d))
	copy(cp, d)
	return cp, true, nil
}

// ListRecords, RecordStore.
func (m *MemStore) ListRecords(prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.records {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// AppendLedger, RecordStore (append-only).
func (m *MemStore) AppendLedger(key string, line []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(line))
	copy(cp, line)
	m.ledgers[key] = append(m.ledgers[key], cp)
	return nil
}

// ReadLedger, RecordStore.
func (m *MemStore) ReadLedger(key string) ([][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.ledgers[key]
	out := make([][]byte, len(src))
	for i, l := range src {
		cp := make([]byte, len(l))
		copy(cp, l)
		out[i] = cp
	}
	return out, nil
}

// arayüz uyumluluğu.
var (
	_ DataStore   = (*MemStore)(nil)
	_ RecordStore = (*MemStore)(nil)
)

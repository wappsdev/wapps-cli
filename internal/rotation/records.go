package rotation

// RecordStore + bellek-içi referans implementasyonu — ZK build'inde internal/
// lifecycle'da yaşıyordu; rotasyon run-ledger'ının (ledger.go) tükettiği KEPT
// alt küme buraya taşındı (SPEC §0.2 lifecycle silindi, §6.3 rotasyon durumu KEPT).

import (
	"errors"
	"sort"
	"strings"
	"sync"
)

// Kayıt-düzlemi hataları.
var (
	// ErrCASConflict, beklenen prev seq mevcut head ile eşleşmiyor (yarış).
	ErrCASConflict = errors.New("rotation: record CAS conflict")
	// ErrRecordRollback, monotonik-olmayan seq yazımı (eski envelope replay reddi).
	ErrRecordRollback = errors.New("rotation: record rollback refused")
)

// RecordStore, rotasyon run planı + ledger'ının saklandığı kontrol-düzlemi
// deposudur. Üretim bağlaması (Worker admin API'si) insan-eliyle gelir; testler
// MemStore kullanır.
type RecordStore interface {
	// PutRecord, bir kaydı (son-yazan-kazanır) yazar. YALNIZCA write-once /
	// append-only olmayan kayıtlar için (ör. worklist run planı).
	PutRecord(key string, data []byte) error
	// PutRecordCAS, MONOTONİK CAS yazımı yapar (anti-rollback): mevcut seq
	// expectedSeq ile eşleşMEZse ErrCASConflict; newSeq mevcut seq'i GEÇMEZse
	// ErrRecordRollback. İlk yazım: expectedSeq=0.
	PutRecordCAS(key string, data []byte, expectedSeq, newSeq uint64) error
	// GetRecord, bir kaydı döner; ok=false → yok.
	GetRecord(key string) (data []byte, ok bool, err error)
	// RecordSeq, bir kaydın izlenen monotonik seq'ini döner (yok → 0).
	RecordSeq(key string) (uint64, error)
	// ListRecords, prefix ile eşleşen kayıt anahtarlarını (sıralı) döner.
	ListRecords(prefix string) ([]string, error)
	// AppendLedger, append-only bir JSONL ledger'a bir satır ekler.
	AppendLedger(key string, line []byte) error
	// ReadLedger, ledger satırlarını (yazım sırasında) döner; yoksa boş.
	ReadLedger(key string) ([][]byte, error)
}

// MemStore, RecordStore'un thread-safe bellek-içi implementasyonudur (testler +
// referans).
type MemStore struct {
	mu        sync.Mutex
	records   map[string][]byte
	recordSeq map[string]uint64
	ledgers   map[string][][]byte
}

// NewMemStore, boş bir bellek-içi kayıt deposu kurar.
func NewMemStore() *MemStore {
	return &MemStore{
		records:   map[string][]byte{},
		recordSeq: map[string]uint64{},
		ledgers:   map[string][][]byte{},
	}
}

// PutRecord, RecordStore (son-yazan-kazanır).
func (m *MemStore) PutRecord(key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.records[key] = cp
	return nil
}

// PutRecordCAS, RecordStore (monotonik anti-rollback).
func (m *MemStore) PutRecordCAS(key string, data []byte, expectedSeq, newSeq uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.recordSeq[key]
	if cur != expectedSeq {
		return ErrCASConflict
	}
	if newSeq <= cur {
		return ErrRecordRollback
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	m.records[key] = cp
	m.recordSeq[key] = newSeq
	return nil
}

// RecordSeq, RecordStore.
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
var _ RecordStore = (*MemStore)(nil)

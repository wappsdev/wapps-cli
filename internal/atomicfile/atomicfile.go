// Package atomicfile, bir dosyayı ya TAMAMEN ya da HİÇ yazar (temp + fsync +
// rename). Eskiden internal/ageutil'de yaşıyordu; age arşivi kaldırılınca
// (v0.21.0) buraya taşındı — çünkü yaptığı işin şifrelemeyle ilgisi yok:
// `apply`'ın yazdığı consumption target'ları (.env.local vb.) düz metindir ve
// yarım yazılmış bir .env dosyası bir dev sunucusunu sessizce bozar.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write, data'yı path'e atomik yazar.
//
// Sıra: (1) AYNI dizinde temp dosyası (cross-filesystem rename atomikliği
// kaybettirir), (2) fsync — rename metadata atomikliğini garanti eder ama
// VERİnin diske indiğini etmez; fsync'siz bir güç kesintisi yeni adı boş/bayat
// içerikle bırakabilir, (3) rename (POSIX'te atomik).
//
// Temp adındaki "*" CreateTemp tarafından rastgele bir sonekle değiştirilir;
// böylece eşzamanlı iki yazıcı birbirinin temp dosyasını truncate etmez.
func Write(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	f, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return fmt.Errorf("atomicfile.Write: create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	// CreateTemp 0600 ile açar; farklı bir mod istenirse yazımdan ÖNCE chmod.
	if mode != 0600 {
		if err := os.Chmod(tmp, mode); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("atomicfile.Write: chmod temp: %w", err)
		}
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("atomicfile.Write: write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("atomicfile.Write: fsync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("atomicfile.Write: close temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("atomicfile.Write: rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

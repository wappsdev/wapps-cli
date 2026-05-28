package ageutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// EncryptWriteAtomic encrypts plaintext with passphrase and writes the
// ciphertext to path using the temp-file + fsync + rename dance.
//
// Why atomic: secrets archives are catastrophic-to-corrupt files. A power
// loss, signal kill, or disk-full mid-write would leave the archive
// truncated and undecryptable. The atomic sequence guarantees that
// readers either see the OLD file or the NEW file, never a partial one.
//
// Sequence:
//  1. Write ciphertext to path+".tmp" (0600 — secrets file mode)
//  2. fsync the temp file so contents are durable on disk
//  3. os.Rename temp → final path (atomic on POSIX filesystems)
//
// Mode is hard-coded 0600. Archive files contain plaintext-equivalent
// material (age-encrypted but recoverable if passphrase leaks) and must
// not be world-readable.
//
// On any error, the temp file is removed. Existing target file is NOT
// touched until the rename succeeds.
func EncryptWriteAtomic(path string, plaintext []byte, passphrase string) error {
	encrypted, err := Encrypt(plaintext, passphrase)
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, encrypted, 0600)
}

// WriteFileAtomic writes data to path via temp+fsync+rename. Exported
// separately so callers that already have ciphertext (or are writing
// non-encrypted artifacts like .env.local from env --write) can reuse
// the same durability guarantees.
//
// Concurrency: each invocation creates a uniquely-named temp file via
// os.CreateTemp, so two processes writing the same target path don't
// trample each other's temp file. The winner of the rename race wins; the
// loser overwrites the winner — last writer wins, but neither sees the
// archive in a partial state mid-write.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	// Temp file in the SAME directory as the target so the rename is
	// guaranteed to stay within one filesystem (cross-fs rename can fail
	// or fall back to copy+delete, defeating atomicity). The "*" placeholder
	// in CreateTemp's pattern is replaced with a random suffix so concurrent
	// writers don't open and truncate each other's tmp file.
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	f, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return fmt.Errorf("ageutil.WriteFileAtomic: create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	// CreateTemp opens with 0600. Most callers want 0600 anyway (secrets);
	// for ones that ask for something else (rare), chmod after open before
	// any write.
	if mode != 0600 {
		if err := os.Chmod(tmp, mode); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return fmt.Errorf("ageutil.WriteFileAtomic: chmod temp: %w", err)
		}
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("ageutil.WriteFileAtomic: write temp: %w", err)
	}
	// fsync forces the kernel to flush the file's data to disk before
	// rename. Without this, a power loss between rename and the data
	// reaching platters can leave the renamed file with stale/empty
	// contents. POSIX filesystems guarantee rename atomicity for metadata
	// but not for data unless fsync ran first.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("ageutil.WriteFileAtomic: fsync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("ageutil.WriteFileAtomic: close temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("ageutil.WriteFileAtomic: rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

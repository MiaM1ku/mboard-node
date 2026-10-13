package certificate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPrivateUmaskProtectsOrphanLibraryStyleLock(t *testing.T) {
	f := newFixture(t, 90)
	if err := f.r.prepareStorage(f.cfg.StoragePath, true); err != nil {
		t.Fatal(err)
	}
	previous := syscall.Umask(0022)
	defer syscall.Umask(previous)
	restore := privateUmask()
	defer restore()
	path := filepath.Join(f.cfg.StoragePath, "orphan-library-lock")
	// CertMagic's default lock creator requests 0644. Even an interrupted direct
	// CLI call must leave a 0600 file, which the next preflight can safely accept.
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("lock not private", err)
	}
	if err = f.r.prepareStorage(f.cfg.StoragePath, false); err != nil {
		t.Fatal("orphan blocks future preflight", err)
	}
}

func TestPrivateStorageLocksExclusiveAndRecoverable(t *testing.T) {
	f := newFixture(t, 90)
	if err := f.r.prepareStorage(f.cfg.StoragePath, true); err != nil {
		t.Fatal(err)
	}
	a, b := newPrivateStorage(f.cfg.StoragePath), newPrivateStorage(f.cfg.StoragePath)
	ctx := context.Background()
	if err := a.Lock(ctx, "certificate/root180"); err != nil {
		t.Fatal(err)
	}
	if ok, err := b.TryLock(ctx, "certificate/root180"); err != nil || ok {
		t.Fatal("lock not exclusive", ok, err)
	}
	if ok, err := b.TryLock(ctx, "account/nested"); err != nil || !ok {
		t.Fatal("independent nested lock failed", ok, err)
	}
	if err := b.Unlock(ctx, "account/nested"); err != nil {
		t.Fatal(err)
	}
	if err := a.Unlock(ctx, "certificate/root180"); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(f.cfg.StoragePath, "private-locks", "*.lock"))
	if err != nil || len(files) != 2 {
		t.Fatal("private lock files not retained", err)
	}
	for _, path := range files {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatal("lock not private", err)
		}
	}
	if err := f.r.prepareStorage(f.cfg.StoragePath, false); err != nil {
		t.Fatal("unheld files prevent recovery", err)
	}
	if ok, err := b.TryLock(ctx, "certificate/root180"); err != nil || !ok {
		t.Fatal("could not reacquire retained lock", ok, err)
	}
	if err := b.Unlock(ctx, "certificate/root180"); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateStorageLockWaitHonorsContext(t *testing.T) {
	f := newFixture(t, 90)
	f.r.prepareStorage(f.cfg.StoragePath, true)
	a, b := newPrivateStorage(f.cfg.StoragePath), newPrivateStorage(f.cfg.StoragePath)
	if err := a.Lock(context.Background(), "same"); err != nil {
		t.Fatal(err)
	}
	defer a.Unlock(context.Background(), "same")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := b.Lock(ctx, "same"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("wait didn't honor context", err)
	}
}

func TestPrivateStorageRejectsUnsafeExistingLock(t *testing.T) {
	f := newFixture(t, 90)
	f.r.prepareStorage(f.cfg.StoragePath, true)
	s := newPrivateStorage(f.cfg.StoragePath)
	if err := s.Lock(context.Background(), "unsafe"); err != nil {
		t.Fatal(err)
	}
	s.Unlock(context.Background(), "unsafe")
	files, err := filepath.Glob(filepath.Join(f.cfg.StoragePath, "private-locks", "*.lock"))
	if err != nil || len(files) != 1 {
		t.Fatal(err)
	}
	os.Chmod(files[0], 0644)
	if ok, err := s.TryLock(context.Background(), "unsafe"); err == nil || ok {
		t.Fatal("public lock accepted", ok, err)
	}
	os.Chmod(files[0], 0600)
	real := files[0] + ".real"
	os.Rename(files[0], real)
	os.Symlink(real, files[0])
	if ok, err := s.TryLock(context.Background(), "unsafe"); err == nil || ok {
		t.Fatal("symlink lock accepted", ok, err)
	}
}

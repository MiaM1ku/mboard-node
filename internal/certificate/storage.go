package certificate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
)

// privateStorage uses the supported FileStorage asset API but overrides its
// named lock methods. Upstream stale-lock handling logs through an unexported
// logger and creates 0644 files; private kernel locks give this local one-shot
// quiet, private locks that recover immediately after a process/host crash.
// It is local-filesystem-only, not distributed/NFS storage. The outer renew.lock
// also covers validation, export, replacement and restart, not just ACME.
type privateStorage struct {
	*certmagic.FileStorage
	mu   sync.Mutex
	held map[string]*os.File
}

func newPrivateStorage(path string) *privateStorage {
	return &privateStorage{FileStorage: &certmagic.FileStorage{Path: path}, held: make(map[string]*os.File)}
}

func (s *privateStorage) Lock(ctx context.Context, name string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ok, err := s.TryLock(ctx, name)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *privateStorage) TryLock(ctx context.Context, name string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held[name] != nil {
		return false, nil
	}
	sum := sha256.Sum256([]byte(name))
	dir := filepath.Join(s.Path, "private-locks")
	if noSymlinks(dir) != nil {
		return false, errors.New("unsafe_lock_path")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return false, errors.New("lock_create_failed")
	}
	for _, p := range []string{s.Path, dir} {
		fi, err := os.Lstat(p)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0700 {
			return false, errors.New("unsafe_lock_directory")
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != os.Geteuid() {
			return false, errors.New("unsafe_lock_directory")
		}
	}
	path := filepath.Join(dir, hex.EncodeToString(sum[:])+".lock")
	if noSymlinks(path) != nil {
		return false, errors.New("unsafe_lock_path")
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return false, errors.New("lock_create_failed")
	}
	f := os.NewFile(uintptr(fd), path)
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return false, errors.New("unsafe_lock")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		f.Close()
		return false, errors.New("unsafe_lock")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return false, nil
		}
		return false, errors.New("lock_failed")
	}
	s.held[name] = f
	return true, nil
}

func (s *privateStorage) Unlock(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.held[name]
	if f == nil {
		return errors.New("lock_not_held")
	}
	delete(s.held, name)
	// Never unlink flock files: unlinking would allow a second independent inode
	// for the same lock name. The small private file is safe to retain indefinitely.
	return f.Close()
}

var _ certmagic.Storage = (*privateStorage)(nil)
var _ certmagic.TryLocker = (*privateStorage)(nil)

package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Sync the ancestry even when a concurrent caller created it: observing an
// existing directory does not prove its parent entry reached durable storage.
func durableMkdirAll(dir string) error { return mkdirAndSync(dir, syncDir) }
func mkdirAndSync(dir string, confirm func(string) error) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	current, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	current, err = filepath.Abs(current)
	if err != nil {
		return err
	}
	for {
		if err = confirm(current); err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func stageFile(path string, data []byte) (string, error) {
	dir := filepath.Dir(path)
	if err := durableMkdirAll(dir); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".mboard-stage-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if err = f.Chmod(0600); err != nil {
		return "", err
	}
	if _, err = f.Write(data); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}
func atomicWrite(path string, data []byte) error {
	name, err := stageFile(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(name)
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func Lock(dir string) (*os.File, error) {
	if err := durableMkdirAll(dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another agent owns this data_dir")
	}
	return f, nil
}

type Spool struct {
	Dir           string
	syncDirectory func(string) error
}

func (s Spool) confirm() error {
	if s.syncDirectory != nil {
		return s.syncDirectory(s.Dir)
	}
	return syncDir(s.Dir)
}

func NewBatchID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}
func ReadBatch(r io.Reader) (Batch, error) {
	var b Batch
	if err := decodeStrict(io.LimitReader(r, MaxBody+1), &b); err != nil {
		return b, errors.New("invalid batch JSON")
	}
	if b.BatchID == "" {
		id, err := NewBatchID()
		if err != nil {
			return b, err
		}
		b.BatchID = id
	}
	return b, b.Validate()
}
func (s Spool) Enqueue(b Batch) error {
	if err := b.Validate(); err != nil {
		return err
	}
	raw, _ := json.Marshal(b)
	path := filepath.Join(s.Dir, b.BatchID+".json")
	temp, err := stageFile(path, raw)
	if err != nil {
		return err
	}
	defer os.Remove(temp)
	// Link publishes a fully synced immutable batch without overwriting the ID.
	if err = os.Link(temp, path); err != nil {
		if !os.IsExist(err) {
			return err
		}
		old, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if !bytes.Equal(old, raw) {
			return errors.New("batch_id already queued with different records")
		}
		return s.confirm()
	}
	return s.confirm()
}
func (s Spool) Flush(ctx context.Context, c *Client) error {
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// Bound each pass so a large queue never starves heartbeat/config work.
	count := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		if count >= 1 {
			break
		}
		count++
		path := filepath.Join(s.Dir, e.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > MaxBody {
			return errors.New("invalid spool file")
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		var b Batch
		err = decodeStrict(io.LimitReader(f, MaxBody+1), &b)
		f.Close()
		if err != nil {
			return errors.New("invalid spool JSON; repair or quarantine the batch")
		}
		if err = b.Validate(); err != nil {
			return fmt.Errorf("invalid spool batch: %w", err)
		}
		if b.BatchID+".json" != e.Name() {
			return errors.New("spool batch ID does not match filename")
		}
		if err = c.Traffic(ctx, b); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		if err = s.confirm(); err != nil {
			return err
		}
	}
	return nil
}

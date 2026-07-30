package keysource

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatic(t *testing.T) {
	s := Static([]byte("key-1"))

	got, err := s.Bytes()
	if err != nil || string(got) != "key-1" {
		t.Fatalf("Bytes() = %q, %v", got, err)
	}
}

func TestFileReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sa-key.json")

	if err := os.WriteFile(path, []byte("key-1"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := File(slog.Default(), path)

	got, err := s.Bytes()
	if err != nil || string(got) != "key-1" {
		t.Fatalf("initial Bytes() = %q, %v", got, err)
	}

	// Rotate: new content, new mtime (set explicitly — some filesystems
	// have coarse mtime granularity).
	if err := os.WriteFile(path, []byte("key-2"), 0o600); err != nil {
		t.Fatal(err)
	}

	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}

	got, err = s.Bytes()
	if err != nil || string(got) != "key-2" {
		t.Fatalf("post-rotation Bytes() = %q, %v", got, err)
	}
}

func TestFileServesLastKnownGoodOnStatFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sa-key.json")

	if err := os.WriteFile(path, []byte("key-1"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := File(slog.Default(), path)

	if _, err := s.Bytes(); err != nil {
		t.Fatal(err)
	}

	// Simulate the transient window of kubelet's atomic swap.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	got, err := s.Bytes()
	if err != nil || string(got) != "key-1" {
		t.Fatalf("last-known-good Bytes() = %q, %v", got, err)
	}
}

func TestFileMissingAtStart(t *testing.T) {
	s := File(slog.Default(), filepath.Join(t.TempDir(), "absent.json"))

	if _, err := s.Bytes(); err == nil {
		t.Fatal("expected error for missing file with no cached key")
	}
}

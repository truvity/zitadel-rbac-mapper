// Package keysource supplies service-account key bytes to the resolver.
//
// Two implementations: Static for env-injected keys, and File for the
// chart's Secret mount. File re-reads on modification: kubelet refreshes
// mounted Secret volumes in place after a rotation (atomic symlink swap,
// which changes the file's mtime), so the next token mint picks up the
// new key WITHOUT a pod restart — closing the ESO-rotation blind spot
// (config-reload standard, gitops docs/architecture/identity-model.md).
package keysource

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Source yields the current key bytes. Implementations must be safe for
// concurrent use.
type Source interface {
	Bytes() ([]byte, error)
}

// Static returns a Source that always yields the same bytes (env-injected
// keys cannot rotate without a restart by nature).
func Static(data []byte) Source {
	return staticSource(data)
}

type staticSource []byte

func (s staticSource) Bytes() ([]byte, error) { return s, nil }

// File returns a Source backed by path. Each Bytes() call stats the file
// (cheap) and re-reads it only when the modification time or size
// changed; a reload is logged so rotations are visible in the audit
// trail.
func File(logger *slog.Logger, path string) Source {
	return &fileSource{logger: logger, path: path}
}

type fileSource struct {
	logger *slog.Logger
	path   string

	mu    sync.Mutex
	mtime time.Time
	size  int64
	data  []byte
}

func (f *fileSource) Bytes() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	info, err := os.Stat(f.path)
	if err != nil {
		// Serve the last-known-good key if we have one: a transient stat
		// failure during the kubelet's symlink swap must not fail a mint.
		if f.data != nil {
			return f.data, nil
		}

		return nil, fmt.Errorf("stat key file %q: %w", f.path, err)
	}

	if f.data != nil && info.ModTime().Equal(f.mtime) && info.Size() == f.size {
		return f.data, nil
	}

	data, err := os.ReadFile(f.path)
	if err != nil {
		if f.data != nil {
			return f.data, nil
		}

		return nil, fmt.Errorf("read key file %q: %w", f.path, err)
	}

	if f.data != nil {
		f.logger.Info("zitadel key reloaded",
			slog.String("path", f.path),
			slog.Time("mtime", info.ModTime()),
		)
	}

	f.mtime = info.ModTime()
	f.size = info.Size()
	f.data = data

	return data, nil
}

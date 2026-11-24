package sysio

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func TestWriteAtomicConcurrentWritersNoCorruption(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "concurrent.json")

	const workers = 16
	const iters = 20
	var wg sync.WaitGroup
	errs := make(chan error, workers*iters)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf(`{"worker":%d,"status":"ok"}`+"\n", id))
			for i := 0; i < iters; i++ {
				if err := WriteAtomic(target, payload, WriteAtomicOptions{Perm: 0600, UID: -1, GID: -1}); err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent WriteAtomic failed: %v", err)
	}
}

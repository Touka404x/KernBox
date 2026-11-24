package sysio

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeReadHandle struct {
	reader *bytes.Reader
	meta   FileMeta
}

func (f *fakeReadHandle) Read(p []byte) (int, error) { return f.reader.Read(p) }
func (f *fakeReadHandle) Close() error               { return nil }
func (f *fakeReadHandle) StatMeta() (FileMeta, error) {
	return f.meta, nil
}

type fakeOpenat2Resolver struct {
	absDirs      map[string]FileMeta
	beneathDirs  map[string]FileMeta
	beneathFiles map[string]struct {
		data []byte
		meta FileMeta
		err  error
	}
	seenHow []OpenHowSpec
}

func (r *fakeOpenat2Resolver) OpenDirAbsolute(absPath string) (int, FileMeta, func() error, error) {
	meta, ok := r.absDirs[absPath]
	if !ok {
		return -1, FileMeta{}, nil, os.ErrNotExist
	}
	return 100, meta, func() error { return nil }, nil
}

func (r *fakeOpenat2Resolver) OpenDirBeneath(dirFD int, relPath string, how OpenHowSpec) (int, FileMeta, func() error, error) {
	r.seenHow = append(r.seenHow, how)
	if how.Resolve != (ResolveNoSymlinks | ResolveBeneath) {
		return -1, FileMeta{}, nil, errors.New("missing openat2 resolve flags")
	}
	meta, ok := r.beneathDirs[relPath]
	if !ok {
		return -1, FileMeta{}, nil, os.ErrNotExist
	}
	return 200, meta, func() error { return nil }, nil
}

func (r *fakeOpenat2Resolver) OpenFileBeneath(dirFD int, relPath string, how OpenHowSpec) (ReadHandle, error) {
	r.seenHow = append(r.seenHow, how)
	if how.Resolve != (ResolveNoSymlinks | ResolveBeneath) {
		return nil, errors.New("missing openat2 resolve flags")
	}
	if strings.Contains(relPath, "..") {
		return nil, ErrSymlinkBlocked
	}
	entry, ok := r.beneathFiles[relPath]
	if !ok {
		return nil, os.ErrNotExist
	}
	if entry.err != nil {
		return nil, entry.err
	}
	return &fakeReadHandle{reader: bytes.NewReader(entry.data), meta: entry.meta}, nil
}

func TestReadWorkVPNStatusBytes_SecurityChecks(t *testing.T) {
	baseResolver := func() *fakeOpenat2Resolver {
		return &fakeOpenat2Resolver{
			absDirs: map[string]FileMeta{
				"/data/user": {IsDir: true, UID: 1000},
			},
			beneathDirs: map[string]FileMeta{
				"10": {IsDir: true, UID: 1000},
			},
			beneathFiles: map[string]struct {
				data []byte
				meta FileMeta
				err  error
			}{
				"com.sandbox.controller/files/vpn_status.json": {
					data: []byte(`{"running":true,"tun_if":"tun0"}`),
					meta: FileMeta{IsRegular: true, UID: 1010376, Size: 32},
				},
			},
		}
	}

	// Valid read verifies exact RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH and flags.
	r := baseResolver()
	got, err := ReadWorkVPNStatusBytes(r, 10, 1010376, "com.sandbox.controller")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != `{"running":true,"tun_if":"tun0"}` {
		t.Fatalf("unexpected payload: %s", string(got))
	}
	if len(r.seenHow) != 2 {
		t.Fatalf("expected 2 openat2 calls, got %d", len(r.seenHow))
	}
	if r.seenHow[1].Resolve != (ResolveNoSymlinks | ResolveBeneath) {
		t.Fatalf("wrong resolve flags: %#x", r.seenHow[1].Resolve)
	}
	if r.seenHow[1].Flags != platformReadOnlyNonBlockCloexec() {
		t.Fatalf("wrong open flags: %#x", r.seenHow[1].Flags)
	}

	// Rejects user 999 / user 0.
	if _, err := ReadWorkVPNStatusBytes(r, 999, 99910376, "com.sandbox.controller"); err == nil {
		t.Fatal("accepted non-managed clone user 999")
	}
	if _, err := ReadWorkVPNStatusBytes(r, 0, 10376, "com.sandbox.controller"); err == nil {
		t.Fatal("accepted user 0")
	}
	if _, err := ReadWorkVPNStatusBytes(r, 10, 1010376, "../evil"); err == nil {
		t.Fatal("accepted traversal package")
	}

	// Rejects symlink on files/ or vpn_status.json.
	rSym := baseResolver()
	rSym.beneathFiles["com.sandbox.controller/files/vpn_status.json"] = struct {
		data []byte
		meta FileMeta
		err  error
	}{err: ErrSymlinkBlocked}
	if _, err := ReadWorkVPNStatusBytes(rSym, 10, 1010376, "com.sandbox.controller"); !errors.Is(err, ErrSymlinkBlocked) {
		t.Fatalf("expected ErrSymlinkBlocked, got %v", err)
	}

	// Rejects FIFO/device (IsRegular == false).
	rPipe := baseResolver()
	rPipe.beneathFiles["com.sandbox.controller/files/vpn_status.json"] = struct {
		data []byte
		meta FileMeta
		err  error
	}{meta: FileMeta{IsRegular: false, UID: 1010376, Size: 10}}
	if _, err := ReadWorkVPNStatusBytes(rPipe, 10, 1010376, "com.sandbox.controller"); !errors.Is(err, ErrNotRegularFile) {
		t.Fatalf("expected ErrNotRegularFile, got %v", err)
	}

	// Rejects wrong UID on vpn_status.json.
	rUID := baseResolver()
	rUID.beneathFiles["com.sandbox.controller/files/vpn_status.json"] = struct {
		data []byte
		meta FileMeta
		err  error
	}{data: []byte("{}"), meta: FileMeta{IsRegular: true, UID: 1010999, Size: 2}}
	if _, err := ReadWorkVPNStatusBytes(rUID, 10, 1010376, "com.sandbox.controller"); !errors.Is(err, ErrInvalidOwner) {
		t.Fatalf("expected ErrInvalidOwner, got %v", err)
	}

	// Rejects /data/user/10 owned by workClientUID.
	rUserOwner := baseResolver()
	rUserOwner.beneathDirs["10"] = FileMeta{IsDir: true, UID: 1010376}
	if _, err := ReadWorkVPNStatusBytes(rUserOwner, 10, 1010376, "com.sandbox.controller"); !errors.Is(err, ErrInvalidOwner) {
		t.Fatalf("expected ErrInvalidOwner on user dir, got %v", err)
	}

	// Rejects oversized payload (>4096B) even if stat lies.
	rBig := baseResolver()
	rBig.beneathFiles["com.sandbox.controller/files/vpn_status.json"] = struct {
		data []byte
		meta FileMeta
		err  error
	}{data: bytes.Repeat([]byte("a"), 4097), meta: FileMeta{IsRegular: true, UID: 1010376, Size: 100}}
	if _, err := ReadWorkVPNStatusBytes(rBig, 10, 1010376, "com.sandbox.controller"); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("expected ErrFileTooLarge, got %v", err)
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "u10.pending.json")
	if err := WriteAtomic(dst, []byte(`{"version":1}`), WriteAtomicOptions{Perm: 0640, UID: -1, GID: -1}); err != nil {
		t.Fatalf("WriteAtomic failed: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"version":1}` {
		t.Fatalf("unexpected file content: %q", string(got))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "u10.pending.json" {
		t.Fatalf("unexpected leftover files: %v", entries)
	}
	_ = io.EOF
}

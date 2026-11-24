package sysio

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

const (
	ResolveNoSymlinks uint64 = 0x04
	ResolveBeneath    uint64 = 0x08
	SysOpenat2Arm64          = 437
)

var (
	ErrSymlinkBlocked = errors.New("symlink or path escape blocked by openat2")
	ErrInvalidOwner   = errors.New("unexpected file or directory owner")
	ErrNotRegularFile = errors.New("target is not a regular file")
	ErrNotDirectory   = errors.New("target is not a directory")
	ErrFileTooLarge   = errors.New("file exceeds maximum allowed size")
)

type OpenHowSpec struct {
	Flags   uint64
	Mode    uint64
	Resolve uint64
}

type FileMeta struct {
	IsRegular bool
	IsDir     bool
	UID       int
	Perm      uint32
	Size      int64
}

type ReadHandle interface {
	io.ReadCloser
	StatMeta() (FileMeta, error)
}

// SafeResolver abstracts Linux openat2 (or strict O_NOFOLLOW component walk in kernel_compat)
// + dirfd traversal so symlink-escape checks are enforced identically across variants.
type SafeResolver interface {
	OpenDirAbsolute(absPath string) (dirFD int, meta FileMeta, closeFn func() error, err error)
	OpenDirBeneath(dirFD int, relPath string, how OpenHowSpec) (subFD int, meta FileMeta, closeFn func() error, err error)
	OpenFileBeneath(dirFD int, relPath string, how OpenHowSpec) (ReadHandle, error)
}

func RequiredVPNStatusOpenHow() OpenHowSpec {
	return OpenHowSpec{
		Flags:   platformReadOnlyNonBlockCloexec(),
		Mode:    0,
		Resolve: ResolveNoSymlinks | ResolveBeneath,
	}
}

func RequiredDirOpenHow() OpenHowSpec {
	return OpenHowSpec{
		Flags:   platformReadOnlyDirCloexec(),
		Mode:    0,
		Resolve: ResolveNoSymlinks | ResolveBeneath,
	}
}

// DefaultResolver returns the platform SafeResolver (exposed for sibling packages like daemon).
func DefaultResolver() SafeResolver {
	return defaultResolver()
}

// ReadWorkVPNStatusBytes securely reads /data/user/<userID>/<workPkg>/files/vpn_status.json
// without ever calling setresuid and strictly rejecting symlinks, path escapes, wrong owners,
// non-regular files, and oversized payloads (>4096B).
func ReadWorkVPNStatusBytes(resolver SafeResolver, userID, workClientUID int, workPkg string) ([]byte, error) {
	if resolver == nil {
		resolver = defaultResolver()
	}
	if oem.IsForbiddenUser(userID) {
		return nil, fmt.Errorf("refusing unsafe user_id %d", userID)
	}
	if !contracts.ValidClientUID(userID, workClientUID) {
		return nil, fmt.Errorf("invalid work client uid %d for user %d", workClientUID, userID)
	}
	pkg := strings.TrimSpace(workPkg)
	if pkg == "" {
		pkg = contracts.DefaultWorkPackage
	}
	if !contracts.ValidPackageName(pkg) || strings.ContainsAny(pkg, "/\\") || strings.Contains(pkg, "..") {
		return nil, fmt.Errorf("invalid work package %q", workPkg)
	}

	parentFD, parentMeta, closeParent, err := resolver.OpenDirAbsolute("/data/user")
	if err != nil {
		return nil, err
	}
	defer closeParent()
	if !parentMeta.IsDir {
		return nil, ErrNotDirectory
	}
	if parentMeta.UID != 0 && parentMeta.UID != 1000 {
		return nil, fmt.Errorf("%w: /data/user owned by uid %d", ErrInvalidOwner, parentMeta.UID)
	}

	userFD, userMeta, closeUser, err := resolver.OpenDirBeneath(parentFD, strconv.Itoa(userID), RequiredDirOpenHow())
	if err != nil {
		return nil, err
	}
	defer closeUser()
	if !userMeta.IsDir {
		return nil, ErrNotDirectory
	}
	if userMeta.UID != 0 && userMeta.UID != 1000 {
		return nil, fmt.Errorf("%w: /data/user/%d owned by uid %d", ErrInvalidOwner, userID, userMeta.UID)
	}

	handle, err := resolver.OpenFileBeneath(userFD, pkg+"/files/vpn_status.json", RequiredVPNStatusOpenHow())
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	meta, err := handle.StatMeta()
	if err != nil {
		return nil, err
	}
	if !meta.IsRegular {
		return nil, ErrNotRegularFile
	}
	if meta.UID != workClientUID {
		return nil, fmt.Errorf("%w: vpn_status.json owned by uid %d, want %d", ErrInvalidOwner, meta.UID, workClientUID)
	}
	if meta.Size > contracts.MaxVPNStatusBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrFileTooLarge, meta.Size)
	}

	data, err := io.ReadAll(io.LimitReader(handle, contracts.MaxVPNStatusBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > contracts.MaxVPNStatusBytes {
		return nil, fmt.Errorf("%w: >%d bytes", ErrFileTooLarge, contracts.MaxVPNStatusBytes)
	}
	return data, nil
}

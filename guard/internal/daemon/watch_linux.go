//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
	"sandbox_guard/internal/sysio"
)

var rtGroups = []int{
	unix.RTNLGRP_LINK,
	unix.RTNLGRP_IPV4_IFADDR,
	unix.RTNLGRP_IPV4_ROUTE,
	unix.RTNLGRP_IPV4_RULE,
	unix.RTNLGRP_IPV6_IFADDR,
	unix.RTNLGRP_IPV6_ROUTE,
	unix.RTNLGRP_IPV6_RULE,
}

func wakeUp(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// WatchRoutes monitors NETLINK_ROUTE events with zero polling via blocking Poll + wake pipe.
func WatchRoutes(wake chan<- struct{}, fail chan<- error) (func(), error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	for _, g := range rtGroups {
		if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, g); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("netlink group %d: %w", g, err)
		}
	}
	var pipeFds [2]int
	if err := unix.Pipe2(pipeFds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	stopR, stopW := pipeFds[0], pipeFds[1]
	done := make(chan struct{})
	var once sync.Once
	closeFn := func() {
		once.Do(func() {
			close(done)
			_ = unix.Close(stopW)
		})
	}
	go func() {
		defer func() {
			_ = unix.Close(fd)
			_ = unix.Close(stopR)
		}()
		buf := make([]byte, 64<<10)
		fds := []unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLIN},
			{Fd: int32(stopR), Events: unix.POLLIN},
		}
		for {
			if _, perr := unix.Poll(fds, -1); perr != nil {
				if perr == unix.EINTR {
					continue
				}
				select {
				case <-done:
					return
				case fail <- fmt.Errorf("netlink poll: %w", perr):
				default:
				}
				return
			}
			select {
			case <-done:
				return
			default:
			}
			if fds[1].Revents != 0 {
				return
			}
			for {
				_, _, err := unix.Recvfrom(fd, buf, 0)
				if err == nil {
					wakeUp(wake)
					continue
				}
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					break
				}
				if err == unix.ENOBUFS {
					wakeUp(wake)
					continue
				}
				if err == unix.EINTR {
					continue
				}
				select {
				case <-done:
					return
				case fail <- fmt.Errorf("netlink: %w", err):
				default:
				}
				return
			}
		}
	}()
	return closeFn, nil
}

type WatchChannels struct {
	RouteWake     chan struct{}
	AckWake       chan struct{}
	VPNStatusWake chan struct{}
	PkgWake       chan struct{}
	UserWake      chan struct{}
	Shutdown      chan string
	Fail          chan error
}

type InotifyWatcher struct {
	fd           int
	stopR        int
	stopW        int
	done         chan struct{}
	mu           sync.Mutex
	kinds        map[int]string
	proxyDirs    map[string]int
	workFD       int
	workWd       int
	workUserID   int
	workClientID int
	workPkg      string
	closeOnce    sync.Once
}

func StartInotifyWatcher(ch WatchChannels) (*InotifyWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	var pipeFds [2]int
	if err := unix.Pipe2(pipeFds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	w := &InotifyWatcher{
		fd:        fd,
		stopR:     pipeFds[0],
		stopW:     pipeFds[1],
		done:      make(chan struct{}),
		kinds:     make(map[int]string),
		proxyDirs: make(map[string]int),
		workFD:    -1,
		workWd:    -1,
	}

	add := func(path string, mask uint32, kind string, required bool) error {
		wd, err := unix.InotifyAddWatch(fd, path, mask|unix.IN_DONT_FOLLOW)
		if err != nil {
			if required {
				return fmt.Errorf("watch %s: %w", path, err)
			}
			return nil
		}
		w.mu.Lock()
		w.kinds[wd] = kind
		w.mu.Unlock()
		return nil
	}

	gone := uint32(unix.IN_DELETE_SELF | unix.IN_MOVE_SELF)
	if err := add(contracts.ModuleDir, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE|gone, "module", true); err != nil {
		_ = unix.Close(fd)
		_ = unix.Close(w.stopR)
		_ = unix.Close(w.stopW)
		return nil, err
	}
	_ = os.MkdirAll(contracts.MainBase, 0700)
	_ = add(contracts.MainBase, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE|unix.IN_DELETE|unix.IN_MOVED_FROM, "mainbase", false)
	w.mu.Lock()
	for wd, k := range w.kinds {
		if k == "mainbase" {
			w.proxyDirs[contracts.MainBase] = wd
		}
	}
	w.mu.Unlock()
	_ = add(filepath.Dir(contracts.PackagesListPath), unix.IN_MOVED_TO, "system", false)
	_ = add(contracts.UsersSystemDir, unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE|unix.IN_CREATE|unix.IN_DELETE, "users", false)
	_ = add(contracts.NetdMiscDir, unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE|unix.IN_CREATE|unix.IN_DELETE, "netd", false)

	go w.loop(ch)
	return w, nil
}

// EnsureProxyBaseWatch dynamically attaches an inotify watch on a custom proxy base directory
// so sandbox_ack.v1.json updates trigger AckWake immediately without waiting for the 3s fallback timer.
func (w *InotifyWatcher) EnsureProxyBaseWatch(dir string) {
	if w == nil {
		return
	}
	clean := filepath.Clean(strings.TrimSpace(dir))
	if clean == "" || clean == "." {
		return
	}
	w.mu.Lock()
	_, exists := w.proxyDirs[clean]
	w.mu.Unlock()
	if exists {
		return
	}
	_ = os.MkdirAll(clean, 0700)
	mask := uint32(unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_DONT_FOLLOW)
	wd, err := unix.InotifyAddWatch(w.fd, clean, mask)
	if err != nil {
		return
	}
	w.mu.Lock()
	if _, dup := w.proxyDirs[clean]; dup {
		_, _ = unix.InotifyRmWatch(w.fd, uint32(wd))
	} else {
		w.proxyDirs[clean] = wd
		w.kinds[wd] = "mainbase"
	}
	w.mu.Unlock()
}

// EnsureWorkFilesWatch attaches an inotify watch on /data/user/<u>/<workPkg>/files
// using sysio.SafeResolver (openat2 or kernel_compat openat O_NOFOLLOW component walk).
func (w *InotifyWatcher) EnsureWorkFilesWatch(userID, clientUID int, workPkg ...string) {
	if w == nil || oem.IsForbiddenUser(userID) || !contracts.ValidClientUID(userID, clientUID) {
		return
	}
	pkg := contracts.DefaultWorkPackage
	if len(workPkg) > 0 && contracts.ValidPackageName(workPkg[0]) {
		pkg = workPkg[0]
	}
	w.mu.Lock()
	sameTarget := w.workWd >= 0 && w.workUserID == userID && w.workClientID == clientUID && w.workPkg == pkg
	needReset := w.workWd >= 0 && !sameTarget
	w.mu.Unlock()
	if sameTarget {
		return
	}
	if needReset {
		w.resetWorkFilesWatch()
	}

	resolver := sysio.DefaultResolver()
	parentFD, _, closeParent, err := resolver.OpenDirAbsolute("/data/user")
	if err != nil {
		return
	}
	defer func() { _ = closeParent() }()

	dirHow := sysio.RequiredDirOpenHow()
	userFD, _, closeUser, err := resolver.OpenDirBeneath(parentFD, strconv.Itoa(userID), dirHow)
	if err != nil {
		return
	}
	defer func() { _ = closeUser() }()

	filesFD, meta, closeFiles, err := resolver.OpenDirBeneath(userFD, pkg+"/files", dirHow)
	if err != nil {
		return
	}
	if !meta.IsDir || meta.UID != clientUID {
		_ = closeFiles()
		return
	}
	wd, err := unix.InotifyAddWatch(w.fd, fmt.Sprintf("/proc/self/fd/%d", filesFD),
		unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO|unix.IN_CREATE|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF)
	if err != nil {
		_ = closeFiles()
		return
	}

	w.mu.Lock()
	if w.workWd >= 0 {
		_, _ = unix.InotifyRmWatch(w.fd, uint32(wd))
		_ = closeFiles()
	} else {
		w.workFD = filesFD
		w.workWd = wd
		w.workUserID = userID
		w.workClientID = clientUID
		w.workPkg = pkg
		w.kinds[wd] = "workfiles"
	}
	w.mu.Unlock()
}

func (w *InotifyWatcher) resetWorkFilesWatch() {
	w.mu.Lock()
	if w.workWd >= 0 {
		delete(w.kinds, w.workWd)
		_, _ = unix.InotifyRmWatch(w.fd, uint32(w.workWd))
		w.workWd = -1
	}
	if w.workFD >= 0 {
		_ = unix.Close(w.workFD)
		w.workFD = -1
	}
	w.workUserID = 0
	w.workClientID = 0
	w.workPkg = ""
	w.mu.Unlock()
}

func (w *InotifyWatcher) Close() {
	w.closeOnce.Do(func() {
		w.resetWorkFilesWatch()
		close(w.done)
		_ = unix.Close(w.stopW)
	})
}

func (w *InotifyWatcher) loop(ch WatchChannels) {
	defer func() {
		_ = unix.Close(w.fd)
		_ = unix.Close(w.stopR)
	}()
	buf := make([]byte, 16<<10)
	gone := uint32(unix.IN_DELETE_SELF | unix.IN_MOVE_SELF)
	fds := []unix.PollFd{
		{Fd: int32(w.fd), Events: unix.POLLIN},
		{Fd: int32(w.stopR), Events: unix.POLLIN},
	}
	for {
		if _, perr := unix.Poll(fds, -1); perr != nil {
			if perr == unix.EINTR {
				continue
			}
			select {
			case <-w.done:
				return
			case ch.Fail <- fmt.Errorf("inotify poll: %v", perr):
			default:
			}
			return
		}
		select {
		case <-w.done:
			return
		default:
		}
		if fds[1].Revents != 0 {
			return
		}
		for {
			n, err := unix.Read(w.fd, buf)
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				break
			}
			if err != nil || n <= 0 {
				select {
				case <-w.done:
					return
				case ch.Fail <- fmt.Errorf("inotify read: %v", err):
				default:
				}
				return
			}
			for off := 0; off+unix.SizeofInotifyEvent <= n; {
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
				evEnd := off + unix.SizeofInotifyEvent + int(ev.Len)
				if evEnd > n {
					break
				}
				name := ""
				if ev.Len > 0 {
					name = strings.TrimRight(string(buf[off+unix.SizeofInotifyEvent:evEnd]), "\x00")
				}
				off = evEnd

				w.mu.Lock()
				kind := w.kinds[int(ev.Wd)]
				w.mu.Unlock()

				switch kind {
				case "module":
					if ev.Mask&gone != 0 || name == "disable" || name == "remove" {
						select {
						case ch.Shutdown <- "module " + name:
						default:
						}
					}
				case "mainbase":
					if name == "sandbox_ack.v1.json" || name == "core.pid" || name == "" {
						wakeUp(ch.AckWake)
					}
				case "system":
					if name == "packages.list" || name == "" {
						wakeUp(ch.PkgWake)
					}
				case "users":
					wakeUp(ch.UserWake)
				case "netd":
					wakeUp(ch.RouteWake)
				case "workfiles":
					if ev.Mask&gone != 0 {
						w.resetWorkFilesWatch()
					} else if name == "vpn_status.json" || name == "" {
						wakeUp(ch.VPNStatusWake)
					}
				}
			}
		}
	}
}

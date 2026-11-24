//go:build !linux

package daemon

import "errors"

func wakeUp(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func WatchRoutes(wake chan<- struct{}, fail chan<- error) (func(), error) {
	return nil, errors.New("netlink watch only supported on linux")
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

type InotifyWatcher struct{}

func StartInotifyWatcher(ch WatchChannels) (*InotifyWatcher, error) {
	return nil, errors.New("inotify only supported on linux")
}

func (w *InotifyWatcher) EnsureWorkFilesWatch(userID, clientUID int, workPkg ...string) {}
func (w *InotifyWatcher) Close()                                     {}

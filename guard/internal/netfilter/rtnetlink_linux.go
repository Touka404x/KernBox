//go:build linux

package netfilter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"sandbox_guard/internal/contracts"
)

func openRouteNetlinkSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	tv := unix.NsecToTimeval(int64(4 * time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func netlinkExchange(fd int, req []byte, seq uint32) ([]byte, error) {
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	buf := make([]byte, 32768)
	var out []byte
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if n == 0 {
			return out, nil
		}
		chunk := buf[:n]
		for len(chunk) >= 16 {
			mlen := int(binary.LittleEndian.Uint32(chunk[0:4]))
			mtype := binary.LittleEndian.Uint16(chunk[4:6])
			mseq := binary.LittleEndian.Uint32(chunk[8:12])
			if mlen < 16 || mlen > len(chunk) {
				return nil, fmt.Errorf("malformed netlink msg len=%d buf=%d", mlen, len(chunk))
			}
			step := nlAlign4(mlen)
			if step <= 0 || step > len(chunk) {
				step = len(chunk)
			}
			if mseq != seq {
				chunk = chunk[step:]
				continue
			}
			msg := chunk[:mlen]
			if mtype == rtmNLMsgError {
				if len(msg) < 20 {
					return nil, errors.New("short nlmsgerr")
				}
				errnoVal := int32(binary.LittleEndian.Uint32(msg[16:20]))
				if errnoVal != 0 {
					return nil, syscall.Errno(-errnoVal)
				}
				return out, nil
			}
			if mtype == rtmNLMsgDone {
				return out, nil
			}
			out = append(out, msg...)
			for z := mlen; z < step; z++ {
				out = append(out, 0)
			}
			chunk = chunk[step:]
		}
		// Single non-multi replies do not emit NLMSG_DONE.
		if len(out) > 0 && binary.LittleEndian.Uint16(out[6:8])&nlmFMulti == 0 {
			return out, nil
		}
	}
}

func loopbackIfindex() (uint32, error) {
	ifi, err := net.InterfaceByName("lo")
	if err != nil || ifi.Index <= 0 {
		return 0, fmt.Errorf("resolve lo ifindex: %v", err)
	}
	return uint32(ifi.Index), nil
}

func nativeEnsureTProxyRouting(mark uint32, pref, table int) error {
	fd, err := openRouteNetlinkSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	loIdx, err := loopbackIfindex()
	if err != nil {
		return err
	}
	wantPref := uint32(pref)
	wantTable := uint32(table)
	wantMask := uint32(contracts.NetIDMask)

	rulesRaw, err := netlinkExchange(fd, encodeIPv4RuleMsg(rtmGetRule, nlmFRequest|nlmFDump, 1, 0, 0, 0, 0), 1)
	if err != nil {
		return err
	}
	validCount := 0
	staleCount := 0
	for _, r := range parseIPv4Rules(rulesRaw) {
		if r.Pref != wantPref {
			continue
		}
		if r.Mark == mark && r.Mask == wantMask && r.Table == wantTable {
			validCount++
		} else {
			staleCount++
		}
	}

	haveRule := validCount == 1 && staleCount == 0
	delCount := 0
	if !haveRule && (validCount > 0 || staleCount > 0) {
		delCount = validCount + staleCount
	}
	var seq uint32 = 2
	for i := 0; i < delCount && i < 16; i++ {
		delMsg := encodeIPv4RuleMsg(rtmDelRule, nlmFRequest|nlmFAck, seq, wantPref, 0, 0, 0)
		seq++
		if _, derr := netlinkExchange(fd, delMsg, seq-1); derr != nil {
			if errors.Is(derr, syscall.ENOENT) {
				break
			}
			return derr
		}
	}
	if !haveRule {
		addMsg := encodeIPv4RuleMsg(rtmNewRule, nlmFRequest|nlmFCreate|nlmFExcl|nlmFAck, seq, wantPref, mark, wantMask, wantTable)
		seq++
		if _, aerr := netlinkExchange(fd, addMsg, seq-1); aerr != nil && !errors.Is(aerr, syscall.EEXIST) {
			return aerr
		}
	}

	routesRaw, err := netlinkExchange(fd, encodeIPv4LocalRouteMsg(rtmGetRoute, nlmFRequest|nlmFDump, seq, 0, 0), seq)
	seq++
	if err != nil || !parseIPv4LocalLoRoutes(routesRaw, loIdx, wantTable) {
		addRoute := encodeIPv4LocalRouteMsg(rtmNewRoute, nlmFRequest|nlmFCreate|nlmFReplace|nlmFAck, seq, loIdx, wantTable)
		if _, rerr := netlinkExchange(fd, addRoute, seq); rerr != nil {
			return rerr
		}
	}
	return nil
}

func nativeVerifyTProxyRouting(mark uint32, pref, table int) error {
	fd, err := openRouteNetlinkSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	loIdx, err := loopbackIfindex()
	if err != nil {
		return err
	}
	wantPref := uint32(pref)
	wantTable := uint32(table)
	wantMask := uint32(contracts.NetIDMask)

	rulesRaw, err := netlinkExchange(fd, encodeIPv4RuleMsg(rtmGetRule, nlmFRequest|nlmFDump, 1, 0, 0, 0, 0), 1)
	if err != nil {
		return err
	}
	validCount := 0
	staleCount := 0
	for _, r := range parseIPv4Rules(rulesRaw) {
		if r.Pref != wantPref {
			continue
		}
		if r.Mark == mark && r.Mask == wantMask && r.Table == wantTable {
			validCount++
		} else {
			staleCount++
		}
	}
	if validCount != 1 || staleCount > 0 {
		return fmt.Errorf("%w: pref %d ip rule mismatch (valid=%d stale=%d want fwmark 0x%x/0x%x lookup %d)", errTProxyVerifyMismatch, pref, validCount, staleCount, mark, wantMask, table)
	}

	routesRaw, err := netlinkExchange(fd, encodeIPv4LocalRouteMsg(rtmGetRoute, nlmFRequest|nlmFDump, 2, 0, 0), 2)
	if err != nil {
		return err
	}
	if !parseIPv4LocalLoRoutes(routesRaw, loIdx, wantTable) {
		return fmt.Errorf("%w: missing local dev lo route in table %d", errTProxyVerifyMismatch, table)
	}
	return nil
}

func nativeCleanupTProxyRouting(pref, table int) error {
	fd, err := openRouteNetlinkSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var seq uint32 = 1
	for i := 0; i < 4; i++ {
		delMsg := encodeIPv4RuleMsg(rtmDelRule, nlmFRequest|nlmFAck, seq, uint32(pref), 0, 0, 0)
		seq++
		if _, derr := netlinkExchange(fd, delMsg, seq-1); derr != nil {
			if errors.Is(derr, syscall.ENOENT) {
				break
			}
			return derr
		}
	}
	if loIdx, lerr := loopbackIfindex(); lerr == nil {
		delRoute := encodeIPv4LocalRouteMsg(rtmDelRoute, nlmFRequest|nlmFAck, seq, loIdx, uint32(table))
		if _, rerr := netlinkExchange(fd, delRoute, seq); rerr != nil && !errors.Is(rerr, syscall.ENOENT) && !errors.Is(rerr, syscall.ESRCH) {
			return rerr
		}
	}
	return nil
}

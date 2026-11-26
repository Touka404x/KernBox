package netfilter

import (
	"encoding/binary"
	"errors"
)

const (
	rtmNLMsgError   = 0x2
	rtmNLMsgDone    = 0x3
	rtmNewRoute     = 24
	rtmDelRoute     = 25
	rtmGetRoute     = 26
	rtmNewRule      = 32
	rtmDelRule      = 33
	rtmGetRule      = 34

	nlmFRequest = 0x01
	nlmFMulti   = 0x02
	nlmFAck     = 0x04
	nlmFRoot    = 0x100
	nlmFMatch   = 0x200
	nlmFDump    = nlmFRoot | nlmFMatch
	nlmFReplace = 0x100
	nlmFExcl    = 0x200
	nlmFCreate  = 0x400

	nlAfInet     = 2
	fraPriority  = 6
	fraFwMark    = 10
	fraTable     = 15
	fraFwMask    = 16
	frActToTbl   = 1

	rtnLocal    = 2
	rtProtBoot  = 3
	rtScopeHost = 254
	rtaOif      = 4
	rtaTable    = 15
)

type ipv4RuleEntry struct {
	Pref  uint32
	Mark  uint32
	Mask  uint32
	Table uint32
}

var errNetlinkUnsupported = errors.New("native rtnetlink unavailable")
var errTProxyVerifyMismatch = errors.New("tproxy routing mismatch")

func nlAlign4(n int) int {
	return (n + 3) &^ 3
}

func appendU32Attr(buf []byte, attrType uint16, val uint32) []byte {
	var a [8]byte
	binary.LittleEndian.PutUint16(a[0:2], 8)
	binary.LittleEndian.PutUint16(a[2:4], attrType)
	binary.LittleEndian.PutUint32(a[4:8], val)
	return append(buf, a[:]...)
}

func encodeIPv4RuleMsg(msgType uint16, flags uint16, seq uint32, pref, mark, mask, table uint32) []byte {
	// 16B nlmsghdr + 12B fib_rule_hdr + up to 4 attrs * 8B = 60B
	buf := make([]byte, 28, 64)
	binary.LittleEndian.PutUint16(buf[4:6], msgType)
	binary.LittleEndian.PutUint16(buf[6:8], flags)
	binary.LittleEndian.PutUint32(buf[8:12], seq)

	// fib_rule_hdr (same wire layout as rtmsg: 12 bytes)
	buf[16] = nlAfInet
	if msgType == rtmGetRule {
		binary.LittleEndian.PutUint32(buf[0:4], uint32(len(buf)))
		return buf
	}
	if table > 0 && table <= 255 {
		buf[20] = byte(table)
	}
	buf[23] = frActToTbl
	if pref > 0 {
		buf = appendU32Attr(buf, fraPriority, pref)
	}
	if mark != 0 {
		buf = appendU32Attr(buf, fraFwMark, mark)
	}
	if mask != 0 {
		buf = appendU32Attr(buf, fraFwMask, mask)
	}
	if table > 0 {
		buf = appendU32Attr(buf, fraTable, table)
	}
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(buf)))
	return buf
}

func encodeIPv4LocalRouteMsg(msgType uint16, flags uint16, seq uint32, loIfindex, table uint32) []byte {
	// 16B nlmsghdr + 12B rtmsg + up to 2 attrs * 8B = 44B
	buf := make([]byte, 28, 48)
	binary.LittleEndian.PutUint16(buf[4:6], msgType)
	binary.LittleEndian.PutUint16(buf[6:8], flags)
	binary.LittleEndian.PutUint32(buf[8:12], seq)

	// rtmsg (12 bytes)
	buf[16] = nlAfInet
	if msgType == rtmGetRoute {
		binary.LittleEndian.PutUint32(buf[0:4], uint32(len(buf)))
		return buf
	}
	if table > 0 && table <= 255 {
		buf[20] = byte(table)
	}
	buf[21] = rtProtBoot
	buf[22] = rtScopeHost
	buf[23] = rtnLocal
	if loIfindex > 0 {
		buf = appendU32Attr(buf, rtaOif, loIfindex)
	}
	if table > 0 {
		buf = appendU32Attr(buf, rtaTable, table)
	}
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(buf)))
	return buf
}

func parseRTAttrs(b []byte, fn func(attrType uint16, val []byte)) {
	for len(b) >= 4 {
		alen := int(binary.LittleEndian.Uint16(b[0:2]))
		atype := binary.LittleEndian.Uint16(b[2:4]) & 0x7fff
		if alen < 4 || alen > len(b) {
			break
		}
		fn(atype, b[4:alen])
		step := nlAlign4(alen)
		if step <= 0 || step > len(b) {
			break
		}
		b = b[step:]
	}
}

func parseIPv4Rules(msgs []byte) []ipv4RuleEntry {
	var out []ipv4RuleEntry
	for len(msgs) >= 16 {
		mlen := int(binary.LittleEndian.Uint32(msgs[0:4]))
		mtype := binary.LittleEndian.Uint16(msgs[4:6])
		if mlen < 16 || mlen > len(msgs) {
			break
		}
		payload := msgs[16:mlen]
		if mtype == rtmNewRule && len(payload) >= 12 && payload[0] == nlAfInet {
			entry := ipv4RuleEntry{
				Table: uint32(payload[4]),
			}
			hasMark := false
			hasMask := false
			parseRTAttrs(payload[12:], func(atype uint16, val []byte) {
				if len(val) < 4 {
					return
				}
				u := binary.LittleEndian.Uint32(val[:4])
				switch atype {
				case fraPriority:
					entry.Pref = u
				case fraFwMark:
					entry.Mark = u
					hasMark = true
				case fraFwMask:
					entry.Mask = u
					hasMask = true
				case fraTable:
					entry.Table = u
				}
			})
			if hasMark && !hasMask {
				entry.Mask = 0xffffffff
			}
			out = append(out, entry)
		}
		step := nlAlign4(mlen)
		if step <= 0 || step > len(msgs) {
			break
		}
		msgs = msgs[step:]
	}
	return out
}

func parseIPv4LocalLoRoutes(msgs []byte, loIfindex, table uint32) bool {
	for len(msgs) >= 16 {
		mlen := int(binary.LittleEndian.Uint32(msgs[0:4]))
		mtype := binary.LittleEndian.Uint16(msgs[4:6])
		if mlen < 16 || mlen > len(msgs) {
			break
		}
		payload := msgs[16:mlen]
		if mtype == rtmNewRoute && len(payload) >= 12 && payload[0] == nlAfInet &&
			payload[1] == 0 && payload[7] == rtnLocal {
			rtTable := uint32(payload[4])
			var oif uint32
			parseRTAttrs(payload[12:], func(atype uint16, val []byte) {
				if len(val) < 4 {
					return
				}
				u := binary.LittleEndian.Uint32(val[:4])
				switch atype {
				case rtaOif:
					oif = u
				case rtaTable:
					rtTable = u
				}
			})
			if rtTable == table && oif == loIfindex {
				return true
			}
		}
		step := nlAlign4(mlen)
		if step <= 0 || step > len(msgs) {
			break
		}
		msgs = msgs[step:]
	}
	return false
}

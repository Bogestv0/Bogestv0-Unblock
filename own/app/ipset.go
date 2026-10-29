package main

// Списки IP-адресов: обход применяется к адресам из списка независимо от имени сайта.

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
)

type ipRange struct{ lo, hi uint32 }

// parseIPList разбирает строки: 1.2.3.4, 10.0.0.0/8, 1.2.3.4-1.2.3.9. Комментарии — после #.
func parseIPList(text string) (rs []ipRange, bad []string) {
	for _, l := range strings.Split(text, "\n") {
		if i := strings.Index(l, "#"); i >= 0 {
			l = l[:i]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if r, ok := parseIPEntry(l); ok {
			rs = append(rs, r)
		} else {
			bad = append(bad, l)
		}
	}
	return mergeRanges(rs), bad
}

func ip4u(s string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(s)).To4()
	if ip == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip), true
}

func parseIPEntry(l string) (ipRange, bool) {
	if i := strings.Index(l, "/"); i >= 0 {
		a, ok := ip4u(l[:i])
		var bits int
		if _, err := fmt.Sscanf(l[i+1:], "%d", &bits); !ok || err != nil || bits < 0 || bits > 32 {
			return ipRange{}, false
		}
		mask := uint32(0)
		if bits > 0 {
			mask = ^uint32(0) << (32 - bits)
		}
		return ipRange{a & mask, a | ^mask}, true
	}
	if i := strings.Index(l, "-"); i >= 0 {
		a, ok1 := ip4u(l[:i])
		b, ok2 := ip4u(l[i+1:])
		if !ok1 || !ok2 || b < a {
			return ipRange{}, false
		}
		return ipRange{a, b}, true
	}
	a, ok := ip4u(l)
	return ipRange{a, a}, ok
}

func mergeRanges(rs []ipRange) []ipRange {
	if len(rs) < 2 {
		return rs
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	out := []ipRange{rs[0]}
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if r.lo <= last.hi+1 && last.hi != ^uint32(0) {
			if r.hi > last.hi {
				last.hi = r.hi
			}
		} else if r.lo > last.hi {
			out = append(out, r)
		}
	}
	return out
}

func hasIP(rs []ipRange, a [4]byte) bool {
	v := binary.BigEndian.Uint32(a[:])
	i := sort.Search(len(rs), func(i int) bool { return rs[i].hi >= v })
	return i < len(rs) && rs[i].lo <= v
}

func ipStr(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", v>>24, byte(v>>16), byte(v>>8), byte(v))
}

// maxFilterRanges — предел диапазонов в фильтре WinDivert (у него ограничен размер выражения).
const maxFilterRanges = 40

func rangesFilter(rs []ipRange) string {
	if len(rs) == 0 {
		return ""
	}
	if len(rs) > maxFilterRanges {
		rs = rs[:maxFilterRanges]
	}
	var parts []string
	for _, r := range rs {
		if r.lo == r.hi {
			parts = append(parts, "ip.DstAddr == "+ipStr(r.lo))
		} else {
			parts = append(parts, fmt.Sprintf("(ip.DstAddr >= %s and ip.DstAddr <= %s)", ipStr(r.lo), ipStr(r.hi)))
		}
	}
	return "((" + strings.Join(parts, " or ") + ") and (tcp.PayloadLength > 0 or udp.PayloadLength > 0))"
}

// fitRanges укрупняет диапазоны (до /24, /16, /8), пока их не станет не больше max —
// иначе они не поместятся в фильтр WinDivert. Сопоставление идёт по тем же укрупнённым диапазонам.
func fitRanges(rs []ipRange, max int) []ipRange {
	rs = mergeRanges(append([]ipRange(nil), rs...))
	for _, mask := range []uint32{0xFFFFFF00, 0xFFFF0000, 0xFF000000} {
		if len(rs) <= max {
			return rs
		}
		for i := range rs {
			rs[i].lo &= mask
			rs[i].hi |= ^mask
		}
		rs = mergeRanges(rs)
	}
	if len(rs) > max {
		rs = rs[:max]
	}
	return rs
}

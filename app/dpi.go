package main

// Ядро обхода: решает, что делать с каждым исходящим пакетом.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"
)

type flowKey struct {
	src, dst [4]byte
	sp, dp   uint16
}

type Core struct {
	st        Strategy
	m         *Matcher
	blockQUIC bool
	flows     map[flowKey]struct{}
	id        uint16
	log       func(string)
	procOf    func(src [4]byte, sport uint16) string // имя exe-файла, которому принадлежит соединение

	TCPHandled atomic.Int64 // соединений, к которым применён обход
	UDPFaked   atomic.Int64 // голосовых потоков с ложными пакетами
	QUICDrop   atomic.Int64 // отброшенных QUIC-пакетов
}

func NewCore(st Strategy, m *Matcher, blockQUIC bool, log func(string)) *Core {
	if log == nil {
		log = func(string) {}
	}
	var b [2]byte
	rand.Read(b[:])
	return &Core{st: st, m: m, blockQUIC: blockQUIC, flows: map[flowKey]struct{}{}, id: binary.BigEndian.Uint16(b[:]), log: log, procOf: tcpOwner}
}

func (c *Core) nextID() uint16 { c.id++; return c.id }

func (c *Core) seen(k flowKey) bool {
	if _, ok := c.flows[k]; ok {
		return true
	}
	if len(c.flows) > 60000 {
		c.flows = map[flowKey]struct{}{}
	}
	c.flows[k] = struct{}{}
	return false
}

// Process получает исходящий пакет. consumed=false — пропустить как есть.
// consumed=true — оригинал не отправлять; вместо него отправить outs по порядку.
func (c *Core) Process(pkt []byte) (outs [][]byte, consumed bool) {
	p, ok := parseIPv4(pkt)
	if !ok {
		return nil, false
	}
	switch p.proto {
	case protoTCP:
		return c.tcp(p)
	case protoUDP:
		return c.udp(p)
	}
	return nil, false
}

func (c *Core) tcp(p *ip4) ([][]byte, bool) {
	if !p.tcpOK() || p.dport() != 443 {
		return nil, false
	}
	pl := p.tcpPayload()
	if len(pl) == 0 {
		return nil, false
	}
	if c.seen(flowKey{p.src(), p.dst(), p.sport(), p.dport()}) {
		return nil, false // только первый пакет с данными (ClientHello)
	}
	host, off, n, ok := parseSNI(pl)
	if !ok {
		return nil, false
	}
	why := ""
	if c.m.Match(host) {
		why = host
	} else if len(c.m.apps) > 0 && c.procOf != nil {
		if exe := c.procOf(p.src(), p.sport()); exe != "" && c.m.apps[exe] {
			why = host + " [" + exe + "]"
		}
	}
	if why == "" {
		return nil, false
	}
	c.TCPHandled.Add(1)
	c.log(fmt.Sprintf("TLS %s → «%s»", why, c.st.Name))

	st := c.st
	seq, flags, ttl := p.seq(), p.tcpFlags(), p.b[8]
	var outs [][]byte

	if st.Fake != "" {
		fake := buildFakeClientHello(or2(st.FakeSNI, "www.google.com"))
		for i := 0; i < max(1, st.FakeRepeat); i++ {
			o := tcpOpts{seq: seq, flags: tcpACK | tcpPSH, id: c.nextID(), ttl: ttl}
			switch st.Fake {
			case "ttl":
				o.ttl = byte(st.FakeTTL)
			case "badsum":
				o.badSum = true
			case "badseq":
				o.seq = seq - 10000 - uint32(i)*1500
			}
			outs = append(outs, buildTCP(p, fake, o))
		}
	}

	k := 0
	switch st.Split {
	case "pos":
		k = st.SplitPos
	case "sni":
		k = off + n/2
	}
	if k <= 0 || k >= len(pl) {
		outs = append(outs, append([]byte(nil), p.b[:p.total]...))
		return outs, true
	}
	p1 := buildTCP(p, pl[:k], tcpOpts{seq: seq, flags: flags &^ (tcpPSH | tcpFIN), id: p.id(), ttl: ttl})
	p2 := buildTCP(p, pl[k:], tcpOpts{seq: seq + uint32(k), flags: flags, id: c.nextID(), ttl: ttl})
	if st.Disorder {
		outs = append(outs, p2, p1)
	} else {
		outs = append(outs, p1, p2)
	}
	return outs, true
}

func (c *Core) udp(p *ip4) ([][]byte, bool) {
	if !p.udpOK() {
		return nil, false
	}
	pl := p.udpPayload()
	if binary.BigEndian.Uint16(p.b[p.ihl+2:]) == 443 { // QUIC → браузер перейдёт на TCP
		if c.blockQUIC {
			c.QUICDrop.Add(1)
			return nil, true
		}
		return nil, false
	}
	isDiscord := len(pl) == 74 && pl[0] == 0 && pl[1] == 1 && pl[2] == 0 && pl[3] == 0x46
	isSTUN := len(pl) >= 20 && pl[0] < 2 && binary.BigEndian.Uint32(pl[4:8]) == 0x2112A442
	if !isDiscord && !isSTUN {
		return nil, false
	}
	port := binary.BigEndian.Uint16(p.b[p.ihl+2:])
	if c.seen(flowKey{p.src(), p.dst(), binary.BigEndian.Uint16(p.b[p.ihl:]), port}) || c.st.UDPFake == 0 {
		return nil, false
	}
	c.UDPFaked.Add(1)
	what := "STUN"
	if isDiscord {
		what = "голос Discord"
	}
	c.log(fmt.Sprintf("UDP %s → ложных пакетов: %d", what, c.st.UDPFake))
	var outs [][]byte
	for i := 0; i < c.st.UDPFake; i++ {
		ttl := p.b[8]
		if c.st.UDPTTL > 0 {
			ttl = byte(c.st.UDPTTL)
		}
		outs = append(outs, buildUDP(p, fakeUDP(c.st.UDPKind, i), c.nextID(), ttl, c.st.UDPBadSum))
	}
	outs = append(outs, append([]byte(nil), p.b[:p.total]...))
	return outs, true
}

func fakeUDP(kind string, i int) []byte {
	var b []byte
	switch kind {
	case "dtls": // выглядит как начало DTLS-рукопожатия
		b = make([]byte, 140+i*7)
		rand.Read(b)
		b[0], b[1], b[2] = 0x16, 0xfe, 0xfd
	case "quic": // выглядит как QUIC Initial
		b = make([]byte, 300+i*11)
		rand.Read(b)
		b[0], b[1], b[2], b[3], b[4] = 0xc0, 0, 0, 0, 1
	default:
		b = make([]byte, 120+i*13)
		rand.Read(b)
	}
	return b
}

func or2(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

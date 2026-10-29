package main

// Разбор и сборка IPv4/TCP/UDP пакетов (собственная реализация).

import (
	"crypto/rand"
	"encoding/binary"
)

type ip4 struct {
	b     []byte // весь пакет
	ihl   int    // длина IP-заголовка
	total int    // общая длина из заголовка
	proto byte
}

const (
	protoTCP = 6
	protoUDP = 17

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

func parseIPv4(b []byte) (*ip4, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(b[0]&15) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || total < ihl || total > len(b) {
		return nil, false
	}
	// фрагменты не трогаем
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return nil, false
	}
	return &ip4{b: b, ihl: ihl, total: total, proto: b[9]}, true
}

func (p *ip4) src() [4]byte { var a [4]byte; copy(a[:], p.b[12:16]); return a }
func (p *ip4) dst() [4]byte { var a [4]byte; copy(a[:], p.b[16:20]); return a }
func (p *ip4) id() uint16   { return binary.BigEndian.Uint16(p.b[4:6]) }

// ---- TCP ----

func (p *ip4) tcpOK() bool   { return p.proto == protoTCP && p.total >= p.ihl+20 }
func (p *ip4) sport() uint16 { return binary.BigEndian.Uint16(p.b[p.ihl:]) }
func (p *ip4) dport() uint16 { return binary.BigEndian.Uint16(p.b[p.ihl+2:]) }
func (p *ip4) seq() uint32   { return binary.BigEndian.Uint32(p.b[p.ihl+4:]) }
func (p *ip4) tcpHdrLen() int {
	return int(p.b[p.ihl+12]>>4) * 4
}
func (p *ip4) tcpFlags() byte { return p.b[p.ihl+13] }

// Данные TCP (nil, если заголовок некорректен).
func (p *ip4) tcpPayload() []byte {
	h := p.tcpHdrLen()
	if h < 20 || p.ihl+h > p.total {
		return nil
	}
	return p.b[p.ihl+h : p.total]
}

// ---- UDP ----

func (p *ip4) udpOK() bool { return p.proto == protoUDP && p.total >= p.ihl+8 }
func (p *ip4) udpPayload() []byte {
	if !p.udpOK() {
		return nil
	}
	return p.b[p.ihl+8 : p.total]
}

// ---- контрольные суммы ----

func csumAdd(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func csumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ipChecksum(h []byte) uint16 { return csumFold(csumAdd(0, h)) }

// Контрольная сумма TCP/UDP с псевдозаголовком; seg — весь сегмент.
func l4Checksum(src, dst []byte, proto byte, seg []byte) uint16 {
	var ph [12]byte
	copy(ph[0:4], src)
	copy(ph[4:8], dst)
	ph[9] = proto
	binary.BigEndian.PutUint16(ph[10:], uint16(len(seg)))
	return csumFold(csumAdd(csumAdd(0, ph[:]), seg))
}

// Проверка сумм (для тестов).
func (p *ip4) checksumsValid() bool {
	if ipChecksum(p.b[:p.ihl]) != 0 {
		return false
	}
	seg := p.b[p.ihl:p.total]
	switch p.proto {
	case protoTCP, protoUDP:
		return l4Checksum(p.b[12:16], p.b[16:20], p.proto, seg) == 0
	}
	return true
}

// ---- сборка ----

type tcpOpts struct {
	seq    uint32
	flags  byte
	id     uint16
	ttl    byte
	badSum bool
	md5    bool // добавить TCP-опцию MD5 (kind 19): сервер без ключа такой пакет отбросит
}

// buildTCP строит пакет на основе orig (копирует заголовки), с новыми данными/seq/флагами.
func buildTCP(orig *ip4, payload []byte, o tcpOpts) []byte {
	th := orig.tcpHdrLen()
	var extra []byte // опция MD5: kind=19, len=18, 16 байт «подписи»; выравниваем до 4 байт
	if o.md5 && th+20 <= 60 {
		extra = make([]byte, 20)
		extra[0], extra[1] = 19, 18
		rand.Read(extra[2:18])
		extra[18], extra[19] = 1, 1 // NOP, NOP
	}
	hl := orig.ihl + th
	out := make([]byte, hl+len(extra)+len(payload))
	copy(out, orig.b[:hl])
	copy(out[hl:], extra)
	copy(out[hl+len(extra):], payload)
	if len(extra) > 0 {
		out[orig.ihl+12] = byte((th+len(extra))/4) << 4
	}
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	binary.BigEndian.PutUint16(out[4:], o.id)
	out[8] = o.ttl
	binary.BigEndian.PutUint32(out[orig.ihl+4:], o.seq)
	out[orig.ihl+13] = o.flags
	finishChecksums(out, orig.ihl, protoTCP, orig.ihl+16, o.badSum)
	return out
}

// buildUDP строит UDP-пакет с теми же адресами/портами, что у orig.
func buildUDP(orig *ip4, payload []byte, id uint16, ttl byte, badSum bool) []byte {
	hl := orig.ihl + 8
	out := make([]byte, hl+len(payload))
	copy(out, orig.b[:hl])
	copy(out[hl:], payload)
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	binary.BigEndian.PutUint16(out[4:], id)
	out[8] = ttl
	binary.BigEndian.PutUint16(out[orig.ihl+4:], uint16(8+len(payload)))
	finishChecksums(out, orig.ihl, protoUDP, orig.ihl+6, badSum)
	return out
}

func finishChecksums(out []byte, ihl int, proto byte, csumOff int, bad bool) {
	out[10], out[11] = 0, 0
	out[csumOff], out[csumOff+1] = 0, 0
	c := l4Checksum(out[12:16], out[16:20], proto, out[ihl:])
	if proto == protoUDP && c == 0 {
		c = 0xffff
	}
	if bad {
		c ^= 0x5a5a
		if c == 0 {
			c = 1
		}
	}
	binary.BigEndian.PutUint16(out[csumOff:], c)
	binary.BigEndian.PutUint16(out[10:], ipChecksum(out[:ihl]))
}

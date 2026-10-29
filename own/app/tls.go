package main

// Разбор TLS ClientHello (SNI) и сборка собственного «ложного» ClientHello.

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
)

// parseSNI возвращает имя сервера и позицию имени в payload. ok=false, если это не ClientHello.
func parseSNI(b []byte) (host string, off, n int, ok bool) {
	if len(b) < 43 || b[0] != 0x16 || b[1] != 0x03 { // handshake, TLS 1.x
		return
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 38 {
		return
	}
	end := 5 + recLen
	if end > len(b) { // ClientHello может быть неполным в этом сегменте — разбираем что есть
		end = len(b)
	}
	if b[5] != 0x01 { // ClientHello
		return
	}
	p := 5 + 4 + 2 + 32 // тип+длина(3)+версия+random
	if p >= end {
		return
	}
	skip := func(lenBytes int) bool {
		if p+lenBytes > end {
			return false
		}
		l := 0
		for i := 0; i < lenBytes; i++ {
			l = l<<8 | int(b[p+i])
		}
		p += lenBytes + l
		return p <= end
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return
	}
	if p+2 > end {
		return
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if extEnd > end {
		extEnd = end
	}
	for p+4 <= extEnd {
		typ := binary.BigEndian.Uint16(b[p:])
		l := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if p+l > extEnd {
			return
		}
		if typ == 0 { // server_name
			// список: длина(2) тип(1) длина имени(2) имя
			if l < 5 || b[p+2] != 0 {
				return
			}
			nl := int(binary.BigEndian.Uint16(b[p+3:]))
			if 5+nl > l {
				return
			}
			off, n = p+5, nl
			return strings.ToLower(string(b[off : off+n])), off, n, true
		}
		p += l
	}
	return
}

// buildFakeClientHello строит правдоподобный ClientHello (TLS 1.3-стиль) с заданным SNI.
func buildFakeClientHello(sni string) []byte {
	rnd := func(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
	u16 := func(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
	ext := func(t int, data []byte) []byte { return append(append(u16(t), u16(len(data))...), data...) }

	var exts []byte
	// server_name
	name := []byte(sni)
	sn := append([]byte{0}, append(u16(len(name)), name...)...)
	exts = append(exts, ext(0, append(u16(len(sn)), sn...))...)
	// supported_groups: x25519, secp256r1, secp384r1
	exts = append(exts, ext(10, append(u16(6), 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18))...)
	// ec_point_formats
	exts = append(exts, ext(11, []byte{1, 0})...)
	// signature_algorithms
	sig := []int{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	var sb []byte
	for _, s := range sig {
		sb = append(sb, u16(s)...)
	}
	exts = append(exts, ext(13, append(u16(len(sb)), sb...))...)
	// ALPN: h2, http/1.1
	alpn := []byte{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	exts = append(exts, ext(16, append(u16(len(alpn)), alpn...))...)
	// supported_versions: TLS1.3, TLS1.2
	exts = append(exts, ext(43, []byte{4, 0x03, 0x04, 0x03, 0x03})...)
	// psk_key_exchange_modes
	exts = append(exts, ext(45, []byte{1, 1})...)
	// key_share: x25519
	ks := append(u16(0x001d), append(u16(32), rnd(32)...)...)
	exts = append(exts, ext(51, append(u16(len(ks)), ks...))...)
	// padding до ~512 байт
	body := func() []byte {
		suites := []int{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
		var cs []byte
		for _, s := range suites {
			cs = append(cs, u16(s)...)
		}
		var h []byte
		h = append(h, 0x03, 0x03)
		h = append(h, rnd(32)...)
		h = append(h, 32)
		h = append(h, rnd(32)...)
		h = append(h, u16(len(cs))...)
		h = append(h, cs...)
		h = append(h, 1, 0)
		return h
	}()
	total := len(body) + 2 + len(exts) + 4 + 4
	if pad := 512 - total; pad > 4 {
		exts = append(exts, ext(21, make([]byte, pad-4))...)
	}
	h := append(body, u16(len(exts))...)
	h = append(h, exts...)
	hs := append([]byte{0x01, byte(len(h) >> 16), byte(len(h) >> 8), byte(len(h))}, h...)
	return append([]byte{0x16, 0x03, 0x01}, append(u16(len(hs)), hs...)...)
}

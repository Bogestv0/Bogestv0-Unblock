package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sort"
	"testing"
)

// Настоящий ClientHello от стандартной библиотеки Go.
func realClientHello(sni string) []byte {
	c1, c2 := net.Pipe()
	go func() { tls.Client(c1, &tls.Config{ServerName: sni}).Handshake(); c1.Close() }()
	buf := make([]byte, 8192)
	n, _ := c2.Read(buf)
	c2.Close()
	return buf[:n]
}

// Собирает тестовый IPv4/TCP-пакет.
func mkTCP(sport, dport uint16, seq uint32, flags byte, payload []byte) []byte {
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 128, protoTCP
	ip[6] = 0x40 // DF
	copy(ip[12:16], []byte{192, 168, 1, 10})
	copy(ip[16:20], []byte{162, 159, 135, 232})
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], 1000)
	tcp[12], tcp[13] = 0x50, flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	pkt := append(append(ip, tcp...), payload...)
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:], 777)
	finishChecksums(pkt, 20, protoTCP, 36, false)
	return pkt
}

func mkUDP(sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 128, protoUDP
	copy(ip[12:16], []byte{192, 168, 1, 10})
	copy(ip[16:20], []byte{5, 6, 7, 8})
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	pkt := append(append(ip, u...), payload...)
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	finishChecksums(pkt, 20, protoUDP, 26, false)
	return pkt
}

func TestParseSNIReal(t *testing.T) {
	for _, h := range []string{"discord.com", "gateway.discord.gg", "www.youtube.com", "a.b.c.example.org"} {
		ch := realClientHello(h)
		host, off, n, ok := parseSNI(ch)
		if !ok || host != h || string(ch[off:off+n]) != h {
			t.Fatalf("%s: got %q ok=%v", h, host, ok)
		}
	}
}

func TestParseSNIOwnFake(t *testing.T) {
	ch := buildFakeClientHello("www.google.com")
	host, _, _, ok := parseSNI(ch)
	if !ok || host != "www.google.com" {
		t.Fatalf("own fake: %q %v", host, ok)
	}
	if len(ch) < 400 || len(ch) > 600 {
		t.Fatalf("fake size %d", len(ch))
	}
	// запись внутри длины TLS
	if int(binary.BigEndian.Uint16(ch[3:5]))+5 != len(ch) {
		t.Fatal("bad record length")
	}
	if _, _, _, ok := parseSNI([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Fatal("http parsed as tls")
	}
	if _, _, _, ok := parseSNI(ch[:30]); ok {
		t.Fatal("truncated parsed")
	}
}

func TestChecksums(t *testing.T) {
	p, ok := parseIPv4(mkTCP(5555, 443, 100, tcpACK|tcpPSH, []byte("hello!!")))
	if !ok || !p.checksumsValid() {
		t.Fatal("tcp checksum invalid")
	}
	u, ok := parseIPv4(mkUDP(5555, 50001, []byte("odd")))
	if !ok || !u.checksumsValid() {
		t.Fatal("udp checksum invalid")
	}
}

func newCore(st Strategy) *Core {
	m := &Matcher{domains: []string{"discord.com", "discord.gg", "youtube.com"}}
	return NewCore(st, m, true, nil)
}

func TestAllStrategiesTCP(t *testing.T) {
	for _, st := range strategies() {
		st := st
		t.Run(st.Name, func(t *testing.T) {
			ch := realClientHello("gateway.discord.gg")
			orig := mkTCP(50000, 443, 0xFFFFFF00, tcpACK|tcpPSH, ch) // seq рядом с переполнением
			c := newCore(st)
			outs, consumed := c.Process(append([]byte(nil), orig...))
			if !consumed || len(outs) == 0 {
				t.Fatal("не обработано")
			}
			type seg struct {
				seq uint32
				pl  []byte
			}
			var real []seg
			fakes := 0
			for _, o := range outs {
				p, ok := parseIPv4(o)
				if !ok {
					t.Fatal("мусор на выходе")
				}
				pl := p.tcpPayload()
				if h, _, _, ok := parseSNI(pl); ok && h == or2(st.FakeSNI, "www.google.com") && st.Fake != "" {
					fakes++
					switch st.Fake {
					case "ttl":
						if int(p.b[8]) != st.FakeTTL {
							t.Fatalf("TTL фейка %d", p.b[8])
						}
						if !p.checksumsValid() {
							t.Fatal("фейк-ttl с плохой суммой")
						}
					case "badsum":
						if p.checksumsValid() {
							t.Fatal("badsum-фейк с верной суммой")
						}
					case "badseq":
						if p.seq() == 0xFFFFFF00 {
							t.Fatal("badseq не сдвинул seq")
						}
					}
					continue
				}
				if !p.checksumsValid() {
					t.Fatalf("плохая сумма у реального сегмента")
				}
				if p.b[8] != 128 {
					t.Fatalf("TTL реального сегмента изменён: %d", p.b[8])
				}
				real = append(real, seg{p.seq(), pl})
			}
			if st.Fake != "" && fakes != max(1, st.FakeRepeat) {
				t.Fatalf("фейков %d, ожидалось %d", fakes, max(1, st.FakeRepeat))
			}
			// сборка потока по seq должна дать исходные данные
			sort.Slice(real, func(i, j int) bool { return real[i].seq-0xFFFFFF00 < real[j].seq-0xFFFFFF00 })
			var got []byte
			next := uint32(0xFFFFFF00)
			for _, s := range real {
				if s.seq != next {
					t.Fatalf("дыра/перекрытие в seq: %d != %d", s.seq, next)
				}
				got = append(got, s.pl...)
				next += uint32(len(s.pl))
			}
			if !bytes.Equal(got, ch) {
				t.Fatal("поток после разрезания не совпал с оригиналом")
			}
			if st.Split != "" && len(real) != 2 {
				t.Fatalf("ожидалось 2 части, получено %d", len(real))
			}
			// порядок отправки
			if st.Split != "" {
				first, _ := parseIPv4(outs[len(outs)-2])
				if st.Disorder == (first.seq() == 0xFFFFFF00) {
					t.Fatalf("неверный порядок отправки (disorder=%v)", st.Disorder)
				}
			}
			// повторный пакет того же потока пропускается как есть
			if _, c2 := c.Process(append([]byte(nil), orig...)); c2 {
				t.Fatal("второй пакет потока не должен обрабатываться")
			}
		})
	}
}

func TestNotMatchedPasses(t *testing.T) {
	c := newCore(strategies()[0])
	pkt := mkTCP(50001, 443, 1, tcpACK|tcpPSH, realClientHello("example.org"))
	if _, consumed := c.Process(pkt); consumed {
		t.Fatal("чужой сайт обработан")
	}
	if _, consumed := c.Process(mkTCP(50002, 80, 1, tcpACK|tcpPSH, realClientHello("discord.com"))); consumed {
		t.Fatal("порт 80 обработан")
	}
	if _, consumed := c.Process(mkTCP(50003, 443, 1, tcpACK, nil)); consumed {
		t.Fatal("пустой ACK обработан")
	}
	c.m.all = true
	if _, consumed := c.Process(mkTCP(50004, 443, 1, tcpACK|tcpPSH, realClientHello("example.org"))); !consumed {
		t.Fatal("режим «все сайты» не сработал")
	}
}

func TestUDP(t *testing.T) {
	st := strategies()[0]
	c := newCore(st)
	disc := make([]byte, 74)
	disc[1], disc[3] = 1, 0x46
	outs, consumed := c.Process(mkUDP(60000, 50010, disc))
	if !consumed || len(outs) != st.UDPFake+1 {
		t.Fatalf("голос: consumed=%v outs=%d", consumed, len(outs))
	}
	for i, o := range outs {
		p, _ := parseIPv4(o)
		if !p.checksumsValid() {
			t.Fatalf("udp %d: плохая сумма", i)
		}
		if i < len(outs)-1 && int(p.b[8]) != st.UDPTTL {
			t.Fatalf("TTL ложного UDP %d", p.b[8])
		}
	}
	last, _ := parseIPv4(outs[len(outs)-1])
	if !bytes.Equal(last.udpPayload(), disc) || last.b[8] != 128 {
		t.Fatal("настоящий пакет искажён")
	}
	// повтор того же потока пропускается
	if _, c2 := c.Process(mkUDP(60000, 50010, disc)); c2 {
		t.Fatal("повтор потока")
	}
	// QUIC
	if _, cons := c.Process(mkUDP(60001, 443, make([]byte, 1200))); !cons {
		t.Fatal("QUIC не отброшен")
	}
	c.blockQUIC = false
	if _, cons := c.Process(mkUDP(60002, 443, make([]byte, 1200))); cons {
		t.Fatal("QUIC отброшен при выключенной опции")
	}
	// обычный UDP не трогаем
	if _, cons := c.Process(mkUDP(60003, 50011, []byte("hello"))); cons {
		t.Fatal("чужой UDP обработан")
	}
	// STUN
	stun := make([]byte, 20)
	stun[1] = 1
	binary.BigEndian.PutUint32(stun[4:], 0x2112A442)
	if _, cons := c.Process(mkUDP(60004, 3478, stun)); !cons {
		t.Fatal("STUN не обработан")
	}
}

func TestGarbageDoesNotPanic(t *testing.T) {
	c := newCore(strategies()[0])
	for _, b := range [][]byte{nil, {1}, make([]byte, 19), make([]byte, 60), append([]byte{0x45, 0, 0xff, 0xff}, make([]byte, 40)...)} {
		c.Process(b)
	}
}

func TestSNIMid(t *testing.T) {
	// «разрез по имени сайта»: граница должна попасть внутрь имени
	ch := realClientHello("gateway.discord.gg")
	_, off, n, _ := parseSNI(ch)
	st := strategies()[2]
	outs, _ := newCore(st).Process(mkTCP(50007, 443, 1, tcpACK|tcpPSH, ch))
	p1, _ := parseIPv4(outs[0])
	k := len(p1.tcpPayload())
	if !(k > off && k < off+n) {
		t.Fatalf("граница %d вне имени [%d,%d)", k, off, off+n)
	}
}

func TestAppsMatch(t *testing.T) {
	c := newCore(strategies()[0])
	c.m.apps = map[string]bool{"tg.exe": true}
	c.procOf = func(src [4]byte, sp uint16) string {
		if sp == 5001 {
			return "tg.exe"
		}
		return "other.exe"
	}
	ch := buildFakeClientHello("example.org") // не из списка
	if outs, ok := c.Process(mkTCP(5002, 443, 1, tcpACK|tcpPSH, ch)); ok || outs != nil {
		t.Fatal("чужая программа не должна обрабатываться")
	}
	if _, ok := c.Process(mkTCP(5001, 443, 1, tcpACK|tcpPSH, ch)); !ok {
		t.Fatal("выбранная программа должна обрабатываться")
	}
}

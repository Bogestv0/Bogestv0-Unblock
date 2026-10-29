package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sort"
	"strings"
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
					if st.fakeHas("ttl") && int(p.b[8]) != st.FakeTTL {
						t.Fatalf("TTL фейка %d", p.b[8])
					}
					if st.fakeHas("badsum") == p.checksumsValid() {
						t.Fatalf("badsum=%v, а сумма верна=%v", st.fakeHas("badsum"), p.checksumsValid())
					}
					if st.fakeHas("badseq") == (p.seq() == 0xFFFFFF00) {
						t.Fatal("badseq и seq не согласованы")
					}
					if !st.fakeHas("badseq") && p.seq() != 0xFFFFFF00 {
						t.Fatal("seq фейка не должен меняться")
					}
					if !st.fakeHas("ttl") && p.b[8] != 128 {
						t.Fatalf("TTL фейка без ttl-приёма изменён: %d", p.b[8])
					}
					hasMD5 := p.tcpHdrLen() > 20 && bytes.Contains(p.b[p.ihl+20:p.ihl+p.tcpHdrLen()], []byte{19, 18})
					if st.fakeHas("md5sig") != hasMD5 {
						t.Fatalf("md5sig=%v, опция в заголовке=%v", st.fakeHas("md5sig"), hasMD5)
					}
					if p.tcpHdrLen()%4 != 0 || p.ihl+p.tcpHdrLen() > p.total {
						t.Fatal("заголовок TCP фейка испорчен")
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
			wantParts := 1
			if st.Split != "" {
				wantParts = 2
				if st.Split == "pos" && st.AlsoSNI {
					wantParts = 3
				}
			}
			if len(real) != wantParts {
				t.Fatalf("ожидалось частей %d, получено %d", wantParts, len(real))
			}
			// порядок отправки: настоящие части идут в конце, по возрастанию seq или (disorder) по убыванию
			if wantParts > 1 {
				var seqs []uint32
				for _, o := range outs[len(outs)-wantParts:] {
					p, _ := parseIPv4(o)
					seqs = append(seqs, p.seq()-0xFFFFFF00)
				}
				if st.Disorder != sort.SliceIsSorted(seqs, func(i, j int) bool { return seqs[i] > seqs[j] }) {
					t.Fatalf("неверный порядок отправки (disorder=%v): %v", st.Disorder, seqs)
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

func TestSNICutInsideMainDomain(t *testing.T) {
	// длинное имя googlevideo: граница обязана попасть внутрь слова «googlevideo», а не в поддомен
	for _, h := range []string{"rr3---sn-8ph2xajvh-n8vs.googlevideo.com", "redirector.googlevideo.com", "www.youtube.com", "gateway.discord.gg", "cdn.discordapp.com", "t.me"} {
		ch := realClientHello(h)
		host, off, n, ok := parseSNI(ch)
		if !ok || host != h {
			t.Fatalf("SNI %q не разобран", h)
		}
		k := sniCut(host, off, n)
		dot := strings.LastIndexByte(h, '.')
		start := strings.LastIndexByte(h[:dot], '.') + 1
		if k < off+start || k > off+dot {
			t.Fatalf("%s: граница %d вне главного домена [%d,%d]", h, k, off+start, off+dot)
		}
		if dot-start >= 2 && (k == off+start || k == off+dot) {
			t.Fatalf("%s: граница на краю слова", h)
		}
	}
}

func TestStrategyNamesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range strategies() {
		if seen[s.Name] {
			t.Fatalf("повтор имени %q", s.Name)
		}
		seen[s.Name] = true
	}
}

func TestMD5OptionKeepsPacketValid(t *testing.T) {
	ch := realClientHello("www.youtube.com")
	orig, _ := parseIPv4(mkTCP(50100, 443, 5, tcpACK|tcpPSH, ch))
	out := buildTCP(orig, ch[:100], tcpOpts{seq: 5, flags: tcpACK, id: 1, ttl: 64, md5: true})
	p, ok := parseIPv4(out)
	if !ok || !p.checksumsValid() || p.tcpHdrLen() != 40 || len(p.tcpPayload()) != 100 {
		t.Fatalf("md5-пакет некорректен: hdr=%d pl=%d", p.tcpHdrLen(), len(p.tcpPayload()))
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

func TestIPListParse(t *testing.T) {
	rs, bad := parseIPList("1.2.3.4\n10.0.0.0/8 # сеть\n5.5.5.5-5.5.5.9\nмусор\n10.1.0.0/16\n300.1.1.1\n")
	if len(bad) != 2 || len(rs) != 3 {
		t.Fatalf("rs=%v bad=%v", rs, bad)
	}
	if !hasIP(rs, [4]byte{10, 200, 1, 1}) || !hasIP(rs, [4]byte{5, 5, 5, 7}) || hasIP(rs, [4]byte{5, 5, 5, 10}) || hasIP(rs, [4]byte{1, 2, 3, 5}) {
		t.Fatal("hasIP")
	}
	f := buildFilter(true, "apps", rs)
	if !strings.Contains(f, "ip.DstAddr >= 10.0.0.0 and ip.DstAddr <= 10.255.255.255") || !strings.Contains(f, "tcp.DstPort >= 1024") {
		t.Fatal(f)
	}
}

func TestGameAndIPSet(t *testing.T) {
	st := strategies()[0]
	st.UDPFake = 2
	mk := func(game string, ips []ipRange) *Core {
		m := &Matcher{domains: []string{"discord.com"}, game: game, ips: ips, apps: map[string]bool{"g.exe": true}}
		c := NewCore(st, m, true, nil)
		c.procOf = func(src [4]byte, sp uint16) string {
			if sp == 6001 {
				return "g.exe"
			}
			return "x.exe"
		}
		c.udpProcOf = c.procOf
		return c
	}
	game := []byte("GAMEPROTO-handshake-data-1234567890")
	// выключено: порт 27015 не трогаем
	if _, ok := mk("off", nil).Process(mkTCP(6001, 27015, 1, tcpACK|tcpPSH, game)); ok {
		t.Fatal("off обработал")
	}
	// только программы
	c := mk("apps", nil)
	if outs, ok := c.Process(mkTCP(6001, 27015, 1, tcpACK|tcpPSH, game)); !ok || len(outs) < 2 {
		t.Fatal("apps: программа не обработана")
	}
	if _, ok := c.Process(mkTCP(6002, 27015, 1, tcpACK|tcpPSH, game)); ok {
		t.Fatal("apps: чужая программа обработана")
	}
	if outs, ok := c.Process(mkUDP(6001, 30000, game)); !ok || len(outs) != 3 {
		t.Fatalf("apps udp: %d %v", len(outs), ok)
	}
	if _, ok := c.Process(mkUDP(6002, 30000, game)); ok {
		t.Fatal("apps udp: чужая")
	}
	// все
	c = mk("all", nil)
	if _, ok := c.Process(mkUDP(6002, 30001, game)); !ok {
		t.Fatal("all udp")
	}
	if _, ok := c.Process(mkUDP(6002, 53, game)); ok {
		t.Fatal("DNS тронут")
	}
	// список IP: mkTCP/mkUDP шлют на 1.2.3.4?
	pk := mkUDP(6003, 40000, game)
	p, _ := parseIPv4(pk)
	d := p.dst()
	rs, _ := parseIPList(ipStr(uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])))
	c = mk("off", rs)
	if _, ok := c.Process(pk); !ok {
		t.Fatal("ipset udp")
	}
	rt, _ := parseIPList("162.159.135.0/24")
	c = mk("off", rt)
	if _, ok := c.Process(mkTCP(6003, 9999, 1, tcpACK|tcpPSH, game)); !ok {
		t.Fatal("ipset tcp")
	}
	if _, ok := c.Process(mkTCP(6004, 9999, 1, tcpACK|tcpPSH, game)); !ok {
		t.Fatal("ipset tcp 2")
	}
}

func TestFitRanges(t *testing.T) {
	var rs []ipRange
	for i := 0; i < 200; i++ { // 200 разрозненных адресов в 100 разных /24
		v := uint32(10)<<24 | uint32(i/2)<<16 | uint32(i%2)<<8 | 7
		rs = append(rs, ipRange{v, v})
	}
	out := fitRanges(rs, maxFilterRanges)
	if len(out) > maxFilterRanges || len(out) == 0 {
		t.Fatalf("диапазонов: %d", len(out))
	}
	for _, r := range rs {
		if !hasIP(out, [4]byte{byte(r.lo >> 24), byte(r.lo >> 16), byte(r.lo >> 8), byte(r.lo)}) {
			t.Fatal("адрес потерян при укрупнении")
		}
	}
	few := []ipRange{{1, 1}, {100, 200}}
	if got := fitRanges(few, 40); len(got) != 2 || got[0].lo != 1 {
		t.Fatalf("малый список изменён: %v", got)
	}
}

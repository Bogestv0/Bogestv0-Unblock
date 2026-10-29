package main

import "strings"

// Собственные стратегии обхода. Каждая — набор приёмов для TLS (TCP/443) и UDP (голос).

type Strategy struct {
	Name string `json:"name"`

	// TCP: разрезание первого пакета TLS ClientHello
	Split    string // "" (не резать) | "pos" (по смещению) | "sni" (внутри имени сайта, в середине главного домена)
	SplitPos int    // для "pos": смещение в байтах
	AlsoSNI  bool   // вдобавок к "pos" разрезать ещё и внутри имени сайта (получается три части)
	Disorder bool   // отправить части в обратном порядке

	// TCP: ложный ClientHello перед настоящим. Приёмы можно соединять через «+»:
	// "ttl" (умирает по пути), "badsum" (неверная сумма), "badseq" (seq из прошлого),
	// "md5sig" (TCP-опция MD5: сервер такой пакет отбрасывает, а провайдерский DPI читает).
	Fake       string
	FakeTTL    int
	FakeRepeat int
	FakeSNI    string

	// UDP: ложные пакеты перед первым пакетом голоса/STUN
	UDPFake   int
	UDPKind   string // "random" | "dtls" | "quic"
	UDPTTL    int    // 0 — обычный TTL
	UDPBadSum bool
}

// fakeHas: входит ли приём в строку Fake.
func (s Strategy) fakeHas(kind string) bool {
	for _, k := range strings.Split(s.Fake, "+") {
		if k == kind {
			return true
		}
	}
	return false
}

func strategies() []Strategy {
	return []Strategy{
		// --- без ложных пакетов: только разрезание ---
		{Name: "Разрез 1", Split: "pos", SplitPos: 1, UDPFake: 4, UDPKind: "random", UDPTTL: 5},
		{Name: "Разрез 2", Split: "pos", SplitPos: 2, UDPFake: 4, UDPKind: "dtls", UDPTTL: 5},
		{Name: "Разрез по имени сайта", Split: "sni", UDPFake: 4, UDPKind: "random", UDPTTL: 6},
		{Name: "Разрез 1 + имя сайта", Split: "pos", SplitPos: 1, AlsoSNI: true, UDPFake: 4, UDPKind: "random", UDPTTL: 5},
		{Name: "Разрез 1, обратный порядок", Split: "pos", SplitPos: 1, Disorder: true, UDPFake: 4, UDPKind: "random", UDPTTL: 5},
		{Name: "Имя сайта, обратный порядок", Split: "sni", Disorder: true, UDPFake: 4, UDPKind: "dtls", UDPTTL: 6},
		{Name: "Разрез 1 + имя сайта, обратный порядок", Split: "pos", SplitPos: 1, AlsoSNI: true, Disorder: true, UDPFake: 4, UDPKind: "dtls", UDPTTL: 6},

		// --- ложный пакет, который сервер отбрасывает без оглядки на TTL (чаще всего рабочие у российских провайдеров) ---
		{Name: "Ложный md5 + разрез 1", Split: "pos", SplitPos: 1, Fake: "md5sig", FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPTTL: 5},
		{Name: "Ложный md5 + имя сайта, обратный", Split: "sni", Disorder: true, Fake: "md5sig", FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "dtls", UDPTTL: 6},
		{Name: "Ложный md5+seq, разрез 1 + имя, обратный", Split: "pos", SplitPos: 1, AlsoSNI: true, Disorder: true, Fake: "badseq+md5sig", FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "quic", UDPTTL: 5},
		{Name: "Ложный seq + разрез 1 + имя, обратный", Split: "pos", SplitPos: 1, AlsoSNI: true, Disorder: true, Fake: "badseq", FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPTTL: 5},
		{Name: "Ложный md5, только ложный пакет", Fake: "md5sig", FakeRepeat: 3, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPTTL: 5},

		// --- ложный пакет с малым TTL (до сервера не доходит; нужное значение зависит от расстояния до оборудования провайдера) ---
		{Name: "Ложный TTL 4 + разрез 1", Split: "pos", SplitPos: 1, Fake: "ttl", FakeTTL: 4, FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPTTL: 4},
		{Name: "Ложный TTL 6 + разрез 1", Split: "pos", SplitPos: 1, Fake: "ttl", FakeTTL: 6, FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "dtls", UDPTTL: 6},
		{Name: "Ложный TTL 8 + имя сайта", Split: "sni", Fake: "ttl", FakeTTL: 8, FakeRepeat: 2, FakeSNI: "www.microsoft.com", UDPFake: 6, UDPKind: "quic", UDPTTL: 8},
		{Name: "Ложный TTL 3 ×3 + имя сайта", Split: "sni", Fake: "ttl", FakeTTL: 3, FakeRepeat: 3, FakeSNI: "www.google.com", UDPFake: 8, UDPKind: "random", UDPTTL: 3},
		{Name: "Ложный TTL 5, обратный порядок", Split: "pos", SplitPos: 1, Disorder: true, Fake: "ttl", FakeTTL: 5, FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPTTL: 5},
		{Name: "Ложный TTL 4 + разрез 1 + имя, обратный", Split: "pos", SplitPos: 1, AlsoSNI: true, Disorder: true, Fake: "ttl", FakeTTL: 4, FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPTTL: 4},
		{Name: "Ложный TTL 7 + разрез 1 + имя, обратный", Split: "pos", SplitPos: 1, AlsoSNI: true, Disorder: true, Fake: "ttl", FakeTTL: 7, FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "dtls", UDPTTL: 7},
		{Name: "Ложный TTL 10 + имя сайта, обратный", Split: "sni", Disorder: true, Fake: "ttl", FakeTTL: 10, FakeRepeat: 2, FakeSNI: "www.microsoft.com", UDPFake: 6, UDPKind: "quic", UDPTTL: 10},
		{Name: "Только ложный TTL 5", Fake: "ttl", FakeTTL: 5, FakeRepeat: 3, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPTTL: 5},

		// --- неверная контрольная сумма / номер последовательности ---
		{Name: "Ложная сумма + разрез 1", Split: "pos", SplitPos: 1, Fake: "badsum", FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPBadSum: true},
		{Name: "Ложная сумма + имя, обратный", Split: "sni", Disorder: true, Fake: "badsum", FakeRepeat: 2, FakeSNI: "www.microsoft.com", UDPFake: 6, UDPKind: "dtls", UDPBadSum: true},
		{Name: "Ложный seq + разрез 1", Split: "pos", SplitPos: 1, Fake: "badseq", FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "quic", UDPTTL: 5},
		{Name: "Только ложная сумма", Fake: "badsum", FakeRepeat: 3, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPBadSum: true},
	}
}

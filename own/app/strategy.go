package main

// Собственные стратегии обхода. Каждая — набор приёмов для TLS (TCP/443) и UDP (голос).

type Strategy struct {
	Name string `json:"name"`

	// TCP: разрезание первого пакета TLS ClientHello
	Split    string // "" (не резать) | "pos" (по смещению) | "sni" (внутри имени сайта)
	SplitPos int    // для "pos": смещение в байтах
	Disorder bool   // отправить вторую часть раньше первой

	// TCP: ложный ClientHello перед настоящим
	Fake       string // "" | "ttl" | "badsum" | "badseq"
	FakeTTL    int
	FakeRepeat int
	FakeSNI    string

	// UDP: ложные пакеты перед первым пакетом голоса/STUN
	UDPFake   int
	UDPKind   string // "random" | "dtls" | "quic"
	UDPTTL    int    // 0 — обычный TTL
	UDPBadSum bool
}

func strategies() []Strategy {
	return []Strategy{
		{Name: "Разрез 1", Split: "pos", SplitPos: 1, UDPFake: 4, UDPKind: "random", UDPTTL: 5},
		{Name: "Разрез 2", Split: "pos", SplitPos: 2, UDPFake: 4, UDPKind: "dtls", UDPTTL: 5},
		{Name: "Разрез по имени сайта", Split: "sni", UDPFake: 4, UDPKind: "random", UDPTTL: 6},
		{Name: "Разрез 1, обратный порядок", Split: "pos", SplitPos: 1, Disorder: true, UDPFake: 4, UDPKind: "random", UDPTTL: 5},
		{Name: "Имя сайта, обратный порядок", Split: "sni", Disorder: true, UDPFake: 4, UDPKind: "dtls", UDPTTL: 6},
		{Name: "Ложный TTL 4 + разрез 1", Split: "pos", SplitPos: 1, Fake: "ttl", FakeTTL: 4, FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPTTL: 4},
		{Name: "Ложный TTL 6 + разрез 1", Split: "pos", SplitPos: 1, Fake: "ttl", FakeTTL: 6, FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "dtls", UDPTTL: 6},
		{Name: "Ложный TTL 8 + имя сайта", Split: "sni", Fake: "ttl", FakeTTL: 8, FakeRepeat: 2, FakeSNI: "www.microsoft.com", UDPFake: 6, UDPKind: "quic", UDPTTL: 8},
		{Name: "Ложный TTL 3 ×3 + имя сайта", Split: "sni", Fake: "ttl", FakeTTL: 3, FakeRepeat: 3, FakeSNI: "www.google.com", UDPFake: 8, UDPKind: "random", UDPTTL: 3},
		{Name: "Ложная сумма + разрез 1", Split: "pos", SplitPos: 1, Fake: "badsum", FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPBadSum: true},
		{Name: "Ложная сумма + имя, обратный", Split: "sni", Disorder: true, Fake: "badsum", FakeRepeat: 2, FakeSNI: "www.microsoft.com", UDPFake: 6, UDPKind: "dtls", UDPBadSum: true},
		{Name: "Ложный seq + разрез 1", Split: "pos", SplitPos: 1, Fake: "badseq", FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "quic", UDPTTL: 5},
		{Name: "Ложный TTL 5, обратный порядок", Split: "pos", SplitPos: 1, Disorder: true, Fake: "ttl", FakeTTL: 5, FakeRepeat: 2, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPTTL: 5},
		{Name: "Только ложный TTL 5", Fake: "ttl", FakeTTL: 5, FakeRepeat: 3, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPTTL: 5},
		{Name: "Только ложная сумма", Fake: "badsum", FakeRepeat: 3, FakeSNI: "www.google.com", UDPFake: 6, UDPKind: "random", UDPBadSum: true},
	}
}

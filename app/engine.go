package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Settings struct {
	Strategy    string   `json:"strategy"`
	AutoEnable  bool     `json:"autoEnable"` // включать обход при запуске программы
	AutoStart   bool     `json:"autoStart"`  // запускать при входе в Windows
	Discord     bool     `json:"discord"`
	YouTube     bool     `json:"youtube"`
	AllSites    bool     `json:"allSites"`    // применять ко всем HTTPS-сайтам
	BlockQUIC   bool     `json:"blockQuic"`   // отбрасывать QUIC (UDP 443): сайты перейдут на TCP
	GameMode    string   `json:"gameMode"`    // off | apps | all — перехват не только 443-го порта
	IPSet       bool     `json:"ipSet"`       // применять обход к адресам из списка IP
	SkipVersion string   `json:"skipVersion"` // версию, от которой отказались («Позже»)
	DNSSet      bool     `json:"dnsSet"`      // мы меняли DNS (вернуть при удалении)
	Apps        []string `json:"apps"`        // программы (имена exe), для которых обход применяется ко всем сайтам
}

type Engine struct {
	mu         sync.Mutex
	base       string
	strategies []Strategy
	runner     *Runner
	active     string
	since      time.Time
	settings   Settings
	tune       *TuneState
	lmu        sync.Mutex // отдельный замок для журнала (чтобы не блокироваться при остановке)
	logBuf     []string
}

func NewEngine(base string) (*Engine, error) {
	e := &Engine{base: base, strategies: strategies()}
	e.settings = Settings{Discord: true, YouTube: true, BlockQUIC: true}
	if b, err := os.ReadFile(filepath.Join(base, "settings.json")); err == nil {
		json.Unmarshal(b, &e.settings)
	}
	if e.find(e.settings.Strategy) == nil {
		e.settings.Strategy = e.strategies[0].Name
	}
	os.MkdirAll(filepath.Join(base, "lists"), 0o755)
	return e, nil
}

func (e *Engine) find(name string) *Strategy {
	for i := range e.strategies {
		if e.strategies[i].Name == name {
			return &e.strategies[i]
		}
	}
	return nil
}

func (e *Engine) saveSettings() {
	b, _ := json.MarshalIndent(e.settings, "", " ")
	os.WriteFile(filepath.Join(e.base, "settings.json"), b, 0o644)
}

func (e *Engine) logf(s string) { e.logLocked(s) }

func (e *Engine) logLocked(s string) {
	e.lmu.Lock()
	defer e.lmu.Unlock()
	e.logBuf = append(e.logBuf, time.Now().Format("15:04:05 ")+s)
	if len(e.logBuf) > 200 {
		e.logBuf = e.logBuf[len(e.logBuf)-200:]
	}
}

func (e *Engine) LogText() string {
	e.lmu.Lock()
	defer e.lmu.Unlock()
	if len(e.logBuf) > 40 {
		return strings.Join(e.logBuf[len(e.logBuf)-40:], "\n")
	}
	return strings.Join(e.logBuf, "\n")
}

func (e *Engine) Start(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.startLocked(name)
}

func (e *Engine) startLocked(name string) error {
	st := e.find(name)
	if st == nil {
		return fmt.Errorf("стратегия «%s» не найдена", name)
	}
	e.stopLocked()
	m := newMatcher(e.base, e.settings)
	r, err := StartRunner(e.base, *st, m, e.settings.BlockQUIC, e.logf)
	if err != nil {
		e.logLocked("ошибка запуска: " + err.Error())
		return err
	}
	e.runner, e.active, e.since = r, name, time.Now()
	e.logLocked("запущено: «" + name + "»")
	return nil
}

func (e *Engine) Stop() { e.mu.Lock(); defer e.mu.Unlock(); e.stopLocked() }

func (e *Engine) stopLocked() {
	if e.runner != nil {
		e.runner.Stop()
		e.logLocked("остановлено")
	}
	e.runner, e.active = nil, ""
	releaseDriver()
}

// Running сообщает состояние и счётчики.
func (e *Engine) Running() (bool, string, time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.runner != nil {
		select {
		case <-e.runner.Done():
			e.runner, e.active = nil, ""
		default:
		}
	}
	return e.runner != nil, e.active, e.since
}

func (e *Engine) Stats() map[string]int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.runner == nil {
		return map[string]int64{}
	}
	c := e.runner.core
	return map[string]int64{"tcp": c.TCPHandled.Load(), "udp": c.UDPFaked.Load(), "quic": c.QUICDrop.Load()}
}

/* ---------------- проверка доступности ---------------- */

type Target struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	URL   string `json:"url"`
}

var Targets = []Target{
	{"Discord", "discord.com", "https://discord.com/api/v10/gateway"},
	{"Discord", "gateway", "https://gateway.discord.gg/?v=10&encoding=json"},
	{"Discord", "cdn", "https://cdn.discordapp.com/"},
	{"Discord", "updates", "https://updates.discord.com/"},
	{"YouTube", "youtube.com", "https://www.youtube.com/"},
	{"YouTube", "картинки", "https://i.ytimg.com/generate_204"},
	{"YouTube", "видео", "https://redirector.googlevideo.com/"},
}

type CheckResult struct {
	Target
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
	MS  int64  `json:"ms"`
}

// только для тестов разработчика: BOGESTV0_FAKE=<имя стратегии> имитирует «работает только эта стратегия»
var fakeGood = os.Getenv("BOGESTV0_FAKE")

func check(ctx context.Context, t Target) CheckResult {
	r := CheckResult{Target: t}
	if fakeGood != "" {
		time.Sleep(40 * time.Millisecond)
		run, name, _ := engine.Running()
		r.OK = run && name == fakeGood
		if !r.OK {
			r.Err = "таймаут"
		}
		return r
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	cl := &http.Client{Transport: tr, Timeout: 7 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", t.URL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Bogestv0Unblock")
	t0 := time.Now()
	resp, err := cl.Do(req)
	r.MS = time.Since(t0).Milliseconds()
	if err != nil {
		r.Err = shortErr(err)
		return r
	}
	resp.Body.Close()
	r.OK = true // любой HTTP-ответ: соединение и TLS прошли
	return r
}

func shortErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "no such host"), strings.Contains(s, "lookup "):
		return "DNS: имя не найдено"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"):
		return "таймаут"
	case strings.Contains(s, "reset"):
		return "соединение сброшено"
	case strings.Contains(s, "EOF"):
		return "обрыв"
	}
	if len(s) > 60 {
		s = s[len(s)-60:]
	}
	return s
}

func checkAll(ctx context.Context) []CheckResult {
	res := make([]CheckResult, len(Targets))
	var wg sync.WaitGroup
	for i, t := range Targets {
		wg.Add(1)
		go func(i int, t Target) { defer wg.Done(); res[i] = check(ctx, t) }(i, t)
	}
	wg.Wait()
	return res
}

func score(res []CheckResult) (discord, total int) {
	for _, r := range res {
		if r.OK {
			total++
			if r.Group == "Discord" {
				discord++
			}
		}
	}
	return
}

/* ---------------- автоподбор ---------------- */

type TuneItem struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pending | testing | ok | part | fail
	Score  int    `json:"score"`
}

type TuneState struct {
	Running bool       `json:"running"`
	Done    bool       `json:"done"`
	Msg     string     `json:"msg"`
	Items   []TuneItem `json:"items"`
	Best    string     `json:"best"`
	cancel  context.CancelFunc
}

func (e *Engine) TuneStatus() TuneState {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tune == nil {
		return TuneState{}
	}
	t := *e.tune
	t.Items = append([]TuneItem(nil), e.tune.Items...)
	return t
}

func (e *Engine) StartTune() error {
	e.mu.Lock()
	if e.tune != nil && e.tune.Running {
		e.mu.Unlock()
		return errors.New("подбор уже идёт")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &TuneState{Running: true, Msg: "Проверяю без обхода…", cancel: cancel}
	for _, s := range e.strategies {
		t.Items = append(t.Items, TuneItem{Name: s.Name, Status: "pending"})
	}
	e.tune = t
	e.mu.Unlock()
	go e.runTune(ctx, t)
	return nil
}

func (e *Engine) CancelTune() {
	e.mu.Lock()
	if e.tune != nil && e.tune.cancel != nil {
		e.tune.cancel()
	}
	e.mu.Unlock()
}

func (e *Engine) runTune(ctx context.Context, t *TuneState) {
	set := func(f func()) { e.mu.Lock(); f(); e.mu.Unlock() }
	finish := func(msg string) { set(func() { t.Running, t.Done, t.Msg = false, true, msg }) }
	e.Stop()
	nd := 0
	for _, x := range Targets {
		if x.Group == "Discord" {
			nd++
		}
	}
	base := checkAll(ctx)
	if d, _ := score(base); d == nd {
		finish("Discord и так открывается без обхода — включать его не нужно.")
		return
	}
	dnsFail := 0
	for _, r := range base {
		if strings.HasPrefix(r.Err, "DNS") {
			dnsFail++
		}
	}
	if dnsFail*2 >= len(base) {
		finish("Адреса сайтов не находятся: провайдер блокирует DNS. Нажмите «Исправить DNS» в блоке ниже и повторите подбор.")
		set(func() { t.Items = nil })
		return
	}
	bestName, bestScore := "", 0
	for i := range e.strategies {
		if ctx.Err() != nil {
			e.Stop()
			finish("Подбор остановлен.")
			return
		}
		name := e.strategies[i].Name
		set(func() {
			t.Items[i].Status = "testing"
			t.Msg = fmt.Sprintf("Пробую «%s» (%d из %d)…", name, i+1, len(e.strategies))
		})
		if err := e.Start(name); err != nil {
			e.Stop()
			set(func() { t.Items[i].Status = "fail" })
			finish("Не удалось запустить перехват пакетов: " + err.Error())
			return
		}
		time.Sleep(500 * time.Millisecond)
		d, tot := score(checkAll(ctx))
		sc := d*2 + tot
		st := "fail"
		if d == nd {
			st = "ok"
		} else if d > 0 {
			st = "part"
		}
		set(func() { t.Items[i].Status, t.Items[i].Score = st, sc })
		if sc > bestScore {
			bestScore, bestName = sc, name
		}
		if d == nd && tot == len(Targets) {
			break
		}
	}
	if bestName == "" {
		e.Stop()
		finish("Ни одна стратегия не сработала. Проверьте интернет и смените DNS (например, на 1.1.1.1), затем повторите подбор.")
		return
	}
	if err := e.Start(bestName); err != nil {
		finish("Нашёл «" + bestName + "», но запустить не удалось: " + err.Error())
		return
	}
	set(func() { e.settings.Strategy = bestName; e.saveSettings(); t.Best = bestName })
	finish("Готово! Выбрана стратегия «" + bestName + "» — обход включён.")
}

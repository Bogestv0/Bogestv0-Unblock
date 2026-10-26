// Bogestv0 Unblock — управление обходом блокировок (собственный движок) с окном в браузере.
package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed ui/index.html
var indexHTML string

const (
	port    = "47821"
	version = "2.2.0"
)

var (
	engine *Engine
	token  string
	base   string
)

func main() {
	exe, _ := os.Executable()
	base = filepath.Dir(exe)
	if d := os.Getenv("BOGESTV0_BASE"); d != "" {
		base = d
	}
	args := strings.Join(os.Args[1:], " ")
	switch {
	case strings.Contains(args, "--serve"):
		serve(strings.Contains(args, "--background"))
	case strings.Contains(args, "--uninstall-cleanup"):
		cleanup()
	default:
		launcher()
	}
}

// Обычный запуск (ярлык): убедиться, что сервер работает, открыть окно.
func launcher() {
	if !ping() {
		if err := runServerElevated(); err != nil {
			os.Exit(1)
		}
		for i := 0; i < 60 && !ping(); i++ {
			time.Sleep(250 * time.Millisecond)
		}
	}
	openUI("http://127.0.0.1:" + port + "/")
}

func ping() bool {
	cl := http.Client{Timeout: 700 * time.Millisecond}
	r, err := cl.Get("http://127.0.0.1:" + port + "/ping")
	if err != nil {
		return false
	}
	r.Body.Close()
	return r.StatusCode == 200
}

func serve(background bool) {
	if !isAdmin() {
		runServerElevatedSelf(background)
		return
	}
	var err error
	if engine, err = NewEngine(base); err != nil {
		fatalBox("Bogestv0 Unblock", "Не удалось запуститься: "+err.Error())
		return
	}
	b := make([]byte, 16)
	rand.Read(b)
	token = hex.EncodeToString(b)
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		return // уже запущено
	}
	if engine.settings.AutoEnable {
		go engine.Start(engine.settings.Strategy)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/", handleAPI)
	srv := &http.Server{Handler: mux}
	srv.Serve(ln)
}

func hostOK(r *http.Request) bool {
	return r.Host == "127.0.0.1:"+port || r.Host == "localhost:"+port
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" || !hostOK(r) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(strings.Replace(indexHTML, "__TOKEN__", token, 1)))
}

func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	if !hostOK(r) || r.Header.Get("X-Token") != token {
		http.Error(w, "forbidden", 403)
		return
	}
	e := engine
	switch strings.TrimPrefix(r.URL.Path, "/api/") {
	case "state":
		run, name, since := e.Running()
		var names []string
		for _, s := range e.strategies {
			names = append(names, s.Name)
		}
		up := int64(0)
		if run {
			up = int64(time.Since(since).Seconds())
		}
		jsonOut(w, map[string]any{"running": run, "active": name, "uptime": up, "settings": e.settings,
			"strategies": names, "version": version, "tune": e.TuneStatus(), "stats": e.Stats()})
	case "start":
		var in struct{ Strategy string }
		json.NewDecoder(r.Body).Decode(&in)
		if in.Strategy == "" {
			in.Strategy = e.settings.Strategy
		}
		if err := e.Start(in.Strategy); err != nil {
			jsonOut(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		e.mu.Lock()
		e.settings.Strategy = in.Strategy
		e.saveSettings()
		e.mu.Unlock()
		jsonOut(w, map[string]any{"ok": true})
	case "stop":
		e.Stop()
		jsonOut(w, map[string]any{"ok": true})
	case "check":
		jsonOut(w, checkAll(r.Context()))
	case "tune":
		if err := e.StartTune(); err != nil {
			jsonOut(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		jsonOut(w, map[string]any{"ok": true})
	case "tune-cancel":
		e.CancelTune()
		jsonOut(w, map[string]any{"ok": true})
	case "settings":
		var in Settings
		json.NewDecoder(r.Body).Decode(&in)
		e.mu.Lock()
		e.settings.AutoEnable = in.AutoEnable
		in.Apps = cleanApps(in.Apps)
		changed := strings.Join(in.Apps, ",") != strings.Join(e.settings.Apps, ",") || in.Discord != e.settings.Discord || in.YouTube != e.settings.YouTube || in.AllSites != e.settings.AllSites || in.BlockQUIC != e.settings.BlockQUIC
		e.settings.Apps = in.Apps
		e.settings.Discord, e.settings.YouTube, e.settings.AllSites, e.settings.BlockQUIC = in.Discord, in.YouTube, in.AllSites, in.BlockQUIC
		if in.AutoStart != e.settings.AutoStart {
			if err := setAutostart(in.AutoStart); err == nil {
				e.settings.AutoStart = in.AutoStart
			}
		}
		e.saveSettings()
		restart := changed && e.runner != nil
		name := e.active
		e.mu.Unlock()
		if restart {
			e.Start(name) // применить новые настройки сразу
		}
		jsonOut(w, map[string]any{"ok": true, "settings": e.settings})
	case "dns":
		var in struct{ On bool }
		json.NewDecoder(r.Body).Decode(&in)
		if err := setDNS(in.On); err != nil {
			jsonOut(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		e.mu.Lock()
		e.settings.DNSSet = in.On
		e.saveSettings()
		e.mu.Unlock()
		e.logf("DNS: " + map[bool]string{true: "установлены 1.1.1.1 / 8.8.8.8", false: "возвращены автоматические"}[in.On])
		jsonOut(w, map[string]any{"ok": true})
	case "openlink":
		var in struct{ URL string }
		json.NewDecoder(r.Body).Decode(&in)
		if in.URL == "https://t.me/bogestv0" { // открываем только ссылку автора
			openExternal(in.URL)
		}
		jsonOut(w, map[string]any{"ok": true})
	case "uninstall":
		un := filepath.Join(base, "uninstall.exe")
		if _, err := os.Stat(un); err != nil {
			jsonOut(w, map[string]any{"ok": false, "error": "uninstall.exe не найден — удалите через «Параметры Windows → Приложения»"})
			return
		}
		e.mu.Lock()
		dns := e.settings.DNSSet
		e.mu.Unlock()
		if dns {
			setDNS(false)
		}
		e.Stop()
		if err := startUninstaller(un); err != nil {
			jsonOut(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		jsonOut(w, map[string]any{"ok": true})
		go func() { time.Sleep(600 * time.Millisecond); os.Exit(0) }()
	case "procs":
		jsonOut(w, map[string]any{"procs": runningApps()})
	case "userlist":
		p := filepath.Join(base, "lists", "list-user.txt")
		if r.Method == "POST" {
			var in struct{ Text string }
			json.NewDecoder(r.Body).Decode(&in)
			lines := []string{}
			for _, l := range strings.Split(in.Text, "\n") {
				if l = strings.ToLower(strings.TrimSpace(l)); l != "" {
					lines = append(lines, l)
				}
			}
			os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
			if run, name, _ := e.Running(); run { // перезапуск, чтобы применить список
				e.Start(name)
			}
			jsonOut(w, map[string]any{"ok": true})
			return
		}
		b, _ := os.ReadFile(p)
		t := strings.TrimSpace(string(b))
		jsonOut(w, map[string]any{"text": t})
	case "log":
		jsonOut(w, map[string]any{"text": e.LogText()})
	case "quit":
		e.Stop()
		jsonOut(w, map[string]any{"ok": true})
		go func() { time.Sleep(300 * time.Millisecond); os.Exit(0) }()
	default:
		http.NotFound(w, r)
	}
}

// Вызывается деинсталлятором.
func cleanup() {
	setAutostart(false)
	releaseDriver()
	fmt.Println("ok")
}

func cleanApps(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, a := range in {
		a = strings.ToLower(strings.TrimSpace(a))
		a = a[strings.LastIndexAny(a, "\\/")+1:]
		if a == "" || seen[a] {
			continue
		}
		if !strings.HasSuffix(a, ".exe") {
			a += ".exe"
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

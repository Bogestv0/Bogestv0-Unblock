package main

// Проверка обновлений на GitHub (Releases) и установка по кнопке.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const setupAsset = "Bogestv0-Unblock-Setup.exe"

type UpdateInfo struct {
	Available bool   `json:"available"`
	Latest    string `json:"latest"`
	Notes     string `json:"notes"`
	Checked   int64  `json:"checked"` // unix, 0 — ещё не проверяли
	Err       string `json:"err,omitempty"`
	Skipped   bool   `json:"skipped"`
	Busy      bool   `json:"busy"` // идёт скачивание
	Stage     string `json:"stage,omitempty"`
}

type Updater struct {
	mu       sync.Mutex
	info     UpdateInfo
	url, sum string // адреса установщика и файла контрольных сумм
}

var updater = &Updater{}

func apiBase() string {
	if b := os.Getenv("BOGESTV0_GH_API"); b != "" {
		return b
	}
	return "https://api.github.com"
}

func (u *Updater) Info() UpdateInfo {
	u.mu.Lock()
	defer u.mu.Unlock()
	i := u.info
	if engine != nil {
		engine.mu.Lock()
		i.Skipped = i.Latest != "" && engine.settings.SkipVersion == i.Latest
		engine.mu.Unlock()
	}
	return i
}

// Loop: проверка при запуске и затем раз в 6 часов.
func (u *Updater) Loop() {
	time.Sleep(15 * time.Second)
	for {
		u.Check(false)
		if engine != nil {
			if ch, _ := SyncIPList(engine); ch {
				if run, name, _ := engine.Running(); run {
					engine.Start(name)
				}
			}
		}
		time.Sleep(6 * time.Hour)
	}
}

func (u *Updater) Check(force bool) UpdateInfo {
	if ghRepo == "" {
		return u.Info()
	}
	u.mu.Lock()
	if !force && time.Since(time.Unix(u.info.Checked, 0)) < time.Hour {
		u.mu.Unlock()
		return u.Info()
	}
	u.mu.Unlock()

	cl := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", apiBase()+"/repos/"+ghRepo+"/releases/latest", nil)
	req.Header.Set("User-Agent", "Bogestv0-Unblock/"+version)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := cl.Do(req)
	set := func(f func(i *UpdateInfo)) {
		u.mu.Lock()
		f(&u.info)
		u.info.Checked = time.Now().Unix()
		u.mu.Unlock()
	}
	if err != nil {
		set(func(i *UpdateInfo) { i.Err = "нет связи с GitHub" })
		return u.Info()
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		set(func(i *UpdateInfo) { i.Err = "GitHub: " + resp.Status })
		return u.Info()
	}
	var rel struct {
		Tag    string `json:"tag_name"`
		Body   string `json:"body"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel) != nil {
		set(func(i *UpdateInfo) { i.Err = "не удалось разобрать ответ GitHub" })
		return u.Info()
	}
	var url, sum string
	for _, a := range rel.Assets {
		switch a.Name {
		case setupAsset:
			url = a.URL
		case "SHA256SUMS.txt":
			sum = a.URL
		}
	}
	latest := strings.TrimPrefix(rel.Tag, "v")
	notes := strings.TrimSpace(rel.Body)
	if len(notes) > 600 {
		notes = notes[:600] + "…"
	}
	u.mu.Lock()
	u.url, u.sum = url, sum
	u.mu.Unlock()
	set(func(i *UpdateInfo) {
		i.Err, i.Latest, i.Notes = "", latest, notes
		i.Available = url != "" && newer(latest, version)
	})
	return u.Info()
}

// newer: a > b по номерам вида 1.2.3 (необязательные суффиксы отбрасываются).
func newer(a, b string) bool {
	pa, pb := verParts(a), verParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func verParts(s string) [3]int {
	var out [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	for i, p := range strings.SplitN(s, ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

func download(url string, limit int64) ([]byte, error) {
	cl := &http.Client{Timeout: 5 * time.Minute}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Bogestv0-Unblock/"+version)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// Install: скачивает установщик из релиза, сверяет контрольную сумму и запускает его (он заменит файлы и откроет программу).
func (u *Updater) Install(e *Engine) error {
	u.mu.Lock()
	if u.info.Busy {
		u.mu.Unlock()
		return errors.New("обновление уже идёт")
	}
	url, sum := u.url, u.sum
	if url == "" || !u.info.Available {
		u.mu.Unlock()
		return errors.New("нет новой версии")
	}
	u.info.Busy, u.info.Stage = true, "Скачиваю…"
	u.mu.Unlock()
	fail := func(err error) error {
		u.mu.Lock()
		u.info.Busy, u.info.Stage = false, ""
		u.mu.Unlock()
		return err
	}

	data, err := download(url, 200<<20)
	if err != nil {
		return fail(fmt.Errorf("не удалось скачать: %v", err))
	}
	if len(data) < 1<<20 || data[0] != 'M' || data[1] != 'Z' {
		return fail(errors.New("скачанный файл не похож на установщик"))
	}
	if sum != "" {
		txt, err := download(sum, 1<<16)
		if err != nil {
			return fail(fmt.Errorf("не удалось скачать контрольную сумму: %v", err))
		}
		h := sha256.Sum256(data)
		want := ""
		for _, l := range strings.Split(string(txt), "\n") {
			f := strings.Fields(l)
			if len(f) >= 2 && strings.TrimPrefix(f[1], "*") == setupAsset {
				want = strings.ToLower(f[0])
			}
		}
		if want == "" || want != hex.EncodeToString(h[:]) {
			return fail(errors.New("контрольная сумма не совпала — обновление отменено"))
		}
	}
	dir, err := os.MkdirTemp("", "bogestv0-update-")
	if err != nil {
		return fail(err)
	}
	path := filepath.Join(dir, setupAsset)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		return fail(err)
	}
	u.mu.Lock()
	u.info.Stage = "Устанавливаю…"
	u.mu.Unlock()
	e.logf("обновление: запускаю установщик " + u.info.Latest)
	if err := startSetup(path); err != nil {
		return fail(err)
	}
	return nil
}

/* ---------- обновляемый список IP из репозитория ---------- */

type IPSync struct {
	Checked int64  `json:"checked"`
	Count   int    `json:"count"`
	Err     string `json:"err,omitempty"`
}

var (
	ipsyncMu sync.Mutex
	ipsync   IPSync
)

func rawBase() string {
	if b := os.Getenv("BOGESTV0_RAW"); b != "" {
		return b
	}
	return "https://raw.githubusercontent.com"
}

func ipSyncInfo() IPSync {
	ipsyncMu.Lock()
	defer ipsyncMu.Unlock()
	return ipsync
}

// SyncIPList скачивает lists/ipset.txt из репозитория в lists/ipset-remote.txt. true — список изменился.
func SyncIPList(e *Engine) (changed bool, err error) {
	if ghRepo == "" {
		return false, errors.New("репозиторий не задан в этой сборке")
	}
	set := func(f func(s *IPSync)) {
		ipsyncMu.Lock()
		f(&ipsync)
		ipsync.Checked = time.Now().Unix()
		ipsyncMu.Unlock()
	}
	data, err := download(rawBase()+"/"+ghRepo+"/HEAD/lists/ipset.txt", 1<<20)
	if err != nil {
		set(func(s *IPSync) { s.Err = "не удалось скачать список: " + err.Error() })
		return false, err
	}
	rs, bad := parseIPList(string(data))
	if len(rs) == 0 && len(bad) > 0 {
		err = errors.New("в скачанном файле нет ни одного адреса — список не применён")
		set(func(s *IPSync) { s.Err = err.Error() })
		return false, err
	}
	p := filepath.Join(e.base, "lists", "ipset-remote.txt")
	old, _ := os.ReadFile(p)
	if string(old) != string(data) {
		os.MkdirAll(filepath.Dir(p), 0o755)
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return false, err
		}
		if err := os.Rename(tmp, p); err != nil {
			return false, err
		}
		changed = true
		e.logf(fmt.Sprintf("список IP обновлён из репозитория: записей %d", len(rs)))
	}
	set(func(s *IPSync) { s.Err, s.Count = "", len(rs) })
	return changed, nil
}

// remoteIPCount — сколько записей в уже скачанном списке (для показа при запуске).
func remoteIPCount(base string) int {
	b, err := os.ReadFile(filepath.Join(base, "lists", "ipset-remote.txt"))
	if err != nil {
		return 0
	}
	rs, _ := parseIPList(string(b))
	return len(rs)
}

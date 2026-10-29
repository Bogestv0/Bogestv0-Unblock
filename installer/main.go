// Установщик Bogestv0 Unblock для Windows (один .exe).
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

//go:embed all:assets
var assets embed.FS

var version = "2.4.1"

const (
	appExe = "Bogestv0-Unblock.exe"
	regKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Bogestv0Unblock`
)

func silent() bool {
	for _, a := range os.Args[1:] {
		if a == "--silent" {
			return true
		}
	}
	return false
}

func say(f string, a ...any) { fmt.Printf(f+"\n", a...) }

func pause() {
	if os.Getenv("BOGESTV0_NOPAUSE") != "" || silent() {
		return
	}
	fmt.Print("\nНажмите Enter, чтобы закрыть окно...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func fatal(msg string, err error) {
	say("\n[ОШИБКА] %s", msg)
	if err != nil {
		say("         %v", err)
	}
	pause()
	os.Exit(1)
}

func run(name string, args ...string) error {
	c := exec.Command(name, args...)
	hide(c)
	return c.Run()
}

func main() {
	setupConsole()
	dest := os.Getenv("BOGESTV0_DEST")
	if dest == "" {
		dest = filepath.Join(os.Getenv("LOCALAPPDATA"), "Bogestv0Unblock")
	}
	if !isAdmin() {
		if elevate() == nil {
			return
		}
		fatal("Нужны права администратора (для драйвера WinDivert). Подтвердите запрос Windows и повторите.", nil)
	}
	if len(os.Args) > 1 && os.Args[1] == "--uninstall" {
		uninstall(dest)
		return
	}
	install(dest)
}

func stopOld(dest string, removeTask bool) {
	run("taskkill", "/F", "/IM", appExe)
	run("sc", "stop", "WinDivert")
	if removeTask {
		run("schtasks", "/Delete", "/TN", "Bogestv0Unblock", "/F")
	}
	time.Sleep(900 * time.Millisecond)
}

func install(dest string) {
	say("==============================================")
	say("   Bogestv0 Unblock — установка (версия %s)", version)
	say("==============================================\n")

	say("[1/4] Копирую файлы...")
	stopOld(dest, false)
	keep := map[string][]byte{}
	for _, f := range []string{"settings.json", "lists/list-general-user.txt", "lists/list-exclude-user.txt", "lists/ipset-exclude-user.txt"} {
		if b, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(f))); err == nil {
			keep[f] = b
		}
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		fatal("Не удалось создать папку "+dest, err)
	}
	err := fs.WalkDir(assets, "assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := strings.TrimPrefix(path, "assets/")
		data, _ := assets.ReadFile(path)
		t := filepath.Join(dest, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(t), 0o755)
		return os.WriteFile(t, data, 0o755)
	})
	if err != nil {
		fatal("Не удалось распаковать файлы (антивирус мог заблокировать файлы программы).", err)
	}
	for f, b := range keep { // сохранить пользовательские настройки и списки
		os.WriteFile(filepath.Join(dest, filepath.FromSlash(f)), b, 0o644)
	}
	// удаление: копия установщика
	if self, err := os.Executable(); err == nil {
		if data, err := os.ReadFile(self); err == nil {
			os.WriteFile(filepath.Join(dest, "uninstall.exe"), data, 0o755)
		}
	}

	say("[2/4] Загружаю драйвер WinDivert (официальная сборка автора)...")
	if err := ensureWinDivert(dest); err != nil {
		say("\n  [!] Не удалось получить WinDivert: %v", err)
		say("  Скачайте вручную архив WinDivert-2.2.x-A.zip со страницы")
		say("    https://github.com/basil00/WinDivert/releases")
		say("  и положите его рядом с установщиком (или файлы WinDivert.dll и WinDivert64.sys из папки x64")
		say("  в папку %s), затем запустите установщик заново.", dest)
	}

	say("[3/4] Создаю ярлыки...")
	exe := filepath.Join(dest, appExe)
	shortcuts(exe, dest)
	regAdd("DisplayName", "Bogestv0 Unblock")
	regAdd("DisplayVersion", version)
	regAdd("Publisher", "Bogestv0")
	regAdd("InstallLocation", dest)
	regAdd("DisplayIcon", exe+",0")
	regAdd("UninstallString", `"`+filepath.Join(dest, "uninstall.exe")+`" --uninstall`)

	say("[4/4] Готово!\n")
	say("  На рабочем столе появился ярлык «Bogestv0 Unblock».")
	say("  Сейчас откроется окно программы:")
	say("   1) Нажмите «Подобрать автоматически» — программа сама найдёт рабочую стратегию")
	say("   2) Включите «Всегда включён», чтобы обход работал сам после запуска Windows")
	say("  Windows спросит разрешение администратора — это нужно для драйвера WinDivert.")
	if runtime.GOOS == "windows" {
		if run("schtasks", "/Query", "/TN", "Bogestv0Unblock") == nil { // «Всегда включён» уже настроен — запускаем без запроса прав
			run("schtasks", "/Run", "/TN", "Bogestv0Unblock")
			time.Sleep(3 * time.Second)
		}
		exec.Command("explorer.exe", exe).Start() // запуск без повышения прав
	}
	pause()
}

func shortcuts(exe, dest string) {
	// Иконка берётся из самого exe (она вшита в файл), а не из отдельного .ico — так Windows
	// не подставляет старую картинку из своего кэша иконок.
	ps := fmt.Sprintf(`$w=New-Object -ComObject WScript.Shell
$paths=@([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))
foreach($d in $paths){ if(-not $d){continue}; $f=Join-Path $d 'Bogestv0 Unblock.lnk'; Remove-Item -Force $f -ErrorAction SilentlyContinue; $s=$w.CreateShortcut($f); $s.TargetPath='%s'; $s.WorkingDirectory='%s'; $s.IconLocation='%s,0'; $s.Description='Bogestv0 Unblock'; $s.Save() }`, exe, dest, exe)
	run("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	refreshIcons()
}

func regAdd(name, value string) {
	run("reg", "add", regKey, "/f", "/v", name, "/t", "REG_SZ", "/d", value)
}

func uninstall(dest string) {
	say("Удаляю Bogestv0 Unblock...")
	stopOld(dest, true)
	run("sc", "delete", "WinDivert")
	run("powershell", "-NoProfile", "-Command", `Remove-Item -Force ([IO.Path]::Combine([Environment]::GetFolderPath('Desktop'),'Bogestv0 Unblock.lnk')), ([IO.Path]::Combine([Environment]::GetFolderPath('Programs'),'Bogestv0 Unblock.lnk')) -ErrorAction SilentlyContinue`)
	run("reg", "delete", regKey, "/f")
	c := exec.Command("cmd", "/c", "ping -n 4 127.0.0.1 >nul & rmdir /s /q \""+dest+"\"")
	hide(c)
	c.Start()
	say("Готово.")
	pause()
}

/* ---------- WinDivert: скачиваем у автора (basil00/WinDivert), LGPLv3 / GPLv2 ---------- */

func ensureWinDivert(dest string) error {
	dll, sys := filepath.Join(dest, "WinDivert.dll"), filepath.Join(dest, "WinDivert64.sys")
	if fileExists(dll) && fileExists(sys) {
		say("      уже установлен")
		return nil
	}
	data, err := localWinDivertZip()
	if err != nil {
		data, err = downloadWinDivert()
		if err != nil {
			return err
		}
	}
	return extractWinDivert(data, dest)
}

func fileExists(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() }

func localWinDivertZip() ([]byte, error) {
	exe, _ := os.Executable()
	for _, dir := range []string{filepath.Dir(exe), "."} {
		m, _ := filepath.Glob(filepath.Join(dir, "WinDivert*.zip"))
		if len(m) > 0 {
			say("      беру архив рядом с установщиком: %s", filepath.Base(m[0]))
			return os.ReadFile(m[0])
		}
	}
	return nil, fmt.Errorf("архива рядом нет")
}

func httpGet(url string) ([]byte, error) {
	cl := &http.Client{Timeout: 2 * time.Minute}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Bogestv0-Unblock-Setup")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func downloadWinDivert() ([]byte, error) {
	urls := []string{}
	if u := os.Getenv("BOGESTV0_WINDIVERT_URL"); u != "" {
		urls = append(urls, u)
	} else {
		// 1) через API GitHub находим актуальный архив
		if b, err := httpGet("https://api.github.com/repos/basil00/WinDivert/releases/latest"); err == nil {
			var rel struct {
				Assets []struct {
					Name string `json:"name"`
					URL  string `json:"browser_download_url"`
				} `json:"assets"`
			}
			if json.Unmarshal(b, &rel) == nil {
				for _, pref := range []string{"-A.zip", ".zip"} {
					for _, a := range rel.Assets {
						if strings.HasSuffix(a.Name, pref) && strings.HasPrefix(a.Name, "WinDivert") {
							urls = append(urls, a.URL)
						}
					}
				}
			}
		}
		// 2) запасные адреса
		urls = append(urls,
			"https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip",
			"https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-D.zip",
			"https://github.com/basil00/WinDivert/releases/download/v2.2.0/WinDivert-2.2.0-A.zip")
	}
	var last error
	for _, u := range urls {
		say("      скачиваю %s", u)
		b, err := httpGet(u)
		if err == nil {
			return b, nil
		}
		last = err
	}
	return nil, last
}

func extractWinDivert(data []byte, dest string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	want := map[string]bool{"windivert.dll": false, "windivert64.sys": false}
	for _, f := range zr.File {
		p := strings.ToLower(strings.ReplaceAll(f.Name, "\\", "/"))
		base := p[strings.LastIndex(p, "/")+1:]
		if _, ok := want[base]; !ok || !strings.Contains(p, "x64/") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		name := "WinDivert.dll"
		if base == "windivert64.sys" {
			name = "WinDivert64.sys"
		}
		if err := os.WriteFile(filepath.Join(dest, name), b, 0o644); err != nil {
			return err
		}
		want[base] = true
	}
	for k, ok := range want {
		if !ok {
			return fmt.Errorf("в архиве нет x64/%s", k)
		}
	}
	return nil
}

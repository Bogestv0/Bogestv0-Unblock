//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	shell32      = syscall.NewLazyDLL("shell32.dll")
	user32       = syscall.NewLazyDLL("user32.dll")
	procAdmin    = shell32.NewProc("IsUserAnAdmin")
	procShellExe = shell32.NewProc("ShellExecuteW")
	procMsgBox   = user32.NewProc("MessageBoxW")
)

func hide(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

func isAdmin() bool { r, _, _ := procAdmin.Call(); return r != 0 }

func shellExecute(verb, file, args string, show int) error {
	v, _ := syscall.UTF16PtrFromString(verb)
	f, _ := syscall.UTF16PtrFromString(file)
	a, _ := syscall.UTF16PtrFromString(args)
	r, _, e := procShellExe.Call(0, uintptr(unsafe.Pointer(v)), uintptr(unsafe.Pointer(f)), uintptr(unsafe.Pointer(a)), 0, uintptr(show))
	if r <= 32 {
		return e
	}
	return nil
}

func runServerElevated() error {
	exe, _ := os.Executable()
	return shellExecute("runas", exe, "--serve", 0)
}

func runServerElevatedSelf(background bool) {
	exe, _ := os.Executable()
	a := "--serve"
	if background {
		a += " --background"
	}
	shellExecute("runas", exe, a, 0)
}

func fatalBox(title, text string) {
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(text)
	procMsgBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10)
}

// Открывает окно интерфейса: Edge/Chrome в режиме «приложение», иначе браузер по умолчанию.
func openUI(url string) {
	pf, pf86, la := os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")
	for _, p := range []string{
		filepath.Join(pf86, `Microsoft\Edge\Application\msedge.exe`), filepath.Join(pf, `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(pf, `Google\Chrome\Application\chrome.exe`), filepath.Join(pf86, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(la, `Google\Chrome\Application\chrome.exe`), filepath.Join(pf, `BraveSoftware\Brave-Browser\Application\brave.exe`),
	} {
		if _, err := os.Stat(p); err == nil {
			if exec.Command(p, "--app="+url, "--window-size=520,860").Start() == nil {
				return
			}
		}
	}
	exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func setAutostart(on bool) error {
	exe, _ := os.Executable()
	var c *exec.Cmd
	if on {
		c = exec.Command("schtasks", "/Create", "/TN", "Bogestv0Unblock", "/TR", `"`+exe+`" --serve --background`,
			"/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
	} else {
		c = exec.Command("schtasks", "/Delete", "/TN", "Bogestv0Unblock", "/F")
	}
	hide(c)
	return c.Run()
}

// Освобождает драйвер WinDivert после остановки winws.
func releaseDriver() {
	for _, a := range [][]string{{"stop", "WinDivert"}, {"delete", "WinDivert"}, {"stop", "WinDivert14"}, {"delete", "WinDivert14"}} {
		c := exec.Command("sc", a...)
		hide(c)
		c.Run()
	}
}

// Адреса, которые ставит программа.
var ourDNS = []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"}

// Сценарий PowerShell: ставит DNS Cloudflare/Google на все активные адаптеры.
// Ошибка на одном адаптере (VPN, виртуальный, Bluetooth…) не должна ломать всё — важно, чтобы хоть один сработал.
// Прежние СТАТИЧЕСКИЕ DNS сохраняются в файл (пустой список = «получать автоматически»).
const dnsOnScript = `$ErrorActionPreference='Continue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
$f='%BK%'; $ok=0; $fail=@()
try { $ad=@(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }) } catch { Write-Output ('Get-NetAdapter: '+$_.Exception.Message); exit 3 }
if($ad.Count -eq 0){ Write-Output 'нет активных сетевых адаптеров'; exit 3 }
if(-not (Test-Path $f)){
  $b=@()
  foreach($a in $ad){
    $s=@()
    foreach($k in 'Tcpip','Tcpip6'){ try { $ns=(Get-ItemProperty -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$k+'\Parameters\Interfaces\'+$a.InterfaceGuid) -ErrorAction Stop).NameServer; if($ns){ $s+=@($ns -split '[,\s]+' | Where-Object { $_ }) } } catch {} }
    $b+=[pscustomobject]@{i=[int]$a.ifIndex;a=@($s)}
  }
  try { ConvertTo-Json -InputObject @($b) -Compress | Set-Content -Encoding UTF8 $f } catch { Write-Output ('backup: '+$_.Exception.Message) }
}
foreach($a in $ad){
  try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses ('1.1.1.1','8.8.8.8','2606:4700:4700::1111','2001:4860:4860::8888') -ErrorAction Stop; $ok++ }
  catch {
    try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses ('1.1.1.1','8.8.8.8') -ErrorAction Stop; $ok++ }
    catch { $fail+=($a.Name+': '+$_.Exception.Message) }
  }
}
if($ok -eq 0){ $fail | ForEach-Object { Write-Output $_ }; exit 3 }
exit 0`

// Возврат: адаптеры, на которых стоят наши адреса, получают прежние статические DNS из файла или снова становятся автоматическими.
const dnsOffScript = `$ErrorActionPreference='Continue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
$f='%BK%'; $ours=@('1.1.1.1','8.8.8.8','2606:4700:4700::1111','2001:4860:4860::8888'); $b=@(); $ok=0; $fail=@()
if(Test-Path $f){ try { $b=@(Get-Content -Raw -Encoding UTF8 $f | ConvertFrom-Json) } catch { $b=@() } }
try { $ad=@(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }) } catch { Write-Output ('Get-NetAdapter: '+$_.Exception.Message); exit 3 }
foreach($a in $ad){
  try {
    $cur=@((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ErrorAction Stop).ServerAddresses)
    $old=$b | Where-Object { $_.i -eq $a.ifIndex } | Select-Object -First 1
    $addr=@(); if($old){ $addr=@($old.a | Where-Object { $_ -and ($ours -notcontains $_) }) }
    $hasOurs=(@($cur | Where-Object { $ours -contains $_ })).Count -gt 0
    if($addr.Count -gt 0){ Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $addr -ErrorAction Stop }
    elseif($hasOurs){ Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction Stop }
    $ok++
  } catch { $fail+=($a.Name+': '+$_.Exception.Message) }
}
if($ok -eq 0 -and $fail.Count -gt 0){ $fail | ForEach-Object { Write-Output $_ }; exit 3 }
Remove-Item -Force $f -ErrorAction SilentlyContinue
exit 0`

func runHidden(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	hide(c)
	out, err := c.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// dnsViaPowerShell: основной способ (запоминает прежние настройки).
func dnsViaPowerShell(on bool) error {
	bk := strings.ReplaceAll(filepath.Join(base, "dns-backup.json"), "'", "''")
	src := dnsOffScript
	if on {
		src = dnsOnScript
	}
	// сценарий кладём в файл: так не мешают кавычки/переносы строк и видны настоящие сообщения об ошибках
	f, err := os.CreateTemp(base, "dns-*.ps1")
	if err != nil {
		if f, err = os.CreateTemp("", "bogestv0-dns-*.ps1"); err != nil {
			return err
		}
	}
	path := f.Name()
	defer os.Remove(path)
	f.WriteString("\xef\xbb\xbf" + strings.ReplaceAll(src, "%BK%", bk)) // UTF-8 с BOM — PowerShell 5 читает кириллицу верно
	f.Close()
	out, err := runHidden(45*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	if err != nil {
		if out == "" {
			out = "без сообщения"
		}
		return fmt.Errorf("PowerShell: %v (%s)", err, clip(out, 300))
	}
	return nil
}

// dnsViaNetsh: запасной способ, если PowerShell/модуль DnsClient недоступен. Адаптеры берём из Go по номеру интерфейса.
// При возврате адаптеры с нашими адресами становятся «автоматическими» (прежние статические не запоминаются).
func dnsViaNetsh(on bool) error {
	ifs, _ := net.Interfaces()
	okN := 0
	var errs []string
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		idx := strconv.Itoa(i.Index)
		if on {
			_, e1 := runHidden(20*time.Second, "netsh", "interface", "ipv4", "set", "dnsservers", "name="+idx, "static", "1.1.1.1", "primary", "validate=no")
			if e1 != nil {
				errs = append(errs, i.Name+": "+e1.Error())
				continue
			}
			runHidden(20*time.Second, "netsh", "interface", "ipv4", "add", "dnsservers", "name="+idx, "8.8.8.8", "index=2", "validate=no")
			okN++
			continue
		}
		cur, _ := runHidden(20*time.Second, "netsh", "interface", "ipv4", "show", "dnsservers", "name="+idx)
		if !strings.Contains(cur, "1.1.1.1") && !strings.Contains(cur, "8.8.8.8") {
			continue // на этом адаптере наших адресов нет — не трогаем
		}
		if _, e := runHidden(20*time.Second, "netsh", "interface", "ipv4", "set", "dnsservers", "name="+idx, "source=dhcp"); e != nil {
			errs = append(errs, i.Name+": "+e.Error())
			continue
		}
		okN++
	}
	if okN == 0 && (on || len(errs) > 0) {
		return fmt.Errorf("netsh: ни один адаптер не изменён (%s)", clip(strings.Join(errs, "; "), 200))
	}
	return nil
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// setDNS: on=true — DNS Cloudflare и Google на активных адаптерах (прежние настройки сохраняются в dns-backup.json);
// on=false — вернуть прежние (или автоматические, если сохранённых нет).
func setDNS(on bool) error {
	err := dnsViaPowerShell(on)
	if err != nil {
		if err2 := dnsViaNetsh(on); err2 != nil {
			return fmt.Errorf("не удалось изменить DNS: %v; запасной способ: %v", err, err2)
		}
	}
	f := exec.Command("ipconfig", "/flushdns")
	hide(f)
	f.Run()
	return nil
}

// vpnOwnsDNS: настройками DNS уже пользуется Bogestv0 VPN (у него своя кнопка «Исправить DNS» с файлом dns-backup.json,
// и ставит она те же 1.1.1.1 / 8.8.8.8). Если при удалении обхода сбросить DNS, VPN потеряет свою настройку.
func vpnOwnsDNS() bool {
	dirs := []string{filepath.Join(filepath.Dir(base), "Bogestv0VPN")}
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		dirs = append(dirs, filepath.Join(la, "Bogestv0VPN"))
	}
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(d, "dns-backup.json")); err == nil {
			return true
		}
	}
	return false
}

func openExternal(url string) { exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start() }

// startUninstaller запускает удаление отдельным скрытым процессом (он сам закроет программу и всё уберёт).
func startUninstaller(path string) error {
	c := exec.Command(path, "--uninstall", "--silent")
	hide(c)
	return c.Start()
}

// startSetup запускает скачанный установщик в тихом режиме (он остановит эту программу и запустит новую).
func startSetup(path string) error {
	c := exec.Command(path, "--silent")
	hide(c)
	return c.Start()
}

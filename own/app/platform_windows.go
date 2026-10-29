//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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

// setDNS: on=true — DNS Cloudflare и Google на активных адаптерах (прежние настройки сохраняются в dns-backup.json);
// on=false — вернуть прежние (или автоматические, если сохранённых нет).
func setDNS(on bool) error {
	bk := strings.ReplaceAll(filepath.Join(base, "dns-backup.json"), "'", "''")
	var script string
	if on {
		script = `$ErrorActionPreference='Stop'; $f='` + bk + `'
$ad=@(Get-NetAdapter | Where-Object Status -eq 'Up')
if(-not (Test-Path $f)){ $b=@(); foreach($a in $ad){ $c=Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex; $b+=[pscustomobject]@{i=[int]$a.ifIndex;a=@($c.ServerAddresses)} }; ConvertTo-Json -InputObject @($b) -Compress | Set-Content -Encoding UTF8 $f }
foreach($a in $ad){ try { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses ('1.1.1.1','8.8.8.8','2606:4700:4700::1111','2001:4860:4860::8888') } catch { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses ('1.1.1.1','8.8.8.8') } }`
	} else {
		script = `$ErrorActionPreference='Stop'; $f='` + bk + `'
$ours=@('1.1.1.1','8.8.8.8','2606:4700:4700::1111','2001:4860:4860::8888'); $b=@()
if(Test-Path $f){ $b=@(Get-Content -Raw $f | ConvertFrom-Json) }
foreach($a in @(Get-NetAdapter | Where-Object Status -eq 'Up')){
  $old=$b | Where-Object { $_.i -eq $a.ifIndex } | Select-Object -First 1
  $addr=@(); if($old){ $addr=@($old.a | Where-Object { $ours -notcontains $_ }) }
  if($addr.Count -gt 0){ Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $addr } else { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses }
}
Remove-Item -Force $f -ErrorAction SilentlyContinue`
	}
	c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	hide(c)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("не удалось изменить DNS: %v %s", err, strings.TrimSpace(string(out)))
	}
	f := exec.Command("ipconfig", "/flushdns")
	hide(f)
	f.Run()
	return nil
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

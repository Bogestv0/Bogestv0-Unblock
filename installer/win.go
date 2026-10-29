//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

var (
	shell32      = syscall.NewLazyDLL("shell32.dll")
	procAdmin    = shell32.NewProc("IsUserAnAdmin")
	procShellExe = shell32.NewProc("ShellExecuteW")
)

func setupConsole() { syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleOutputCP").Call(65001) }
func hide(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
func isAdmin() bool { r, _, _ := procAdmin.Call(); return r != 0 }

func elevate() error {
	exe, _ := os.Executable()
	args := strings.Join(os.Args[1:], " ")
	v, _ := syscall.UTF16PtrFromString("runas")
	f, _ := syscall.UTF16PtrFromString(exe)
	a, _ := syscall.UTF16PtrFromString(args)
	r, _, e := procShellExe.Call(0, uintptr(unsafe.Pointer(v)), uintptr(unsafe.Pointer(f)), uintptr(unsafe.Pointer(a)), 0, 1)
	if r <= 32 {
		return e
	}
	return nil
}

// refreshIcons просит Проводник перечитать иконки (иначе на рабочем столе может висеть старая картинка из кэша).
func refreshIcons() {
	for _, a := range []string{"-show", "-ClearIconCache"} { // первый — Windows 10/11, второй — старые версии
		c := exec.Command("ie4uinit.exe", a)
		hide(c)
		c.Run()
	}
	// SHCNE_ASSOCCHANGED: сообщить оболочке, что ассоциации/иконки изменились
	syscall.NewLazyDLL("shell32.dll").NewProc("SHChangeNotify").Call(0x08000000, 0, 0, 0)
}

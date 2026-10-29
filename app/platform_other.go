//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// Заглушки для разработки и тестов на Linux/macOS.
func hide(c *exec.Cmd)            {}
func isAdmin() bool               { return true }
func runServerElevatedSelf(bool)  {}
func fatalBox(title, text string) { fmt.Println(title+":", text) }
func openUI(url string)           { fmt.Println("UI:", url) }
func setAutostart(on bool) error  { return nil }
func releaseDriver()              {}
func runServerElevated() error {
	exe, _ := os.Executable()
	return exec.Command(exe, "--serve").Start()
}

func setDNS(on bool) error { return nil }

func openExternal(url string)         { fmt.Println("open:", url) }
func startUninstaller(p string) error { fmt.Println("uninstall:", p); return nil }

func startSetup(p string) error { fmt.Println("setup:", p); return nil }

func vpnOwnsDNS() bool { return false }

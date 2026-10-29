//go:build !windows

package main

import "os"

// Вне Windows владельца соединения не определяем (только для разработки; можно подставить через BOGESTV0_OWNER).
func tcpOwner(src [4]byte, sport uint16) string { return os.Getenv("BOGESTV0_OWNER") }

func runningApps() []string { return []string{"discord.exe", "chrome.exe", "telegram.exe"} }

func udpOwner(src [4]byte, sport uint16) string { return os.Getenv("BOGESTV0_OWNER") }

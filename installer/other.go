//go:build !windows

package main

import "os/exec"

func setupConsole()    {}
func hide(c *exec.Cmd) {}
func isAdmin() bool    { return true }
func elevate() error   { return nil }
func refreshIcons()    {}

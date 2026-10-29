//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// Обёртка над WinDivert.dll (https://reqrypt.org/windivert.html, LGPLv3/GPLv2) без cgo.
// WINDIVERT_ADDRESS занимает 80 байт; флаги — в 10-м байте (бит 1 — Outbound, биты 5–7 — «контрольные суммы верны»).

type divertWin struct {
	h                     uintptr
	recv, send, closeProc *syscall.LazyProc
}

func openDivert(dir, filter string) (diverter, error) {
	dllPath := filepath.Join(dir, "WinDivert.dll")
	if _, err := os.Stat(dllPath); err != nil {
		return nil, errors.New("не найден WinDivert.dll — переустановите программу")
	}
	if _, err := os.Stat(filepath.Join(dir, "WinDivert64.sys")); err != nil {
		return nil, errors.New("не найден WinDivert64.sys — переустановите программу")
	}
	dll := syscall.NewLazyDLL(dllPath)
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("не удалось загрузить WinDivert.dll: %w", err)
	}
	open := dll.NewProc("WinDivertOpen")
	f, _ := syscall.BytePtrFromString(filter)
	h, _, e := open.Call(uintptr(unsafe.Pointer(f)), 0 /* NETWORK */, 0 /* приоритет */, 0 /* флаги */)
	if h == ^uintptr(0) {
		if en, ok := e.(syscall.Errno); ok {
			switch en {
			case 5:
				return nil, errors.New("нет прав администратора для драйвера WinDivert")
			case 577:
				return nil, errors.New("Windows не загрузила драйвер WinDivert (неподписанный драйвер или блок антивируса)")
			case 87:
				return nil, errors.New("неверный фильтр WinDivert")
			}
		}
		return nil, fmt.Errorf("WinDivertOpen: %v", e)
	}
	return &divertWin{h: h, recv: dll.NewProc("WinDivertRecv"), send: dll.NewProc("WinDivertSend"), closeProc: dll.NewProc("WinDivertClose")}, nil
}

func (d *divertWin) Recv(buf []byte) (int, []byte, error) {
	var n uint32
	var addr [80]byte
	r, _, e := d.recv.Call(d.h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&addr[0])))
	if r == 0 {
		return 0, nil, e
	}
	return int(n), addr[:], nil
}

func (d *divertWin) Send(pkt []byte, addr []byte, injected bool) error {
	var a [80]byte
	copy(a[:], addr)
	if injected {
		a[10] |= 0xE0 // IP/TCP/UDP-суммы считаем сами и считаем их готовыми
	}
	var n uint32
	r, _, e := d.send.Call(d.h, uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&a[0])))
	if r == 0 {
		return e
	}
	return nil
}

func (d *divertWin) Close() error { d.closeProc.Call(d.h); return nil }

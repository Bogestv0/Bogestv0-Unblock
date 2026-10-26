//go:build windows

package main

// Определение программы-владельца соединения: таблица TCP (iphlpapi) → PID → имя exe.

import (
	"encoding/binary"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	iphlp                = syscall.NewLazyDLL("iphlpapi.dll")
	pGetExtendedTcpTable = iphlp.NewProc("GetExtendedTcpTable")
	kern                 = syscall.NewLazyDLL("kernel32.dll")
	pOpenProcess         = kern.NewProc("OpenProcess")
	pQueryImageName      = kern.NewProc("QueryFullProcessImageNameW")
	pSnapshot            = kern.NewProc("CreateToolhelp32Snapshot")
	pProc32First         = kern.NewProc("Process32FirstW")
	pProc32Next          = kern.NewProc("Process32NextW")

	pidMu    sync.Mutex
	pidNames = map[uint32]string{}
)

// tcpPidOf ищет PID по локальному адресу и порту исходящего соединения.
func tcpPidOf(src [4]byte, sport uint16) uint32 {
	var size uint32
	for try := 0; try < 3; try++ {
		buf := make([]byte, size+4096)
		size = uint32(len(buf))
		// AF_INET=2, TCP_TABLE_OWNER_PID_ALL=5
		r, _, _ := pGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, 2, 5, 0)
		if r == 122 { // ERROR_INSUFFICIENT_BUFFER
			continue
		}
		if r != 0 || len(buf) < 4 {
			return 0
		}
		n := int(binary.LittleEndian.Uint32(buf))
		for i := 0; i < n && 4+(i+1)*24 <= len(buf); i++ {
			row := buf[4+i*24:]
			la := [4]byte{row[4], row[5], row[6], row[7]}
			lp := uint16(row[8])<<8 | uint16(row[9]) // порт хранится в сетевом порядке
			if lp == sport && (la == src || la == [4]byte{}) {
				return binary.LittleEndian.Uint32(row[20:])
			}
		}
		return 0
	}
	return 0
}

func pidName(pid uint32) string {
	pidMu.Lock()
	if n, ok := pidNames[pid]; ok {
		pidMu.Unlock()
		return n
	}
	pidMu.Unlock()
	name := ""
	h, _, _ := pOpenProcess.Call(0x1000, 0, uintptr(pid)) // PROCESS_QUERY_LIMITED_INFORMATION
	if h != 0 {
		defer syscall.CloseHandle(syscall.Handle(h))
		var b [1024]uint16
		sz := uint32(len(b))
		if r, _, _ := pQueryImageName.Call(h, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&sz))); r != 0 {
			full := syscall.UTF16ToString(b[:sz])
			name = strings.ToLower(full[strings.LastIndexAny(full, "\\/")+1:])
		}
	}
	pidMu.Lock()
	if len(pidNames) > 4000 {
		pidNames = map[uint32]string{}
	}
	pidNames[pid] = name
	pidMu.Unlock()
	return name
}

func tcpOwner(src [4]byte, sport uint16) string {
	pid := tcpPidOf(src, sport)
	if pid == 0 {
		return ""
	}
	return pidName(pid)
}

// runningApps — имена запущенных программ (для выбора в окне).
func runningApps() []string {
	h, _, _ := pSnapshot.Call(2, 0) // TH32CS_SNAPPROCESS
	if h == ^uintptr(0) {
		return nil
	}
	defer syscall.CloseHandle(syscall.Handle(h))
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	set := map[string]bool{}
	r, _, _ := pProc32First.Call(h, uintptr(unsafe.Pointer(&pe)))
	for r != 0 {
		n := strings.ToLower(syscall.UTF16ToString(pe.ExeFile[:]))
		if strings.HasSuffix(n, ".exe") && !skipProc[n] {
			set[n] = true
		}
		r, _, _ = pProc32Next.Call(h, uintptr(unsafe.Pointer(&pe)))
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

var skipProc = map[string]bool{"svchost.exe": true, "system": true, "csrss.exe": true, "wininit.exe": true, "services.exe": true,
	"lsass.exe": true, "smss.exe": true, "winlogon.exe": true, "dwm.exe": true, "fontdrvhost.exe": true, "conhost.exe": true,
	"runtimebroker.exe": true, "taskhostw.exe": true, "sihost.exe": true, "ctfmon.exe": true, "searchhost.exe": true}

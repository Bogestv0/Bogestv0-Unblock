package main

import (
	"fmt"
	"sync"
	"time"
)

// diverter — перехват пакетов (WinDivert в Windows).
type diverter interface {
	Recv(buf []byte) (int, []byte, error)
	Send(pkt []byte, addr []byte, injected bool) error
	Close() error
}

type Runner struct {
	d    diverter
	core *Core
	done chan struct{}
	once sync.Once
}

func buildFilter(blockQUIC bool) string {
	f := "outbound and ip and ((tcp.DstPort == 443 and tcp.PayloadLength > 0) or udp.PayloadLength == 74 or udp.DstPort == 3478"
	if blockQUIC {
		f += " or udp.DstPort == 443"
	}
	return f + ")"
}

func StartRunner(dir string, st Strategy, m *Matcher, blockQUIC bool, log func(string)) (*Runner, error) {
	d, err := openDivert(dir, buildFilter(blockQUIC))
	if err != nil {
		return nil, err
	}
	r := &Runner{d: d, core: NewCore(st, m, blockQUIC, log), done: make(chan struct{})}
	go r.loop()
	return r, nil
}

func (r *Runner) loop() {
	defer close(r.done)
	buf := make([]byte, 65535)
	for {
		n, addr, err := r.d.Recv(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		outs, consumed := r.safeProcess(pkt)
		if !consumed {
			r.d.Send(pkt, addr, false)
			continue
		}
		for _, o := range outs {
			r.d.Send(o, addr, true)
		}
	}
}

// Любая ошибка разбора не должна ломать интернет: пакет пропускаем как есть.
func (r *Runner) safeProcess(pkt []byte) (outs [][]byte, consumed bool) {
	defer func() {
		if e := recover(); e != nil {
			r.core.log(fmt.Sprint("ошибка обработки пакета: ", e))
			outs, consumed = nil, false
		}
	}()
	return r.core.Process(pkt)
}

func (r *Runner) Stop() {
	r.once.Do(func() { r.d.Close() })
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
	}
}

func (r *Runner) Done() <-chan struct{} { return r.done }

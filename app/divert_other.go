//go:build !windows

package main

import (
	"errors"
	"os"
)

// Заглушка для Linux/macOS: драйвера нет. Для проверки интерфейса можно задать BOGESTV0_FAKE.
type divertStub struct{ closed chan struct{} }

func openDivert(dir, filter string) (diverter, error) {
	if os.Getenv("BOGESTV0_FAKE") == "" {
		return nil, errors.New("перехват пакетов работает только в Windows")
	}
	return &divertStub{closed: make(chan struct{})}, nil
}
func (d *divertStub) Recv([]byte) (int, []byte, error) {
	<-d.closed
	return 0, nil, errors.New("closed")
}
func (d *divertStub) Send([]byte, []byte, bool) error { return nil }
func (d *divertStub) Close() error                    { close(d.closed); return nil }

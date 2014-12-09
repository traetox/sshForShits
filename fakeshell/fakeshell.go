package fakeshell

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

type fakeShell struct {
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
	closer   io.Closer
	prompt   string
	h        Handler
	doneChan chan error
	mtx      *sync.Mutex
	running  bool
}

type Handler interface {
	Handle(string, []string, io.Writer) (bool, error)
}

func New(prompt string, hn Handler) *fakeShell {
	return &fakeShell{
		prompt:   prompt,
		doneChan: make(chan error, 2),
		mtx:      &sync.Mutex{},
		running:  false,
		h:        hn,
	}
}

func (f *fakeShell) Wait() error {
	f.mtx.Lock()
	if !f.running {
		f.mtx.Unlock()
		return errors.New("not running")
	}
	f.mtx.Unlock()
	return <-f.doneChan
}

func (f *fakeShell) SetReadWriteCloser(rd io.Reader, wr io.Writer, cl io.Closer) {
	f.stdin = rd
	f.stdout = wr
	f.stderr = wr
	f.closer = cl
}

func (f *fakeShell) Start() error {
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if f.running {
		return errors.New("already running")
	}
	f.running = true
	go f.routine()
	return nil
}

func (f *fakeShell) routine() {
	rdr := bufio.NewReader(f.stdin)
	for {
		fmt.Fprintf(f.stdout, "%s", f.prompt)
		ln, err := rdr.ReadString('\n')
		if err != nil {
			break
		}
		ln = strings.TrimRight(ln, "\n\r")
		if len(ln) == 0 {
			continue
		}
		if ln == "exit" {
			break
		}
		flds := strings.Fields(ln)
		cmd := flds[0]
		var args []string
		if len(flds) > 1 {
			args = flds[1:len(flds)]
		} else {
			args = nil
		}
		ok, err := f.h.Handle(cmd, args, f.stdout)
		if err != nil {
			break
		}
		if !ok {
			fmt.Fprintf(f.stdout, "sh: %s: command not found\n", cmd)
		}
	}
	f.running = false
	f.doneChan <- f.closer.Close()
}

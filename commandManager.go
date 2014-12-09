package main

import (
	"errors"
	"io"
)

type processor func(args []string, out io.Writer) error

type hndler struct {
	funcs map[string]processor
}

func NewHandler() *hndler {
	return &hndler{
		funcs: make(map[string]processor, 3),
	}
}

func (h *hndler) Register(command string, proc processor) error {
	_, ok := h.funcs[command]
	if ok {
		return errors.New("Already registered")
	}
	h.funcs[command] = proc
	return nil
}

func (h *hndler) Handle(cmd string, args []string, out io.Writer) (bool, error) {
	hnd, ok := h.funcs[cmd]
	if !ok {
		//no handler ready for that command
		return false, nil
	}
	return true, hnd(args, out)
}

package main

import (
	"errors"
	"io"
	"strings"
)

type processor func(args []string, out io.Writer, state *State) error

type hndler struct {
	funcs map[string]processor
	state *State
}

type State struct {
	Files   []FakeFile //fake files which are "introduced to the session"
	History []string   //listing of previous commands for the '!!' and what not
}

type FakeFile struct {
	Path    string
	Content string
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
	err := hnd(args, out, h.state)
	if err != nil {
		h.state.History = append(h.state.History, cmd+strings.Join(args, " "))
	}
	return true, err
}

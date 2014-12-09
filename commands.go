package main

import (
	"fmt"
	"io"
)

func registerCommands(hnd *hndler) error {
	if err := hnd.Register("whoami", whoami); err != nil {
		return err
	}
	return nil
}

func whoami(args []string, out io.Writer) error {
	_, err := fmt.Fprintf(out, "root\n")
	return err
}

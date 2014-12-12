package main

import (
	"fmt"
	"io"
	"strings"
)

func registerCommands(hnd *hndler) error {
	if err := hnd.Register("whoami", whoami); err != nil {
		return err
	}
	if err := hnd.Register("id", id); err != nil {
		return err
	}
	if err := hnd.Register("curl", curl); err != nil {
		return err
	}
	if err := hnd.Register("ls", ls); err != nil {
		return err
	}
	return nil
}

func whoami(args []string, out io.Writer, state *State) error {
	_, err := fmt.Fprintf(out, "root\n")
	return err
}

func id(args []string, out io.Writer, state *State) error {
	_, err := fmt.Fprintf(out, "uid=0(root) gid=0(root) groups=0(root)\n")
	return err
}

func curl(args []string, out io.Writer, state *State) error {
	fileOut := false
	st := ""
	for i := range args {
		if args[i] == "-o" || args[i] == "-O" || args[i] == "--output" || args[i] == "--remote-name" {
			fileOut = true
		}
	}
	if fileOut {
		st = `
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                               Dload  Upload   Total   Spent    Left  Speed
100   219  100   219    0     0 490000      0 --:--:-- --:--:-- --:--:--   49243
`
	} else {
		st = `<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://shellsforshits.com/">here</A>.
</BODY></HTML>`
	}
	_, err := fmt.Fprintf(out, "%s\n", st)
	return err
}

func ls(args []string, out io.Writer, state *State) error {
	var dirs []string
	var err error
	for i := range args {
		if strings.HasPrefix(args[i], "-") {
			continue
		}
		dirs = append(dirs, args[i])
	}
	if len(dirs) == 0 {
		_, err := fmt.Fprintf(out, ". ..\n")
		return err
	}
	for i := range dirs {
		_, err = fmt.Fprintf(out, "ls: cannot access %s: No such file or directory\n", dirs[i])
	}
	return err
}

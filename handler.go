package main

import (
	"./fakeshell"
	"fmt"
	"github.com/traetox/pty"
	"golang.org/x/crypto/ssh"
	"io"
	"sync"
	"time"
)

const (
	pmpt = "sh-4.3$ "
)

func mainHandler(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, handler fakeshell.Handler, dg datagram) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go handleRequests(reqs, &wg)
	go handleChannels(chans, &wg, handler, dg)
	wg.Wait()
}

func handleRequests(reqs <-chan *ssh.Request, wg *sync.WaitGroup) {
	defer wg.Done()
	for _ = range reqs {
	}
}

func handleChannels(chans <-chan ssh.NewChannel, wg *sync.WaitGroup, handler fakeshell.Handler, dg datagram) {
	defer wg.Done()
	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		//fire up our fake shell
		c := fakeshell.New("sh-4.3$ ", handler, &dg)
		f, err := pty.StartFaker(c)
		if err != nil {
			continue
		}

		//teardown session
		var once sync.Once
		close := func() {
			channel.Close()
			c.Wait()
			dg.Logout = time.Now().Format(time.RFC3339Nano)
			activityClient.Write(dg)
		}

		//pipe session to bash and visa-versa
		go func() {
			io.Copy(channel, f)
			once.Do(close)
		}()
		go func() {
			io.Copy(f, channel)
			once.Do(close)
		}()

		// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell":
					// We don't accept any commands (Payload),
					// only the default shell.
					if len(req.Payload) == 0 {
						req.Reply(true, nil)
					} else {
						req.Reply(false, nil)
					}
				case "pty-req":
					// Responding 'ok' here will let the client
					// know we have a pty ready for input
					req.Reply(true, nil)
				case "window-change":
					continue //no response
				}
			}
		}(requests)
	}
}

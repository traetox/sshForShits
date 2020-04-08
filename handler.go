package main

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/traetox/pty"
	"github.com/traetox/sshForShits/fakeshell"
	"golang.org/x/crypto/ssh"
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
	conn.Close()
	conn.Conn.Close()
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
			errLog.Printf("Failed to Accept new channel: %v", err)
			continue
		}

		//fire up our fake shell
		c := fakeshell.New("sh-4.3$ ", handler, &dg)
		f, err := pty.StartFaker(c)
		if err != nil {
			errLog.Printf("Failed to start faker: %v", err)
			continue
		}

		//teardown session
		var once sync.Once
		close := func() {
			channel.Close()
			c.Wait()
			f.Close() //close the PTY device
			dg.Logout = time.Now().Format(time.RFC3339Nano)
			if len(dg.ShellActivity) > 0 {
				if err := activityClient.Write(dg); err != nil {
					errLog.Printf("Failed to write session: %v", err)
					if err := activityClient.Login(); err != nil {
						errLog.Printf("Failed to re-login after Write error: %v", err)
					}
				}
			}
		}

		//pipe session to bash and vice-versa
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

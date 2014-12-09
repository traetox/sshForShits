package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

var (
	logFile              = flag.String("l", "/tmp/ssh_attempts.log", "Log file to log SSH attempts")
	bindAddr             = flag.String("b", "", "Address to bind to, if nil, bind all")
	portNum              = flag.String("p", "22", "Port to bind to")
	keyFile              = flag.String("k", "/tmp/hostkey", "Host keyfile for the server")
	logger               *log.Logger
	hostPrivateKeySigner ssh.Signer
)

func init() {
	flag.Parse()
	if *logFile == "" {
		log.Panic("Invalid log output file")
	}
	fout, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	logger = log.New(fout, "", log.LstdFlags)
	hostPrivateKey, err := ioutil.ReadFile(*keyFile)
	if err != nil {
		panic(err)
	}

	hostPrivateKeySigner, err = ssh.ParsePrivateKey(hostPrivateKey)
	if err != nil {
		panic(err)
	}
}

func passAuth(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	var host string
	var err error
	if host, _, err = net.SplitHostPort(conn.RemoteAddr().String()); err != nil {
		host = conn.RemoteAddr().String()
	}
	logger.Printf("%s %s:%s\n", host, conn.User(), string(pass))
	return nil, nil
}

func main() {
	var port string
	config := ssh.ServerConfig{
		PasswordCallback: passAuth,
	}
	config.AddHostKey(hostPrivateKeySigner)
	if *portNum == "" {
		port = "2222"
	} else {
		port = *portNum
	}
	hnd := NewHandler()
	registerCommands(hnd)

	socket, err := net.Listen("tcp", *bindAddr+":"+port)
	if err != nil {
		panic(err)
	}
	failCount := 0
	for failCount < 10 {
		conn, err := socket.Accept()
		if err != nil {
			failCount++
			continue
		}

		// From a standard TCP connection to an encrypted SSH connection
		sshConn, chans, reqs, err := ssh.NewServerConn(conn, &config)
		if err != nil {
			failCount++
			continue
		}
		go mainHandler(sshConn, chans, reqs, hnd)
		failCount = 0
	}
	if failCount >= 10 {
		log.Printf("Bailed after %d errors\n", failCount)
	}
}

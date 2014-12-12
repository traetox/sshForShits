package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	logFile              = flag.String("l", "/tmp/ssh_attempts.log", "Log file to log SSH attempts")
	bindAddr             = flag.String("b", "", "Address to bind to, if nil, bind all")
	portNum              = flag.String("p", "22", "Port to bind to")
	keyFile              = flag.String("k", "/tmp/hostkey", "Host keyfile for the server")
	remoteServer         = flag.String("s", "ds063140.mongolab.com:63140", "mongodb server")
	mong_user            = flag.String("user", "", "mongodb user")
	mong_pass            = flag.String("pass", "", "mongodb password")
	db                   = flag.String("db", "sshforshits", "mongodb database")
	coll                 = flag.String("col", "pwns", "mongodb collection")
	setuidUser           = flag.String("suid", "nobody", "User to transition to if running as root")
	logger               *log.Logger
	hostPrivateKeySigner ssh.Signer
	activityClient       *shellActivityClient
	becomeUID            int
)

func init() {
	flag.Parse()
	if *remoteServer == "" {
		log.Panic("Invalid API server url")
	}
	if *mong_user == "" || *mong_pass == "" || *db == "" || *coll == "" {
		log.Panic("Empty mongo info")
	}
	if *logFile != "" {
		fout, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		logger = log.New(fout, "", log.LstdFlags)
	} else {
		logger = log.New(ioutil.Discard, "", log.LstdFlags)
	}
	hostPrivateKey, err := ioutil.ReadFile(*keyFile)
	if err != nil {
		panic(err)
	}

	hostPrivateKeySigner, err = ssh.ParsePrivateKey(hostPrivateKey)
	if err != nil {
		panic(err)
	}

	if *setuidUser != "" && os.Getuid() == 0 {
		usr, err := user.Lookup(*setuidUser)
		if err != nil {
			panic(err)
		}
		uid, err := strconv.Atoi(usr.Uid)
		if err != nil {
			panic(err)
		}
		becomeUID = uid
	}
	//clear the password from the command line args
}

func passAuth(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	var host string
	var err error
	if host, _, err = net.SplitHostPort(conn.RemoteAddr().String()); err != nil {
		host = conn.RemoteAddr().String()
	}
	logger.Printf("%s %s:%s\n", host, conn.User(), string(pass))
	creds := map[string]string{}
	creds["username"] = conn.User()
	creds["password"] = string(pass)
	perm := ssh.Permissions{
		CriticalOptions: nil,
		Extensions:      creds,
	}
	return &perm, nil
}

func main() {
	var err error
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
	activityClient, err = NewShellActivityClient(*remoteServer, *db, *coll, *mong_user, *mong_pass)
	if err != nil {
		panic(err)
	}
	if err = activityClient.Login(); err != nil {
		log.Printf("Failed to login, all writes will be cached until we can actually login")
		log.Printf("Error: \"%v\"\n", err)
	}

	socket, err := net.Listen("tcp", *bindAddr+":"+port)
	if err != nil {
		panic(err)
	}
	if becomeUID != 0 {
		if err := syscall.Setuid(becomeUID); err != nil {
			panic(err)
		}
	}
	defer socket.Close()
	for {
		conn, err := socket.Accept()
		if err != nil {
			log.Printf("Accept error: %v\n", err)
			continue
		}

		// From a standard TCP connection to an encrypted SSH connection
		sshConn, chans, reqs, err := ssh.NewServerConn(conn, &config)
		if err != nil {
			log.Printf("NewServerConn error: %v\n", err)
			continue
		}
		if sshConn.Permissions == nil {
			log.Printf("Failed to get ssh permissions\n")
			sshConn.Close()
			continue
		}
		if sshConn.Permissions.Extensions == nil {
			log.Printf("ssh permissions extensions are nil")
			sshConn.Close()
			continue
		}
		username, ok := sshConn.Permissions.Extensions["username"]
		if !ok {
			log.Printf("ssh permission extensions is missing the username")
			sshConn.Close()
			continue
		}
		password, ok := sshConn.Permissions.Extensions["password"]
		if !ok {
			log.Printf("ssh permission extensions is missing the password")
			sshConn.Close()
			continue
		}
		dg := datagram{
			Login: time.Now().Format(time.RFC3339Nano),
			Src:   sshConn.Conn.RemoteAddr().String(),
			Dst:   sshConn.Conn.LocalAddr().String(),
			User:  username,
			Pass:  password,
		}
		go mainHandler(sshConn, chans, reqs, hnd, dg)
	}
}

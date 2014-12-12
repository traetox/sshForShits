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
	pcoll                = flag.String("pcoll", "pwns", "mongodb shell activity collection")
	acoll                = flag.String("acoll", "attempts", "mongodb login attempts collection")
	versionBanner        = flag.String("v", "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2", "Banner to present")
	setuidUser           = flag.String("suid", "nobody", "User to transition to if running as root")
	logger               *log.Logger
	hostPrivateKeySigner ssh.Signer
	activityClient       *shellActivityClient
	attemptChan          chan attempt
	becomeUID            int
)

func init() {
	flag.Parse()
	if *remoteServer == "" {
		log.Panic("Invalid API server url")
	}
	if *mong_user == "" || *mong_pass == "" || *db == "" || *pcoll == "" || *acoll == "" {
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
	attemptChan = make(chan attempt, 16)
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
	attemptChan <- attempt{
		User:   conn.User(),
		Pass:   string(pass),
		TS:     time.Now().Format(time.RFC3339Nano),
		Origin: conn.RemoteAddr().String(),
	}
	return &perm, nil
}

func main() {
	var err error
	var port string
	config := ssh.ServerConfig{
		PasswordCallback: passAuth,
		ServerVersion:    *versionBanner,
	}
	config.AddHostKey(hostPrivateKeySigner)
	if *portNum == "" {
		port = "2222"
	} else {
		port = *portNum
	}
	hnd := NewHandler()
	registerCommands(hnd)
	activityClient, err = NewShellActivityClient(*remoteServer, *db, *pcoll, *acoll, *mong_user, *mong_pass)
	if err != nil {
		panic(err)
	}
	if err = activityClient.Login(); err != nil {
		log.Printf("Failed to login, all writes will be cached until we can actually login")
		log.Printf("Error: \"%v\"\n", err)
	}
	go attempter(activityClient)

	socket, err := net.Listen("tcp", *bindAddr+":"+port)
	if err != nil {
		panic(err)
	}
	if becomeUID != 0 {
		if err := syscall.Setuid(becomeUID); err != nil {
			panic(err)
		}
		if os.Getuid() == 0 {
			log.Panic("Failed to actually change the uid!\n")
		}
		log.Printf("Transitioned to uid %d\n", becomeUID)
	}
	defer socket.Close()
	for {
		conn, err := socket.Accept()
		if err != nil {
			continue
		}

		// From a standard TCP connection to an encrypted SSH connection
		sshConn, chans, reqs, err := ssh.NewServerConn(conn, &config)
		if err != nil {
			conn.Close()
			continue
		}
		if sshConn.Permissions == nil {
			log.Printf("Failed to get ssh permissions\n")
			sshConn.Close()
			conn.Close()
			continue
		}
		if sshConn.Permissions.Extensions == nil {
			log.Printf("ssh permissions extensions are nil")
			sshConn.Close()
			conn.Close()
			continue
		}
		username, ok := sshConn.Permissions.Extensions["username"]
		if !ok {
			log.Printf("ssh permission extensions is missing the username")
			sshConn.Close()
			conn.Close()
			continue
		}
		password, ok := sshConn.Permissions.Extensions["password"]
		if !ok {
			log.Printf("ssh permission extensions is missing the password")
			sshConn.Close()
			conn.Close()
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

func attempter(sac *shellActivityClient) {
	var ats []attempt
	for at := range attemptChan {
		if err := sac.WriteAttempt(at); err != nil {
			ats = append(ats, at)
			if err = sac.Login(); err != nil {
				time.Sleep(10 * time.Second)
				continue
			}
		}
		//a write worked, try to clear the backlog
		i := 0
	wloop:
		for i = 0; i < len(ats); i++ {
			if err := sac.WriteAttempt(ats[i]); err != nil {
				break wloop
			}
		}
		if i == len(ats) {
			//we got everything out
			ats = nil
		} else {
			ats = ats[i:len(ats)]
		}
	}
}

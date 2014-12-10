package main

import (
	"container/list"
	"errors"
	"fmt"
	"sync"
	"time"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	defaultTimeout = time.Second * 2
)

type datagram struct {
	Login         string    `json:"login"`
	Logout        string    `json:"logout"`
	Src           string    `json:"src"`
	Dst           string    `json:"dst"`
	User          string    `json:"user"`
	Pass          string    `json:"pass"`
	ShellActivity []command `json:"shell_activity"`
}

type command struct {
	TS   string `json:"ts"`
	Cmd  string `json:"cmd"`
	Resp string `json:"resp"`
}

type shellActivityClient struct {
	user       string
	pass       string
	dst        string
	db         string
	collection string
	session    *mgo.Session
	status     bool
	headers    map[string]string
	mtx        *sync.Mutex
	cache      *list.List
}

func NewShellActivityClient(dst, db, collection, user, pass string) (*shellActivityClient, error) {
	return &shellActivityClient{
		user:       user,
		pass:       pass,
		dst:        dst,
		db:         db,
		collection: collection,
		headers:    make(map[string]string, 1),
		mtx:        &sync.Mutex{},
		cache:      list.New(),
	}, nil
}

//do the actual login work
func (sac *shellActivityClient) login() error {
	var err error
	uri := fmt.Sprintf("mongodb://%s:%s@%s/%s", sac.user, sac.pass, sac.dst, sac.db)
	sac.session, err = mgo.Dial(uri)
	if err != nil {
		return err
	}
	sac.status = true
	return nil
}

//Login will renew creds with the remote server
//it is totally ok to hit this over and over
func (sac *shellActivityClient) Login() error {
	sac.mtx.Lock()
	defer sac.mtx.Unlock()
	return sac.login()
}

func (sac *shellActivityClient) Close() error {
	sac.mtx.Lock()
	defer sac.mtx.Unlock()
	if sac.status && sac.session != nil {
		//attempt to send everything in the cache
		for {
			dg, err := sac.popCache()
			if err != nil || dg == nil {
				break
			}
			if err = sac.sendDatagram(dg); err != nil {
				break
			}
		}
	}
	sac.session.Close()
	sac.status = false
	return nil
}

func (sac *shellActivityClient) sendDatagram(dg *datagram) error {
	collection := sac.session.DB(sac.db).C(sac.collection)
	if err := collection.Insert(dg); err != nil {
		return err
	}
	return nil
}

func (sac *shellActivityClient) Write(dg datagram) error {
	sac.mtx.Lock()
	defer sac.mtx.Unlock()
	if !sac.status {
		sac.pushCache(dg)
		return errors.New("Client closed")
	}
	for {
		d, err := sac.popCache()
		if err != nil {
			return err
		}
		//cache is empty
		if d == nil {
			break
		}
		if err := sac.sendDatagram(d); err != nil {
			return err
		}
	}
	return sac.sendDatagram(&dg)
}

func (sac *shellActivityClient) Cache(dg datagram) error {
	sac.mtx.Lock()
	defer sac.mtx.Unlock()
	if !sac.status {
		return errors.New("Client closed")
	}
	return sac.pushCache(dg)
}

func (sac *shellActivityClient) pushCache(dg datagram) error {
	if sac.cache.PushBack(dg) == nil {
		return errors.New("Failed push")
	}
	return nil
}

func (sac *shellActivityClient) popCache() (*datagram, error) {
	if sac.cache.Len() <= 0 {
		return nil, nil
	}
	e := sac.cache.Front()
	if e == nil {
		return nil, nil
	}
	dg, ok := e.Value.(datagram)
	if !ok {
		return nil, errors.New("Invalid item in cache")
	}
	return &dg, nil
}

func (dg *datagram) AddCommand(cmd, resp string) error {
	ts := time.Now().Format(time.RFC3339Nano)
	dg.ShellActivity = append(dg.ShellActivity, command{ts, cmd, resp})
	return nil
}

type msg struct {
	Id    bson.ObjectId `bson:"_id"`
	Msg   string        `bson:"msg"`
	Count int           `bson:"count"`
}

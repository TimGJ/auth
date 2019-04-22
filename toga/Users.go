package toga

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

type Users struct{ Users map[string]*User }

func (u *Users) Write(w io.Writer) error {
	var r []*User
	var s *User
	var err error
	var b []byte
	var writer = bufio.NewWriter(w)

	for _, s = range u.Users {
		r = append(r, s)
	}
	if b, err = json.MarshalIndent(r, "", "  "); err != nil {
		return err
	}
	if _, err = writer.Write(b); err != nil {
		return err
	}
	if err = writer.Flush(); err != nil {
		return err
	}
	return nil
}

func (u *Users) Read(reader io.Reader) error {
	var b []byte
	var err error
	var recs []*User
	var rec *User
	if b, err = ioutil.ReadAll(reader); err != nil {
		return err
	}
	if err = json.Unmarshal(b, &recs); err != nil {
		return err
	}
	for _, rec = range recs {
		u.Users[rec.UserName] = rec
	}
	return nil
}

func ReadUsersFile(name string) (*Users, error) {
	var f *os.File
	var err error
	var u = NewUsers()

	if f, err = os.Open(name); err != nil {
		return u, err
	}
	defer f.Close()
	if err = u.Read(f); err != nil {
		return u, err
	}
	return u, nil
}

func (u *Users) WriteFile(name string) error {
	var f *os.File
	var err error

	if f, err = os.Create(name); err != nil {
		return err
	}
	defer f.Close()
	if err = u.Write(f); err != nil {
		return err
	}
	return nil
}

func (u *Users) Add(username, realname, password string, privs PrivMask) error {
	var ok bool
	var v *User
	var err error
	username = strings.ToLower(username)
	if _, ok = u.Users[username]; ok {
		return fmt.Errorf("User %s already exists", username)
	}
	if v, err = CreateUser(username, realname); err != nil {
		return err
	}
	if err = v.SetPassword(password); err != nil {
		return err
	}
	v.Grant(privs)
	u.Users[v.UserName] = v
	return nil
}

func NewUsers() *Users {
	var u = new(Users)
	u.Users = make(map[string]*User)
	return u
}

func (u *Users) GetUser(name string) *User {
	// Returns a pointer to the specified username or nil if it doesn't exist.
	var v *User
	var ok bool

	if v, ok = u.Users[strings.ToLower(name)]; ok {
		return v
	}
	return nil
}



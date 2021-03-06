package main

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
)

type PrivMask uint64

const (
	PRV_READ = PrivMask(1 << iota)
	PRV_WRITE
	PRV_DELETE
	PRV_EXECUTE
)

func (p PrivMask) String() string {
	var v []string // List of the privileges associated with the mask
	var i uint     // Generic counter
	var m PrivMask // Mask associated with a particular privilege
	var k PrivMask
	var n string // Name associated with that mask
	var ok bool  // Does such a mask exist

	for i = 0; i < 64; i++ {
		m = 1 << i
		k = m & p
		if k != 0 {
			if n, ok = Privileges[m]; ok {
				v = append(v, n)
			}
		}
	}
	return strings.Join(v, "|")
}

var Privileges = map[PrivMask]string{
	PRV_READ:    "PRV_READ",
	PRV_WRITE:   "PRV_WRITE",
	PRV_DELETE:  "PRV_DELETE",
	PRV_EXECUTE: "PRV_EXECUTE",
}

type User struct {
	UserName   string
	RealName   string
	Password   [64]byte
	Privileges PrivMask
}

func (u User) String() string {
	var b64 = base64.StdEncoding.EncodeToString(u.Password[:])
	return fmt.Sprintf("%s (%s) %s %s", u.UserName, u.RealName, b64, u.Privileges)
}

func CreateUser(user, real string) (*User, error) {
	var u = new(User)
	// Validate username. Must be at least three alphanumeric starting with initial alpha
	var usernamere = regexp.MustCompile(`(?i)^[A-Z][A-Z0-9]{2,}$`)
	if !usernamere.MatchString(user) {
		return u, fmt.Errorf("Invalid username %s", user)
	}
	u.UserName = user
	u.RealName = real
	return u, nil
}

func (u *User) SetPassword(p string) error {
	// Sets the password to the hashed value of p
	const MinPassLen = 4

	if len(p) == 0 {
		return fmt.Errorf("Password may not be blank")
	}
	if len(p) < MinPassLen {
		return fmt.Errorf("Password too short. Must be a minimum of %d characters", len(p))
	}
	u.Password = u.HashPassword(p)
	return nil
}

func (u *User) HashPassword(p string) [64]byte {
	// Hashes a password. Broken into a separate function so we only have one
	// canonical implementation which may be called from various places
	var b = []byte(p)
	var h = sha512.Sum512(b)
	return h
}

func (u *User) HasPrivilege(p PrivMask) bool {
	return (u.Privileges & p) == p
}

func (u *User) Grant(p PrivMask) {
	// Set the appropriate bit(s)... i.e. a bitwise OR
	u.Privileges |= p
}

func (u *User) Revoke(p PrivMask) {
	// Clear the appopriate bits... i.e. a bitwise NAND
	u.Privileges &^= p
}

func (u *User) Authenticate(p string) bool {
	// Does p hash to the same value as stored for the user
	var h = u.HashPassword(p)
	return bytes.Compare(u.Password[:], h[:]) == 0
}

func ParsePrivilegeMaskString(s string) (PrivMask, error) {
	// Passed a string e.g. PRV_READ|PRV_WRITE returns the corresponding mask
	var p PrivMask
	var v string
	var t string
	var k PrivMask
	var ok bool

	// Invert the dictionary that maps PrivMask to string.
	var d = make(map[string]PrivMask)

	for k, v = range Privileges {
		d[v] = k
	}

	// Convert the input string into tokens. If a token is in the dictionary then
	// set the relevant privilege bit, otherwise throw an error

	for _, t = range strings.Split(s, "|") {
		if _, ok = d[t]; ok {
			p |= d[t]
		} else {
			return p, fmt.Errorf("Unknown privelege %s", t)
		}
	}
	return p, nil
}

// We need to read and write users to JSON and have to handle binary gubbins like passwords and privileges.

func (u *User) MarshalJSON() ([]byte, error) {
	var bob = strings.Builder{}
	bob.WriteString(`{`)
	bob.WriteString(fmt.Sprintf(`"username": "%s",`, u.UserName))
	bob.WriteString(fmt.Sprintf(`"realname": "%s",`, u.RealName))
	bob.WriteString(fmt.Sprintf(`"password": "%s",`, base64.StdEncoding.EncodeToString(u.Password[:])))
	bob.WriteString(fmt.Sprintf(`"privileges": "%s"`, u.Privileges.String()))

	bob.WriteString(`}`)
	return []byte(bob.String()), nil
}

func (u *User) UnmarshalJSON(b []byte) error {
	var stuff map[string]string
	var err error
	var ok bool
	var s string
	var buf []byte
	var p PrivMask

	if err = json.Unmarshal(b, &stuff); err != nil {
		return err
	}

	if s, ok = stuff["username"]; ok { // Username is mandatory
		u.UserName = s
	} else {
		return fmt.Errorf("No username specified")
	}

	if s, ok = stuff["realname"]; ok {
		u.RealName = s
	}

	if s, ok = stuff["password"]; ok {
		if buf, err = base64.StdEncoding.DecodeString(s); err != nil {
			return err
		} else {
			if len(buf) != 64 {
				return fmt.Errorf("Corrupt password detected for user %s", u.UserName)
			}
			copy(u.Password[:], buf)
		}
	} else {
		return fmt.Errorf("No password specified for user %s", u.UserName)
	}

	// Now read the privileges

	if s, ok = stuff["privileges"]; ok {
		if p, err = ParsePrivilegeMaskString(s); err != nil {
			return err
		}
		u.Privileges = p
	}
	return nil
}

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

func main() {
	var err error
	var users *Users
	var t *User
	if users, err = ReadUsersFile("password.json"); err != nil {
		fmt.Println(err.Error())
	} else {
		if t = users.GetUser("tim"); t != nil {
			fmt.Println(t)
			for _, p := range []string{"susages", "sausages", "Sausages", "marmalade"} {
				fmt.Println(p, t.Authenticate(p))
			}
		}
	}

}

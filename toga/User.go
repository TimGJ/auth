package toga

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

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
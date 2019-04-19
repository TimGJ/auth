package main

import (
	"crypto/sha512"
	"fmt"
	"regexp"
)

type User struct {
	UserName string
	RealName string
	Password [64]byte
}

func (u User) String() string {
	return fmt.Sprintf("%s (%s) %x", u.UserName, u.RealName, u.Password)
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

func (u *User) SetPassword(p string) {
	// Sets the password to the hashed value of p
	var b = []byte(p)
	var h = sha512.Sum512(b)
	u.Password = h
}
func main() {

	if u, err := CreateUser("TimGreeningJackson", "Tim Greening-Jackson"); err != nil {
		fmt.Println(err.Error())

	} else {
		fmt.Println(u.String())
		u.SetPassword("sausages")
		fmt.Println(u.String())
	}
}

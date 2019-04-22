package toga

import (
	"fmt"
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
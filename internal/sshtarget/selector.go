// Package sshtarget validates textual SSH selectors without consulting DNS.
package sshtarget

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var dns = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

func Key(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(host)
}

func ValidHost(host string) bool {
	return net.ParseIP(host) != nil || len(host) <= 253 && dns.MatchString(host)
}

// Split accepts DNS names, IP literals, and host:port ([IPv6]:port).
func Split(s string) (string, int, error) {
	if ValidHost(s) {
		return Key(s), 0, nil
	}
	h, p, err := net.SplitHostPort(s)
	n, pe := strconv.Atoi(p)
	if err != nil || pe != nil || !ValidHost(h) || n < 1 || n > 65535 || strconv.Itoa(n) != p {
		return "", 0, fmt.Errorf("invalid SSH target %q (expected host or host:port)", s)
	}
	return Key(h), n, nil
}

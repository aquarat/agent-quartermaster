// agefixture creates a throwaway offline owner identity in the interop test's
// private directory. Only the public recipient goes to stdout.
package main

import (
	"filippo.io/age"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	key, err := age.GenerateX25519Identity()
	if err != nil {
		panic(err)
	}
	f, err := os.OpenFile(os.Args[1], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	if _, err = fmt.Fprintln(f, key.String()); err != nil {
		panic(err)
	}
	if err = f.Close(); err != nil {
		panic(err)
	}
	fmt.Println(key.Recipient().String())
}

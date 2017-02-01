package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/boynton/ca/https"
)

func main() {
	identity := "localhost"
	if len(os.Args) > 1 {
		if os.Args[1] == "-h" {
			fmt.Println("usage: server [identity]")
			os.Exit(0)
		}
		identity = os.Args[1]
	}
	err := https.Serve(identity, 4443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := https.ClientIdentity(r)
		if user == "" {
			fmt.Println("[Not authenticated: no client certs found]")
			w.WriteHeader(401)
			fmt.Fprintf(w, "Unauthorized\n")
		} else {
			fmt.Printf("[Authenticated '%s' from TLS client cert]\n", user)
			w.WriteHeader(200)
			fmt.Fprintf(w, "OK\n")
		}
	}))
	fmt.Println("***", err)
}

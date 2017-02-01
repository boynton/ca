package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/boynton/ca/https"
)

func main() {
	serverIdentity := "localhost"
	clientIdentity := os.Getenv("USER")
	if len(os.Args) > 1 {
		if os.Args[1] == "-h" {
			fmt.Println("usage: client [serverIdentity [clientIdentity]]")
			os.Exit(0)
		}
		serverIdentity = os.Args[1]
		if len(os.Args) > 2 {
			clientIdentity = os.Args[2]
		}
	}
	hclient, err := https.Client(clientIdentity, serverIdentity)
	if err != nil {
		panic(err)
	}
	req, err := http.NewRequest("GET", "https://localhost:4443/", nil)
	if err != nil {
		panic(err)
	}
	resp, err := hclient.Do(req)
	if err != nil {
		panic(err)
	}
	content, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		panic(err)
	}
	fmt.Println("status, content:", resp.StatusCode, string(content))
}

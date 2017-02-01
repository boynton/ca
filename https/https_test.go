package https

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/boynton/ca"
)

func TestHttps(test *testing.T) {
	ca.SetDir("test_root/")
	os.RemoveAll(ca.Dir())
	err := ca.EnsureDir()
	if err != nil {
		test.Errorf("Cannot ensure CA directory: %v", err)
		return
	}
	conf, err := ca.GenerateDefaultConfig()
	if err != nil {
		test.Errorf("Cannot create default config: %v", err)
		return
	}
	err = ca.Init(conf)
	if err != nil {
		test.Errorf("Cannot init CA: %v", err)
		return
	}
	err = ca.CreateCert(conf, "test_server", "", "", "")
	if err != nil {
		test.Errorf("Cannot create server cert for test: %v", err)
		return
	}
	err = ca.CreateCert(conf, "test_client", "", "", "")
	if err != nil {
		test.Errorf("Cannot create client cert for test: %v", err)
		return
	}

	go testServer(test, "test_server")
	time.Sleep(1 * time.Second)
	testClient(test, "test_client", "test_server")
}

func testServer(test *testing.T, identity string) {
	err := Serve(identity, 4443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ClientIdentity(r)
		if user == "" {
			fmt.Println("[Not authenticated: no client certs found]")
			w.WriteHeader(401)
			fmt.Fprintf(w, "Unauthorized")
		} else {
			fmt.Printf("[Authenticated '%s' from TLS client cert]\n", user)
			w.WriteHeader(200)
			fmt.Fprintf(w, "OK")
		}
	}))
	if err != nil {
		test.Errorf("Cannot run server: %v", err)
	}
}

func testClient(test *testing.T, identity, serverIdentity string) {
	hclient, err := Client(identity, serverIdentity)
	if err != nil {
		test.Errorf("fail: cannot create client:", err)
		return
	}
	req, err := http.NewRequest("GET", "https://localhost:4443/", nil)
	if err != nil {
		test.Errorf("fail: cannot form GET request:", err)
		return
	}
	resp, err := hclient.Do(req)
	if err != nil {
		test.Errorf("fail: cannot perform GET request:", err)
		return
	}
	content, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		test.Errorf("no response content:", err)
		return
	}
	if resp.StatusCode == 200 && string(content) == "OK" {
		fmt.Printf("[got expected response (%d): %s]\n", resp.StatusCode, string(content))
	} else {
		test.Errorf("Enexpected response: (%v) %s", resp.StatusCode, string(content))
	}
}

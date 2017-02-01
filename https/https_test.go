package https

import (
	"fmt"
	"net/http"
	"os"
	"testing"
)

func TestHttps(test *testing.T) {
	dir = "./test_root/"
	os.RemoveAll(ca.Dir())
	err := ca.EnsureDir()
	if err != nil {
		test.Errorf("Cannot ensure CA directory: %v", err)
		return
	}
	_, err = ca.GenerateDefaultConfig()
	if err != nil {
		test.Errorf("Cannot create default config: %v", err)
		return
	}
	err = ca.CreateCert(conf, "test_server", "", "", "")
	if err != nil {
		test.Errorf("Cannot create server cert for test: %v", err)
		return
	}
	err = CreateCert(conf, "test_client", "", "", "")
	if err != nil {
		test.Errorf("Cannot create client cert for test: %v", err)
		return
	}

	go testServer("test_server")
	time.Sleep(1 * time.Second)
	testClient("test_client")
}

func testServer(identity string) {
	err = Serve(identity, 4443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func testClient(identity string) {
	hclient, err := Client(identity)
	if err != nil {
		fmt.Println("fail: cannot create client:", err)
	}
	req, err := http.NewRequest("GET", "https://"+identity+":4443/", nil)
	if err != nil {
		fmt.Println("fail: cannot form GET request:", err)
		return
	}
	resp, err := hclient.Do(req)
	if err != nil {
		fmt.Println("fail: cannot perform GET request:", err)
		return
	}
	content, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Println("no response content:", err)
		return
	}
	if resp.StatusCode == 200 && string(content) == "OK" {
		fmt.Printf("OK: got expected response (%d): %s\n", resp.StatusCode, string(content))
	} else {
		fmt.Println("FAIL: unexpected response")
	}
}

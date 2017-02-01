package ca

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func testConfig(test *testing.T, dir string) bool {
	os.RemoveAll(Dir())
	err := EnsureDir()
	if err != nil {
		test.Errorf("Cannot ensure CA directory: %v", err)
		return false
	}
	_, err = GenerateDefaultConfig()
	if err != nil {
		test.Errorf("Cannot create default config: %v", err)
		return false
	}

	conf, err := ReadConfig()
	if err != nil {
		test.Errorf("Cannot read config: %v", err)
		return false
	}
	if conf.Name == "" || conf.Country == "" || conf.Locality == "" || conf.Province == "" || conf.Organization == "" {
		test.Errorf("config has some empty values")
		return false
	}
	return true
}

func TestInit(test *testing.T) {
	dir = "./test_root/"
	fmt.Printf("[using test ca dir: '%s']\n", Dir())
	if !testConfig(test, dir) {
		return
	}
	conf, err := ReadConfig()
	if err != nil {
		test.Errorf("Cannot read config: %v", err)
		return
	}
	err = Init(conf)
	if err != nil {
		test.Errorf("Cannot initialize CA: %v", err)
		return
	}
	host, err := os.Hostname()
	if err != nil {
		test.Errorf("Cannot get hostname for test: %v", err)
		return
	}
	err = CreateCert(conf, host, "", "", "")
	if err != nil {
		test.Errorf("Cannot create server cert for test: %v", err)
		return
	}
	fmt.Println("[signed  host cert successfully]")
	user := os.Getenv("USER")
	err = CreateCert(conf, user, "", "", "")
	if err != nil {
		test.Errorf("Cannot create client cert for test: %v", err)
		return
	}
	fmt.Println("[signed  client cert successfully]")
	/*
		fmt.Println("\nTo authenticate with client cert using Mac OS X version of curl, do the following:")
		fmt.Println("  openssl pkcs12 -password pass:foo -export -in test_root/" + user + ".cert -inkey test_root/" + user + ".key -out test_root/" + user + ".p12")
		fmt.Println("Then:\n  curl --cacert test_root/ca.cert -E ./test_root/" + user + ".p12:foo https://" + host + ":4443/")
	*/

	go testServer(host)
	time.Sleep(1 * time.Second)
	testClient(host)
	testClientUnauthorized(host)
	testClientUnknown(host)
}

func testClient(host string) {
	capem, err := ioutil.ReadFile(Dir() + "/ca.cert")
	if err != nil {
		fmt.Println("Cannot read CA key:", err)
		return
	}
	config := &tls.Config{}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(capem) {
		fmt.Println("Cannot append certs to pool")
		return
	}
	config.RootCAs = certPool
	user := os.Getenv("USER")
	keypem, err := ioutil.ReadFile(Dir() + "/" + user + ".key")
	if err != nil {
		fmt.Println("Cannot read client key:", err)
		return
	}
	certpem, err := ioutil.ReadFile(Dir() + "/" + user + ".cert")
	if err != nil {
		fmt.Println("Cannot read user key:", err)
		return
	}
	mycert, err := tls.X509KeyPair(certpem, keypem)
	if err != nil {
		fmt.Println("Cannot form keypair:", err)
		return
	}
	config.Certificates = []tls.Certificate{mycert}
	config.ClientCAs = certPool
	config.ClientAuth = tls.VerifyClientCertIfGiven
	config.CipherSuites = []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}
	config.MinVersion = tls.VersionTLS12
	config.SessionTicketsDisabled = true

	tr := &http.Transport{
		TLSClientConfig: config,
	}
	hclient := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "https://"+host+":4443/", nil)
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

func testClientUnauthorized(host string) {
	//no client cert. We should still be able to connect and get a 401, though
	capem, err := ioutil.ReadFile(Dir() + "/ca.cert")
	if err != nil {
		fmt.Println("Cannot read CA key:", err)
		return
	}
	config := &tls.Config{}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(capem) {
		fmt.Println("Cannot append certs to pool")
		return
	}
	config.RootCAs = certPool
	config.CipherSuites = []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}
	config.MinVersion = tls.VersionTLS12
	config.SessionTicketsDisabled = true

	tr := &http.Transport{
		TLSClientConfig: config,
	}
	hclient := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "https://"+host+":4443/", nil)
	if err != nil {
		fmt.Println("FAIL: could not form request")
		return
	}
	resp, err := hclient.Do(req)
	if err != nil {
		fmt.Println("FAIL: could not execute request")
		return
	}
	content, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Println("no response content:", err)
		return
	}
	if resp.StatusCode == 401 {
		fmt.Printf("OK: expected response (%d) received with no client cert: %s\n", resp.StatusCode, string(content))
	} else {
		fmt.Println("FAIL: unexpected response")
	}

}
func testClientUnknown(host string) {
	//no client cert or ca cert.
	config := &tls.Config{}
	config.CipherSuites = []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}
	config.MinVersion = tls.VersionTLS12
	config.SessionTicketsDisabled = true

	tr := &http.Transport{
		TLSClientConfig: config,
	}
	hclient := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "https://"+host+":4443/", nil)
	if err != nil {
		fmt.Println("FAIL: Cannot form request:", err)
		return
	}
	resp, err := hclient.Do(req)
	if err != nil {
		if strings.Index(fmt.Sprint(err), "unknown authority") >= 0 {
			fmt.Println("OK: Expected error for not knowing CA:", err)
			return
		}
		fmt.Println("FAIL: unexpected error:", err)
		return
	}
	fmt.Println("FAIL: unexpected response:", resp.StatusCode)
}

func testServer(host string) {
	capem, err := ioutil.ReadFile(Dir() + "/ca.cert")
	if err != nil {
		fmt.Println("Cannot read CA key:", err)
		return
	}
	keypem, err := ioutil.ReadFile(Dir() + "/" + host + ".key")
	if err != nil {
		fmt.Println("Cannot read server key:", err)
		return
	}
	certpem, err := ioutil.ReadFile(Dir() + "/" + host + ".cert")
	if err != nil {
		fmt.Println("Cannot read server key:", err)
		return
	}
	mycert, err := tls.X509KeyPair(certpem, keypem)
	if err != nil {
		fmt.Println("Cannot form server key:", err)
		return
	}
	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = mycert

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(capem) {
		fmt.Println("Cannot append certs to pool")
		return
	}
	config.ClientCAs = certPool

	//config.ClientAuth = tls.RequireAndVerifyClientCert
	config.ClientAuth = tls.VerifyClientCertIfGiven

	config.CipherSuites = []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}
	config.MinVersion = tls.VersionTLS12
	config.SessionTicketsDisabled = true

	handler := authorizeHandler(http.FileServer(http.Dir(".")))
	listener, err := tls.Listen("tcp", host+":4443", config)
	if err != nil {
		panic(err)
	}
	log.Fatal(http.Serve(listener, handler))
}

func authorizeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, cert := range r.TLS.PeerCertificates {
			fmt.Printf("[Server: Authenticated '%s' from TLS client cert]\n", cert.Subject.CommonName)
			w.WriteHeader(200)
			fmt.Fprintf(w, "OK")
			return
		}
		fmt.Println("[Server: no certs found]")
		w.WriteHeader(401)
		fmt.Fprintf(w, "Unauthorized")
	})
}

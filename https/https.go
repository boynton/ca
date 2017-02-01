package https

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github/boynton.com/ca"
)

func Client(identity string) (*http.Client, error) {
	tr, err := ClientTransport(identity)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: tr}, nil
}

func ClientTransport(identity string) (*http.Transport, error) {
	conf, err := TLSConfig(identity)
	if err != nil {
		return nil, err
	}
	return &http.Transport{TLSClientConfig: config}
}

// RunServer - run an https server with the given identity (hostname) on the given port,
// using the given handler. The handler can call https.ClientIdentity() to get the CN
// of the client, if the client presents a valid client cert.
func Serve(identity string, port int, handler http.Handler) error {
	conf, err := TLSConfig(identity)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s:%d", identity, port)
	listener, err := tls.Listen("tcp", endpoint, conf)
	if err != nil {
		return err
	}
	log.Printf("[Listening for requests at https://%s/]\n", endpoint)
	return http.Serve(listener, handler)
}

// ClientIdentity - returns the client's identity (cert.Subject.CommonName) for requests
// that provided a valid client cert, "" returned in all other cases.
func ClientIdentity(r *http.Request) string {
	for _, cert := range r.TLS.PeerCertificates {
		return cert.Subject.CommonName
	}
	return ""
}

// TLSConfig - for a given identity (hostname), return a *tls.Config that uses
// the certs managed by the CA to both listen for on a cert and recognize client certs
// signed by the CA. This same config works for both server and client.
func TLSConfig(identity string) (*tls.Config, error) {
	dir := ca.Dir()
	capem, err := ioutil.ReadFile(dir + "ca.cert")
	if err != nil {
		return nil, err
	}
	keypem, err := ioutil.ReadFile(dir + identity + ".key")
	if err != nil {
		return nil, err
	}
	certpem, err := ioutil.ReadFile(dir + identity + ".cert")
	if err != nil {
		return nil, err
	}
	mycert, err := tls.X509KeyPair(certpem, keypem)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = mycert

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(capem) {
		return nil, fmt.Errorf("Cannot append certs to TLS certificate pool")
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

	return config, nil
}

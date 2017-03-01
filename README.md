# ca
A simple X.509 Certificate Authority written in Go

The CA itself is self-signed, but the certs it generates can all be used by trusting the CA's cert. This is
useful for testing services requiring TLS client cert authentication.

## Overview

The keys and certs are stored in ~/.ca/{keys,certs}. As in your ~/.ssh directory, be careful with how visible
this is. You can set the CA environment variable to specify a different directory than the default.

## Installation

    $ go get github.com/boynton/ca/...

This gets the project and builds an installs the utility `ca`. It also makes available the Go library that
makes it easier to set up both clients and servers with the certs it manages.

## Usage

### Initialization

You must first initialize the CA:

    $ ca init

This creates the key/cert storage directory, and generates the CA's root cert to sign things with. After this
call, the ~/.ca/certs/ca.cert file contains the public certificate you should distribute to servers and clients
to verify signatures on all other certs the CA generates.

A default config file (~/.ca/config) is also created. You probably want to modify its attributes to make your CA
unique. If thee values are changed, run `ca init` again to regenerate the root certs. If the config change date is
not later than the ca.key.pem file date, nothing will be done.

Note also that if you have your own actual signing cert, perhaps obtained elsewhere, you can also copy it into the ~/.ca
directory with the proper name, or set the `root-key-path` and `root-cert-path` attributes to point at them. They must
be PEM-encoded.

Note that when you run `ca init` again, your previously generated certs can no longer be validated.


### Creating certificates

You can generate a new TLS certificate for a server as follows:

    $ ca create foobar

The value `foobar` is used in this case as the _identity_, the Common Name (CN) of the cert. The name of the resulting
files is also based on that value, i.e. it generates the two files `~/.ca/keys/foobar.key.pem` and `~/.ca/certs/foobar.cert.pem`.

The value for a server cert would likely be the DNS name the server is reached as. For local testing, this probably
can be `hostname`.

### Reading certificates

The listing of all certs can be queried for:

    $ ca list
    ca
    foobar

And then individual certs can be read to show the summary (not all) information:

    $ ca read foobar
        Version: 3
        Serial Number: 28:c9:f0:a6:fd:9b:f2:19:b5:8f:4a:31:19:1f:53:18
        Signature algorithm: SHA256-RSA
        Issuer: C=US, ST=Oregon, L=Stafford, O=Boynton, OU=Example, CN=CA
        Not valid before 2017-02-01 01:08:33 +0000 UTC
        Not valid after 2018-02-01 01:08:33 +0000 UTC
        Subject: C=US, ST=Oregon, L=Stafford, O=Boynton, OU=Example, CN=foobar
        Subject public key algorithm: RSA (4096 bit)
        Key Usage: Digital Signature, Key Encipherment

These are standard x.509 certs, compatible with openssl:

    $ openssl x509 -noout -text -in  ~/.ca/foobar.cert
	Certificate:
	    Data:
	        Version: 3 (0x2)
	        Serial Number:
	            28:c9:f0:a6:fd:9b:f2:19:b5:8f:4a:31:19:1f:53:18
	        Signature Algorithm: sha256WithRSAEncryption
	        Issuer: C=US, ST=Oregon, L=Stafford, O=Boynton, OU=Example, CN=CA
	        Validity
	            Not Before: Feb  1 01:08:33 2017 GMT
	            Not After : Feb  1 01:08:33 2018 GMT
	        Subject: C=US, ST=Oregon, L=Stafford, O=Boynton, OU=Example, CN=foobar
	        Subject Public Key Info:
	            Public Key Algorithm: rsaEncryption
	            RSA Public Key: (4096 bit)
	                Modulus (4096 bit):
	                    00:af:0c:47:a6:20:d7:24:b5:55:d8:26:e8:8a:48:
	                    0b:b1:72:d4:c5:a4:38:8c:88:10:1b:b3:3a:75:7a:
	                    fd:37:5d:a4:ef:fb:8d:45:dc:c8:36:25:9e:46:53:
	                    60:dd:0d:18:99:f5:6a:fa:11:4b:9c:4b:0f:1c:92:
	                    b7:bf:96:bb:c7:d4:aa:3e:a0:4c:70:42:4f:d3:c8:
	                    fe:40:bf:ef:6e:da:92:58:ad:8b:53:34:e2:0f:9a:
	                    2b:c3:74:c6:67:e8:a7:4e:2f:51:2c:cd:08:51:52:
	                    cb:7a:61:65:bc:f6:80:b6:7a:86:df:95:7a:87:39:
	                    eb:8f:f7:07:8d:97:c1:ea:eb:0a:73:61:8e:19:8d:
	                    57:69:d8:0f:18:f4:ae:81:dd:21:34:b1:f1:8a:c7:
	                    c0:60:ca:89:d9:16:5f:4d:ae:72:18:6c:28:c4:f7:
	                    76:8c:5d:44:6d:95:ff:80:b2:ea:c1:7d:10:cb:b7:
	                    bc:a9:69:13:19:a2:ce:dd:e1:1a:08:e4:fd:d0:c0:
	                    b6:ea:27:71:1e:5b:86:5c:c3:b6:29:93:46:6c:e1:
	                    9f:f0:21:a9:3d:44:3d:61:10:dd:30:e9:33:32:59:
	                    b2:8f:39:d8:f0:db:0e:45:38:a5:b1:d8:c3:42:b0:
	                    09:71:20:7d:a8:1e:81:95:6f:cb:c8:cb:05:d3:7b:
	                    06:66:42:db:1f:14:de:e8:d8:04:45:32:2c:5c:c4:
	                    ae:1a:e5:e5:a0:a9:de:e0:cb:15:fb:38:1d:cd:9d:
	                    ef:13:54:8c:a2:67:79:65:70:64:a4:ce:21:9f:4a:
	                    71:57:56:25:be:7b:71:56:7c:7d:7d:2c:52:86:c3:
	                    03:44:a1:40:92:f9:a5:6a:0e:29:db:86:df:e7:bd:
	                    3b:0a:70:4e:67:3a:a5:8a:1a:a7:ff:8f:0a:f1:ab:
	                    49:5a:e1:ed:16:e1:2f:6a:db:54:51:83:12:89:54:
	                    4f:ef:e6:54:d4:63:13:d1:83:f2:8a:74:80:9b:d7:
	                    51:d5:56:c4:a8:a5:49:16:cf:06:c6:4a:9d:81:ac:
	                    05:3d:35:51:e8:b2:92:d2:ad:a0:39:ca:51:ac:9c:
	                    03:52:eb:94:a6:a2:f8:00:5c:35:a4:fe:d0:02:e1:
	                    3a:bd:90:60:23:a8:7f:6c:23:ba:7f:1c:e3:c2:e2:
	                    13:25:fa:d8:72:d2:85:34:2f:57:4f:ac:77:97:bc:
	                    f1:96:9d:21:3c:ca:73:49:79:ae:e9:52:c5:33:92:
	                    4f:38:64:e8:46:b2:9e:ba:bc:9b:44:1b:b5:cc:3c:
	                    73:24:ac:b7:d8:0e:f9:52:a1:d6:ce:26:58:31:8a:
	                    f0:b7:82:2e:fd:70:fc:6c:9a:b9:01:a3:25:95:7d:
	                    6b:33:b5
	                Exponent: 65537 (0x10001)
	        X509v3 extensions:
	            X509v3 Key Usage: critical
	                Digital Signature, Key Encipherment
	            X509v3 Extended Key Usage: 
	                TLS Web Client Authentication, TLS Web Server Authentication
	            X509v3 Basic Constraints: critical
	                CA:FALSE
	    Signature Algorithm: sha256WithRSAEncryption
	        0e:9a:b1:02:8f:c5:c4:ac:fb:09:47:52:67:3d:bf:55:fc:8b:
	        de:a6:65:53:b2:38:9d:d2:0e:bc:79:e0:56:f8:8b:2b:fc:be:
	        b5:11:03:cf:87:e3:b0:35:fb:bf:e7:3e:7b:44:39:e6:9a:8e:
	        29:61:a9:e9:b0:9d:0c:68:0e:2c:bf:b4:c1:bf:01:7a:19:09:
	        80:2e:10:58:76:0d:2b:e4:28:0a:5a:b5:46:9f:44:57:67:0a:
	        c6:8f:14:21:11:79:9f:93:37:1f:ee:65:c1:d8:17:09:66:1c:
	        66:87:d5:11:43:c4:95:ed:b8:60:df:f9:a2:c8:d7:f3:ee:21:
	        7d:93:6b:02:27:91:08:9c:44:c4:62:f1:15:b7:a9:18:a8:b5:
	        2e:97:c8:f1:d4:ec:fe:b0:be:42:4c:23:8d:c5:a8:8b:6d:c9:
	        66:27:f3:5d:d5:3a:38:17:6c:ad:27:74:a9:e2:a8:68:d2:3c:
	        11:0d:25:e6:d4:ce:58:b8:81:a0:ac:6e:96:15:27:7a:25:07:
	        4e:1b:61:73:26:de:7c:6b:04:82:11:6d:28:6d:56:52:bd:20:
	        e7:43:89:d7:55:60:6f:87:9a:6c:fb:d7:05:0f:02:95:f1:c4:
	        64:70:7b:ea:9c:b3:5a:bd:07:ce:72:57:4c:24:6c:66:91:4e:
	        36:24:4b:55:6f:fe:99:9c:95:cf:c4:51:89:5f:c1:33:5b:bc:
	        1f:85:80:99:85:e5:c9:ff:65:50:ab:4e:2b:0f:1d:7b:e2:72:
	        df:95:0e:3a:04:0b:e8:b5:0f:63:70:82:b9:c4:d5:59:43:78:
	        a2:a0:be:51:aa:10:b9:9c:55:59:de:f2:d0:7f:4a:b0:f9:4d:
	        14:a6:c1:6e:cb:19:11:cf:0e:0b:18:2d:c7:d1:b4:17:f9:5d:
	        e3:ea:b4:38:da:1e:e8:e7:f8:cb:0d:89:86:97:fe:2c:b7:a1:
	        c7:92:c0:c2:d9:46:0d:ce:f8:9f:65:90:0e:c9:5b:bb:a9:b0:
	        8b:ea:15:db:e4:e0:9b:4e:cd:95:62:ff:d9:51:13:f6:45:1b:
	        f6:58:89:85:25:f8:54:cf:a4:85:15:33:7b:69:e7:d6:81:d4:
	        e0:42:17:2b:88:0e:05:26:10:2e:b6:5e:e6:ec:b0:70:b3:44:
	        37:36:e4:69:e4:0b:f3:13:e4:46:75:52:2b:37:df:51:58:fb:
	        bd:8b:22:d7:b6:a7:40:42:e1:0f:90:57:95:75:c9:cd:08:42:
	        e8:ab:96:b8:f3:71:d1:2f:e5:72:ab:50:57:5f:e1:6c:b8:df:
	        a6:ba:e9:54:27:a5:3b:aa:a6:fd:92:e9:77:d9:a6:4d:b4:32:
	        84:17:0c:b3:a1:a6:77:6a

## Updating Certs
Cert have a limited lifetime. Updating them will resign them with existing info.

    $ ca update foobar
    updated cert for 'foobar'

## Deleting Certs

And of course you can delete them:

    $ ca delete foobar
    deleted cert for 'foobar'
    $ ca list
    ca

## Using the certs from Go programs

Some utilities are available for creating Go-based servers and clients with these certs, making it easier to see
if a client has been authenticated or not with a client cert.

Here is a simple file server that serves up TLS to avoid snooping:

    import "github.com/boynton/ca/https"
    err := https.Serve("myserver", http.FileServer(http.Dir("/tmp")))

You also can just get the config for the server:

    tdsConfig, err := https.ServerConfig("myserver")
    listener, err := tls.Listen("tcp", "myserver:4443", tlsConfig)
    http.Serve(listener, handler)


To require that the client have a cert to authenticate, you can do something like this:

	err = RunServer(serverIdentity, 4443, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := https.ClientIdentity(r)
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

A Client can be created that uses the client cert:

    url := "https://localhost:4443"
    transport, err := https.ClientTransport(clientIdentity, serverIdentity)
    client = &http.Client{Transport: transport}
    req, err := http.NewRequest("GET", url + "/", nil)
    resp, err := hclient.Do(req)

The serverIdentity is provided so that the identity doesn't has to match the DNS name of the server (i.e. "localhost").

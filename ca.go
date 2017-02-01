package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var dir = initDir()

func initDir() string {
	d := os.Getenv("CA")
	if d == "" {
		d = os.Getenv("HOME") + "/.ca"
	}
	return d + "/"
}

func SetDir(d string) {
	//mainly for testing in other packages
	if !strings.HasSuffix(d, "/") {
		d = d + "/"
	}
	dir = d
}

func Dir() string {
	return dir
}

func EnsureDir() error {
	d := Dir()
	if FileExists(d) {
		return nil
	}
	return os.MkdirAll(d, 0700)
}

func FileExists(filepath string) bool {
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return false
	}
	return true
}

type Config struct {
	Country      string `json:"country"`
	Locality     string `json:"locality"`
	Province     string `json:"province"`
	Organization string `json:"organization"`
	Unit         string `json:"unit"`           //used when signing certs if a unit is not specified
	Name         string `json:"name"`           //used as the CN of the signing cert
	Expiration   int    `json:"expiration"`     //expiration time of signing cert, in days
	RootKeyFile  string `json:"root-key-file"`  //default to 'ca.key'
	RootCertFile string `json:"root-cert-file"` //default to 'ca.cert'
	Bits         int    `json:"bits"`           //default to 4096
}

func (conf *Config) String() string {
	bconfig, _ := json.MarshalIndent(conf, "", "    ")
	return string(bconfig) + "\n"
}

func GenerateDefaultConfig() (*Config, error) {
	filename := Dir() + "config"
	if FileExists(filename) {
		return nil, fmt.Errorf("Already exists")
	}
	err := EnsureDir()
	if err != nil {
		return nil, err
	}
	conf := &Config{
		Country:      "US",
		Province:     "Oregon",
		Locality:     "Stafford",
		Organization: "Boynton",
		Unit:         "Example",
		Name:         "CA",
		RootKeyFile:  Dir() + "ca.key",
		RootCertFile: Dir() + "ca.cert",
		Bits:         2048,
		Expiration:   365 * 24,
	}
	bconfig, err := json.MarshalIndent(conf, "", "    ")
	if err != nil {
		return nil, err
	}
	sconfig := string(bconfig) + "\n"
	err = ioutil.WriteFile(filename, []byte(sconfig), 0600)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

func ReadConfig() (*Config, error) {
	filename := Dir() + "/config"
	bconfig, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var config *Config
	err = json.Unmarshal(bconfig, &config)
	return config, err
}

func Init(conf *Config) error {
	caKey, err := rsa.GenerateKey(rand.Reader, conf.Bits)
	if err != nil {
		return err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	//algo := x509.SHA256WithRSA //for ecdsa
	//algo := x509.SHA1WithRSA //for rsa
	algo := x509.SHA256WithRSA //for rsa
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)
	subj := pkix.Name{
		CommonName:         conf.Name,
		Country:            []string{conf.Country},
		Locality:           []string{conf.Locality},
		Province:           []string{conf.Province},
		Organization:       []string{conf.Organization},
		OrganizationalUnit: []string{conf.Unit},
	}

	template := &x509.Certificate{
		Subject:            subj,
		SerialNumber:       serialNumber,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          caKey.PublicKey,
		SignatureAlgorithm: algo,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		//		EmailAddresses:        csr.EmailAddresses,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		//		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}
	/*
		if hosts != nil {
			template.DNSNames = hosts
		}
		if ips != nil {
			template.IPAddresses = ips
		}
	*/

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	certOut := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return fmt.Errorf("Cannot encode Cert to PEM: %v", err)
	}
	caCertPem := certOut.String()

	if err != nil {
		return err
	}
	caKeyPem := PrivatePem(caKey)

	err = ioutil.WriteFile(conf.RootKeyFile, []byte(caKeyPem), 0600)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(conf.RootCertFile, []byte(caCertPem), 0644)
}

func PrivatePem(privateKey *rsa.PrivateKey) string {
	privatePem := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	privateBytes := pem.EncodeToMemory(privatePem)
	return string(privateBytes)
}

func CreateCert(conf *Config, name, descr, ip, hostname string) error {
	keyFile := Dir() + name + ".key"
	certFile := Dir() + name + ".cert"
	if FileExists(keyFile) || FileExists(certFile) {
		return fmt.Errorf("Cert and/or key files already exist: %s, %s", certFile, keyFile)
	}
	key, err := rsa.GenerateKey(rand.Reader, conf.Bits)
	if err != nil {
		return err
	}
	csr, err := GenerateCSR(conf, key, descr, name, ip, hostname)
	if err != nil {
		return err
	}
	certPem, err := GenerateCert(conf, csr, name)
	if err != nil {
		return err
	}
	keyPem := PrivatePem(key)
	err = ioutil.WriteFile(keyFile, []byte(keyPem), 0400)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(certFile, []byte(certPem), 0444)
	if err != nil {
		return err
	}
	return nil
}

func UpdateCert(conf *Config, name, descr, ip, hostname string) error {
	keyFile := Dir() + name + ".key"
	certFile := Dir() + name + ".cert"
	if !FileExists(keyFile) || !FileExists(certFile) {
		return fmt.Errorf("Cert and/or key files do not exist: %s, %s", certFile, keyFile)
	}
	//todo: allow changing some attributes, but defaulting to the ones that are already there.
	key, err := rsa.GenerateKey(rand.Reader, conf.Bits)
	if err != nil {
		return err
	}
	csr, err := GenerateCSR(conf, key, descr, name, ip, hostname)
	if err != nil {
		return err
	}
	certPem, err := GenerateCert(conf, csr, name)
	if err != nil {
		return err
	}
	keyPem := PrivatePem(key)
	//todo: fix race where one file updates but the other doesn't. Users of the certs might get a mismatch.
	err = ioutil.WriteFile(keyFile, []byte(keyPem), 0400)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(certFile, []byte(certPem), 0444)
	if err != nil {
		return err
	}
	return nil
}

func DeleteCert(conf *Config, name string) error {
	keyFile := Dir() + name + ".key"
	certFile := Dir() + name + ".cert"
	if FileExists(certFile) {
		err := os.Remove(certFile)
		if err != nil {
			return err
		}
	}
	if FileExists(keyFile) {
		err := os.Remove(keyFile)
		if err != nil {
			return err
		}
	}
	return nil
}

func GenerateCSR(conf *Config, key *rsa.PrivateKey, unit, commonName, ip, hostname string) (string, error) {
	subj := pkix.Name{CommonName: commonName}
	if conf.Country != "" {
		subj.Country = []string{conf.Country}
	}
	if conf.Locality != "" {
		subj.Locality = []string{conf.Locality}
	}
	if conf.Province != "" {
		subj.Province = []string{conf.Province}
	}
	if conf.Organization != "" {
		subj.Organization = []string{conf.Organization}
	}
	if unit != "" {
		subj.OrganizationalUnit = []string{unit}
	} else if conf.Unit != "" {
		subj.OrganizationalUnit = []string{conf.Unit}
	}
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA1WithRSA,
	}
	if ip != "" {
		template.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	if hostname != "" {
		template.DNSNames = []string{hostname}
	}
	//template.EmailAddresses = []string{"gopher@golang.org"}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return "", fmt.Errorf("Cannot create CSR: %v", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, block)
	if err != nil {
		return "", fmt.Errorf("Cannot encode CSR to PEM: %v", err)
	}
	return buf.String(), nil
}

func GetCert(identity string) (*x509.Certificate, error) {
	certPemBytes, err := ioutil.ReadFile(Dir() + identity + ".cert")
	if err != nil {
		return nil, err
	}
	cert, err := CertFromPEMBytes(certPemBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func GetSigner(conf *Config) (*rsa.PrivateKey, *x509.Certificate, error) {
	caCertPemBytes, err := ioutil.ReadFile(conf.RootCertFile)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := CertFromPEMBytes(caCertPemBytes)
	if err != nil {
		return nil, nil, err
	}
	caKey, err := PrivateKeyFromFile(conf.RootKeyFile)
	if err != nil {
		return nil, nil, err
	}
	return caKey, caCert, nil
}

func CertFromPEMBytes(pemBytes []byte) (*x509.Certificate, error) {
	var derBytes []byte
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("Cannot parse cert (empty pem)")
	}
	derBytes = block.Bytes
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
func PrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromPemBytes(pemBytes)
}
func PrivateKeyFromPemBytes(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
func decodeCSR(csr string) (*x509.CertificateRequest, error) {
	var derBytes []byte
	block, _ := pem.Decode([]byte(csr))
	if block == nil {
		return nil, fmt.Errorf("Cannot parse CSR (empty pem)")
	}
	derBytes = block.Bytes
	req, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, err
	}
	//err = req.CheckSignatureFrom(parent)
	err = req.CheckSignature()
	if err != nil {
		return nil, err
	}
	return req, nil
}

func GenerateCert(conf *Config, csrPem, cn string) (string, error) {
	caKey, caCert, err := GetSigner(conf)
	if err != nil {
		return "", err
	}
	csr, err := decodeCSR(csrPem)
	if err != nil {
		return "", err
	}
	if cn != "" && cn != csr.Subject.CommonName {
		return "", fmt.Errorf("CSR common name (%s) doesn't match expected common name (%s)", csr.Subject.CommonName, cn)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	algo := x509.SHA256WithRSA
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour //fixme
	notAfter := notBefore.Add(validFor)
	template := &x509.Certificate{
		Subject:               csr.Subject,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SignatureAlgorithm:    algo,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return "", err
	}

	certOut := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err != nil {
		return "", fmt.Errorf("Cannot encode Cert to PEM: %v", err)
	}
	return certOut.String(), nil
}

func formatPkixName(name pkix.Name) string {
	lst := make([]string, 0)
	if len(name.Country) > 0 {
		lst = append(lst, "C="+strings.Join(name.Country, ","))
	}
	if len(name.Province) > 0 {
		lst = append(lst, "ST="+strings.Join(name.Province, ","))
	}
	if len(name.Locality) > 0 {
		lst = append(lst, "L="+strings.Join(name.Locality, ","))
	}
	if len(name.Organization) > 0 {
		lst = append(lst, "O="+strings.Join(name.Organization, ","))
	}
	if len(name.OrganizationalUnit) > 0 {
		lst = append(lst, "OU="+strings.Join(name.OrganizationalUnit, ","))
	}
	lst = append(lst, "CN="+name.CommonName)
	return strings.Join(lst, ", ")
}

func GetCertInfo(cert *x509.Certificate) map[string]string {
	m := make(map[string]string)
	m["version"] = fmt.Sprint(cert.Version)
	s := fmt.Sprintf("%x", cert.SerialNumber)
	max := len(s)
	a := make([]string, 0, max/2)
	for i := 0; i < max; i += 2 {
		a = append(a, s[i:i+2])
	}
	m["serial-number"] = strings.Join(a, ":")
	m["signature-algorithm"] = cert.SignatureAlgorithm.String()

	m["issuer"] = formatPkixName(cert.Issuer)
	m["not-before"] = fmt.Sprint(cert.NotBefore)
	m["not-after"] = fmt.Sprint(cert.NotAfter)
	m["subject"] = formatPkixName(cert.Subject)
	alg := "?"
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		alg = "RSA"
		tmp, ok := cert.PublicKey.(*rsa.PublicKey)
		if ok {
			alg = fmt.Sprintf("RSA (%d bit)", 4*len(fmt.Sprintf("%x", tmp.N)))
		}
	case x509.DSA:
		alg = "DSA"
	case x509.ECDSA:
		alg = "ECDSA"
	}
	m["subject-pub-key-algo"] = alg

	use := make([]string, 0)
	//Digital Signature, Key Encipherment, Certificate Sign, CRL Sign
	if (cert.KeyUsage & x509.KeyUsageDigitalSignature) != 0 {
		use = append(use, "Digital Signature")
	}
	if (cert.KeyUsage & x509.KeyUsageKeyEncipherment) != 0 {
		use = append(use, "Key Encipherment")
	}
	if (cert.KeyUsage & x509.KeyUsageCertSign) != 0 {
		use = append(use, "Certificate Sign")
	}
	if (cert.KeyUsage & x509.KeyUsageCRLSign) != 0 {
		use = append(use, "CRL Sign")
	}
	m["usage"] = strings.Join(use, ", ")
	if cert.BasicConstraintsValid {
		if cert.IsCA {
			m["ca"] = "true"
		}
	}
	return m
}

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/pkg/x509"

	// Load all the auth plugins for the cloud providers.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func main() {
	tokenPath := flag.String("token", "/var/run/secrets/kuberentes.io/serviceaccount/token", "path to read token from")
	keyPath := flag.String("key", "", "path that the key is written to")
	csrPath := flag.String("csr", "", "path that the csr is written to")
	expectedName := flag.String("name", "", "DNS-like identity name")

	// override glog's default configuration
	flag.Set("logtostderr", "true")
	logLevel := flag.String("log-level", log.InfoLevel.String(),
		"log level, must be one of: panic, fatal, error, warn, info, debug")

	flag.Parse()

	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("invalid log-level: %s", *logLevel)
	}
	log.SetLevel(level)

	if *tokenPath == "" {
		log.Fatal("`-token` must be specified")
	}

	if *keyPath == "" {
		log.Fatal("`-key` must be specified")
	}

	if *csrPath == "" {
		log.Fatal("`-csr` must be specified")
	}

	tokenPayload, err := readToken(*tokenPath)
	if err != nil {
		log.Fatal(err.Error())
	}

	ns := tokenPayload["kubernetes.io/serviceaccount/namespace"]
	if ns == "" {
		log.Fatal("Token missing 'kuberenetes.io/serviceaccount/namespace")
	}

	sa := tokenPayload["kubernetes.io/serviceaccount/service-account.name"]
	if sa == "" {
		log.Fatal("Token missing 'kuberenetes.io/serviceaccount/service-account.name")
	}

	uid := tokenPayload["kubernetes.io/serviceaccount/service-account.uid"]
	if uid == "" {
		log.Fatal("Token missing 'kuberenetes.io/serviceaccount/service-account.uid")
	}

	name := fmt.Sprintf("%s.%s.%s", uid, sa, ns)
	if *expectedName != name {
		log.Fatalf("Names do not match: expected=%s; read=%s", *expectedName, name)
	}

	key, err := newKey()
	if err != nil {
		log.Fatal(err.Error())
	}

	names := []string{name}
	csr, err := newCSR(key, &x509.CertificateRequest{DNSNames: names})
	if err != nil {
		log.Fatal(err.Error())
	}

	p, err := pemutil.Serialize(key)
	if err != nil {
		log.Fatal(err.Error())
	}
	if err := ioutil.WriteFile(*keyPath, pem.EncodeToMemory(p), 0400); err != nil {
		log.Fatal(err.Error())
	}
	log.Debugf("Wrote key to %s", *keyPath)

	if err := ioutil.WriteFile(*csrPath, pem.EncodeToMemory(csr), 0400); err != nil {
		log.Fatal(err.Error())
	}
	log.Debugf("Wrote CSR to %s", *csrPath)

	os.Exit(0)
}

func newKey() (*ecdsa.PrivateKey, error) {
	k, err := keys.GenerateKey("EC", "P-256", 0)
	if err != nil {
		return nil, err
	}
	switch key := k.(type) {
	case *ecdsa.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("Unexpected key type")
	}
}

func newCSR(key *ecdsa.PrivateKey, req *x509.CertificateRequest) (*pem.Block, error) {
	csrb, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return nil, err
	}
	p := &pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Bytes:   csrb,
		Headers: map[string]string{},
	}
	return p, nil
}

func readToken(path string) (map[string]string, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	tok, err := jose.ParseJWS(string(bytes))
	if err != nil {
		return nil, err
	}

	token, err := tok.CompactSerialize()
	if err != nil {
		return nil, err
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("Malformed token does not contain 3 parts")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	payload := make(map[string]string)
	err = json.Unmarshal(decoded, &payload)
	return payload, err
}
